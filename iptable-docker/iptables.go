package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/csmith/containuum"
	"gopkg.in/yaml.v3"
)

// targetContainerName 只关心名字匹配该模式的容器，留空则监听所有容器。
// 可以写多个模式，用逗号分隔，命中任意一个即算匹配（逗号两侧空格会被忽略）。
// 每个模式用 path.Match 语法：
//
//	"kali"       精确匹配 kali
//	"kali*"      以 kali 开头
//	"*kali*"     名字中包含 kali
//	"web-?"      web- 后跟任意一个字符
//	"ywm*,wms*"  以 ywm 开头 或 以 wms 开头
const targetContainerName = "ywm*,wms*"

// 宿主机端口与容器端口保持一致：从区间里挑一个「本机空闲 + iptables 未占用」的端口，
// 两端都用同一个端口号，例如 20000 -> 容器IP:20000。
// 前提：容器内服务本身也监听这个端口。
const (
	hostPortStart = 20000
	hostPortEnd   = 30000
)

// configPath 端口转发记录文件（相对程序工作目录）。
// 配过的容器会写进这里；程序重启或容器重建时读到记录就跳过，不再重复下发规则。
// 想让某个容器重新分配端口，手动删掉它的条目即可。
const configPath = "iptable_config.yaml"

// hostIP 宿主机对外 IP。留空则自动探测本机默认出口 IP。
const hostIP = ""

// probeAddr 用于探测默认出口 IP 的地址（UDP 不会真正发包，只做路由选择）。
const probeAddr = "8.8.8.8:80"

// 默认网络名，优先输出自定义网络的 IP，这些网络只作为兜底。
var fallbackNetworks = map[string]struct{}{
	"bridge": {},
	"host":   {},
	"none":   {},
}

// containerNameMatches 返回一个按容器名通配匹配的过滤器。
// containuum 只内置了 LabelExists/LabelEquals/StateEquals，
// 没有按名字过滤的函数，但 Filter 本质就是 func(Container) bool，可以直接自定义。
// 传入的是逗号分隔的多个模式，命中任意一个即匹配；模式在构造时校验一次，
// 避免每个容器都重复报错。
func containerNameMatches(pattern string) (containuum.Filter, error) {
	patterns := splitPatterns(pattern)
	if len(patterns) == 0 {
		return func(containuum.Container) bool { return true }, nil
	}

	for _, p := range patterns {
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("容器名通配模式 %q 非法: %w", p, err)
		}
	}

	return func(c containuum.Container) bool {
		for _, p := range patterns {
			if ok, _ := path.Match(p, c.Name); ok {
				return true
			}
		}
		return false
	}, nil
}

// splitPatterns 把 "ywm*,wms*" 拆成 ["ywm*","wms*"]，去掉空串和两端空格。
func splitPatterns(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// mapping 一条已下发的转发记录。
// 以容器名作为「是否已配置过」的依据：容器重建后 ID 会变、名字一般不变，
// 这样重建或程序重启都能命中记录并跳过。
type mapping struct {
	Container string `yaml:"container"`
	ID        string `yaml:"id"`
	IP        string `yaml:"ip"`
	Port      int    `yaml:"port"` // 宿主机端口 == 容器端口
	Host      string `yaml:"host"`
	CreatedAt string `yaml:"created_at"`
}

// config 配置文件整体结构。
type config struct {
	Mappings []mapping `yaml:"mappings"`
}

// configHeader 写在文件开头的说明，手工编辑时能看明白规则。
const configHeader = "# 已下发的端口转发记录。\n" +
	"# 保留某条记录 = 该容器不再重复配置；想让它重新分配端口，删掉对应条目即可。\n"

// find 按容器名查找已有记录。
func (c *config) find(name string) (mapping, bool) {
	for _, m := range c.Mappings {
		if m.Container == name {
			return m, true
		}
	}
	return mapping{}, false
}

// findPort 按「容器名 + 端口」查找记录。
// 一个容器可能有多条转发规则（不同端口），导入现有规则时要用这个判断重复。
func (c *config) findPort(name string, port int) (mapping, bool) {
	for _, m := range c.Mappings {
		if m.Container == name && m.Port == port {
			return m, true
		}
	}
	return mapping{}, false
}

// usedPorts 返回配置里已占用的端口，供分配新端口时避开。
// iptables 规则在机器重启后会丢失，光靠查 iptables 不够，必须看这份记录。
func (c *config) usedPorts() map[string]struct{} {
	out := make(map[string]struct{}, len(c.Mappings))
	for _, m := range c.Mappings {
		if m.Port > 0 {
			out[strconv.Itoa(m.Port)] = struct{}{}
		}
	}
	return out
}

// add 追加一条记录；只有「同容器名 + 同端口」的旧记录才被覆盖。
// 一个容器允许有多条不同端口的转发规则，所以判定键是 (名字, 端口)。
func (c *config) add(m mapping) {
	for i, old := range c.Mappings {
		if old.Container == m.Container && old.Port == m.Port {
			c.Mappings[i] = m
			return
		}
	}
	c.Mappings = append(c.Mappings, m)
}

// loadConfig 读取配置文件。文件不存在时返回空配置，不算错误。
// 解析失败才返回错误，交给调用方决定是否退出，避免把坏文件当成空配置覆盖掉。
func loadConfig(path string) (*config, error) {
	cfg := &config{Mappings: []mapping{}}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取配置 %s 失败: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置 %s 失败: %w", path, err)
	}
	if cfg.Mappings == nil {
		cfg.Mappings = []mapping{}
	}
	return cfg, nil
}

// save 原子写入配置文件：先写 .tmp 再 rename，
// 避免写到一半断电/被杀导致配置损坏。
func (c *config) save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(configHeader), data...), 0o644); err != nil {
		return fmt.Errorf("写入临时文件 %s 失败: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("替换配置 %s 失败: %w", path, err)
	}
	return nil
}

// shortID 返回容器 ID 的前 12 位，ID 不足时返回原值，避免切片越界。
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// preferredIPv4 返回容器「最合适」的一个 IPv4 及其所在网络名。
// 优先取自定义网络（非 bridge/host/none），没有时回退到默认网络。
// 找不到则返回空字符串。
func preferredIPv4(c containuum.Container) (ip, network string) {
	var fallbackIP, fallbackNetwork string

	for _, n := range c.Networks {
		if n.IPAddress == "" {
			continue
		}
		if _, isDefault := fallbackNetworks[n.Name]; isDefault {
			if fallbackIP == "" {
				fallbackIP, fallbackNetwork = n.IPAddress, n.Name
			}
			continue
		}
		return n.IPAddress, n.Name
	}

	return fallbackIP, fallbackNetwork
}

// monitor 负责处理容器集合的变化，并在内部维护上一次的快照。
type monitor struct {
	// 上一次回调中出现过的容器 ID，用于判断新增/移除。
	seen map[string]struct{}
	// 首次回调是全量快照，只用于建立基线，不视为新增。
	initialized bool
	// 容器 ID -> 已分配的宿主机端口，同一个容器复用，避免端口漂移。
	ports map[string]string
	// cfg 持久化的转发记录，容器重建或程序重启后靠它跳过已配置的容器。
	cfg *config
	// path 配置文件路径，写回时使用。
	path string
}

func newMonitor(cfg *config, path string) *monitor {
	return &monitor{
		seen:  make(map[string]struct{}),
		ports: make(map[string]string),
		cfg:   cfg,
		path:  path,
	}
}

// handle 是传给 containuum.Run 的回调：
// containuum 只在集合变化时才调用，且每次给的是全量列表，
// 所以「新建/移除」通过与上一次的 ID 快照对比得出。
func (m *monitor) handle(containers []containuum.Container) {
	current := make(map[string]struct{}, len(containers))

	// 首次回调：只记录基线快照。启动前就存在的容器不算新增、不配规则，
	// 之后真正新建的容器才会触发 IpTables。
	if !m.initialized {
		for _, c := range containers {
			current[c.ID] = struct{}{}
			ip, network := preferredIPv4(c)
			if ip == "" {
				log.Printf("[初始] 容器 %s (%s) 暂无 IPv4", c.Name, shortID(c.ID))
				continue
			}
			log.Printf("[初始] 容器 %s (%s) 网络 %s: IPv4=%s", c.Name, shortID(c.ID), network, ip)
		}
		m.seen = current
		m.initialized = true
		log.Printf("初始同步完成，共 %d 个容器；此后新建的容器才会配置转发", len(containers))
		return
	}

	log.Printf("当前有 %d 个容器", len(containers))

	for _, c := range containers {
		_, existed := m.seen[c.ID]
		current[c.ID] = struct{}{}

		// IP 在这里取出，后面日志和下游函数共用同一个值
		ip, network := preferredIPv4(c)
		m.logContainer(c, existed, ip, network)

		// 新建容器且拿到 IPv4 时，挑一个空闲的宿主机端口再下发规则
		if ip != "" && !existed {
			m.forward(c, ip)
		}
	}

	// 上次有、这次没有 => 容器已被移除
	for id := range m.seen {
		if _, ok := current[id]; !ok {
			log.Printf("[移除] 容器 %s", shortID(id))
			delete(m.ports, id) // 端口回收，可再分配给后来的容器
		}
	}

	m.seen = current
}

// forward 处理新建容器：
//  1. 配置文件里已有该容器的记录 => 之前配过，直接跳过（容器重建、程序重启都走这里）；
//  2. 本次运行内已分配过端口 => 复用，规则幂等；
//  3. 全新容器 => 挑空闲端口、下发 iptables 规则、写回配置文件。
func (m *monitor) forward(c containuum.Container, ip string) {
	if rec, ok := m.cfg.find(c.Name); ok {
		if rec.Port == 0 {
			// 被 -import 收编过：只登记名字、没有转发规则，重建也不动它
			log.Printf("容器 %s (%s) 已被收编（无转发规则），跳过", c.Name, shortID(c.ID))
			return
		}
		if rec.IP != ip {
			log.Printf("容器 %s (%s) 已配置过（记录 IP=%s，当前 IP=%s），跳过；"+
				"要按新 IP 重配请删除 %s 中该条目",
				c.Name, shortID(c.ID), rec.IP, ip, m.path)
		} else {
			log.Printf("容器 %s (%s) 已有转发记录 %s:%d，跳过",
				c.Name, shortID(c.ID), rec.Host, rec.Port)
		}
		return
	}

	if port, ok := m.ports[c.ID]; ok {
		if _, err := IpTables(ip, port); err != nil {
			log.Printf("容器 %s (%s) 刷新转发规则失败: %v", c.Name, shortID(c.ID), err)
		}
		return
	}

	port, err := allocateHostPort(m.cfg.usedPorts())
	if err != nil {
		log.Printf("容器 %s (%s) 分配宿主机端口失败: %v", c.Name, shortID(c.ID), err)
		return
	}

	host, err := IpTables(ip, port)
	if err != nil {
		log.Printf("容器 %s (%s) 配置转发失败: %v", c.Name, shortID(c.ID), err)
		return
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		log.Printf("端口 %q 转数字失败: %v", port, err)
		return
	}

	m.cfg.add(mapping{
		Container: c.Name,
		ID:        shortID(c.ID),
		IP:        ip,
		Port:      portNum,
		Host:      host,
		CreatedAt: time.Now().Format(time.RFC3339),
	})
	if err := m.cfg.save(m.path); err != nil {
		log.Printf("警告: 容器 %s (%s) 规则已生效，但写入 %s 失败: %v；"+
			"下次启动可能重新分配端口", c.Name, shortID(c.ID), m.path, err)
	}

	m.ports[c.ID] = port
	log.Printf("容器 %s (%s) 使用宿主机端口 %s，已写入 %s", c.Name, shortID(c.ID), port, m.path)
}

// logContainer 输出单个容器的 IPv4（每个容器只输出一个 IP）。
// ip/network 由调用方传入，这里只负责打印，不产生副作用。
func (m *monitor) logContainer(c containuum.Container, existed bool, ip, network string) {
	tag := "[新增] "
	if existed {
		tag = ""
	}

	if ip == "" {
		log.Printf("%s容器 %s (%s) 暂无 IPv4", tag, c.Name, shortID(c.ID))
		return
	}

	log.Printf("%s容器 %s (%s) 网络 %s: IPv4=%s", tag, c.Name, shortID(c.ID), network, ip)
}

// IpTables 为容器配置端口转发规则，宿主机端口与容器端口相同：
//  1. sudo iptables -t nat -I PREROUTING 1 -d 宿主机IP/32 -p tcp --dport P -j DNAT --to-destination 容器IP:P
//  2. sudo iptables -I FORWARD 1 -d 容器IP/32 -p tcp --dport P -j ACCEPT
//
// ip 由调用方传入；port 由 allocateHostPort 挑出的空闲端口，两端共用。
// 返回实际使用的宿主机 IP，方便调用方写进配置文件。
func IpTables(ip, port string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("IpTables 收到非法容器 IP %q", ip)
	}
	if !validPort(port) {
		return "", fmt.Errorf("IpTables 收到非法端口 %q", port)
	}

	host, err := resolveHostIP()
	if err != nil {
		return "", fmt.Errorf("无法获取宿主机 IP: %w", err)
	}

	log.Printf("配置转发: 宿主机 %s:%s -> 容器 %s:%s", host, port, ip, port)

	// 1) nat 表 PREROUTING：外部访问宿主机端口时做 DNAT（目的端口不变）
	natSpec := []string{
		"-t", "nat", "PREROUTING",
		"-d", host + "/32",
		"-p", "tcp", "--dport", port,
		"-j", "DNAT", "--to-destination", ip + ":" + port,
	}
	if err := ensureRule(natSpec); err != nil {
		return "", fmt.Errorf("添加 DNAT 规则失败: %w", err)
	}

	// 2) filter 表 FORWARD：允许转发到容器的同一端口
	forwardSpec := []string{
		"FORWARD",
		"-d", ip + "/32",
		"-p", "tcp", "--dport", port,
		"-j", "ACCEPT",
	}
	if err := ensureRule(forwardSpec); err != nil {
		return "", fmt.Errorf("添加 FORWARD 规则失败: %w", err)
	}

	log.Printf("转发规则已就绪: %s:%s -> %s:%s", host, port, ip, port)
	return host, nil
}

// allocateHostPort 在 hostPortStart..hostPortEnd 里找第一个可用端口：
// 既要本机 TCP 端口没人监听、iptables nat PREROUTING 里没被占用，
// 也不能是 already 里已经登记过的端口（配置文件里的记录）。
func allocateHostPort(already map[string]struct{}) (string, error) {
	for p := hostPortStart; p <= hostPortEnd; p++ {
		port := strconv.Itoa(p)

		if _, taken := already[port]; taken {
			continue // 配置文件里已分配给别的容器
		}

		if !tcpPortFree(port) {
			continue // 本机已有进程占用
		}

		used, err := iptablesPortUsed(port)
		if err != nil {
			return "", err
		}
		if !used {
			return port, nil
		}
	}
	return "", fmt.Errorf("端口范围 %d-%d 内没有可用端口", hostPortStart, hostPortEnd)
}

// tcpPortFree 用一次 bind 试探端口是否空闲，能 bind 上就说明没人监听。
func tcpPortFree(port string) bool {
	l, err := net.Listen("tcp", net.JoinHostPort("", port))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// dportPattern 从 iptables -S 的输出里抓 --dport 后面的端口号。
var dportPattern = regexp.MustCompile(`(?:^|\s)--dport\s+(\d+)(?:\s|$)`)

// iptablesPortUsed 判断 nat PREROUTING 里是否已有占用该端口的 DNAT 规则。
// 不用 -C 是因为它要求规则完全一致（含 --to-destination），无法只按端口查；
// 这里列出整条链再匹配 --dport，能覆盖别人或其它容器留下的规则。
func iptablesPortUsed(port string) (bool, error) {
	out, err := runIPTablesOutput("-t", "nat", "-S", "PREROUTING")
	if err != nil {
		return false, err
	}

	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "-j DNAT") {
			continue
		}
		if m := dportPattern.FindStringSubmatch(line); m != nil && m[1] == port {
			return true, nil
		}
	}
	return false, nil
}

// validPort 判断字符串是否是合法的端口号。
func validPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && n <= 65535
}

// resolveHostIP 返回宿主机 IP：优先用 hostIP 常量，否则探测默认出口 IP。
func resolveHostIP() (string, error) {
	if hostIP != "" {
		if net.ParseIP(hostIP) == nil {
			return "", fmt.Errorf("hostIP 常量不是合法 IP: %q", hostIP)
		}
		return hostIP, nil
	}

	conn, err := net.Dial("udp", probeAddr)
	if err != nil {
		return "", fmt.Errorf("探测出口 IP 失败: %w", err)
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return "", errors.New("无法从探测连接中取到本地地址")
	}
	return addr.IP.String(), nil
}

// ensureRule 保证规则存在：先用 -C 检查，已存在就跳过，不存在才 -I 插到链首。
// 这样重复触发（首次全量快照、容器重启）不会产生重复规则，保证幂等。
// spec 形如 ["-t","nat","PREROUTING", ...匹配条件..., "-j","DNAT", ...] 或 ["FORWARD", ...]。
func ensureRule(spec []string) error {
	if err := runIPTables(buildRuleArgs(spec, "-C")...); err == nil {
		return nil // 规则已存在
	}
	return runIPTables(buildRuleArgs(spec, "-I")...)
}

// buildRuleArgs 把规则描述拼成命令行参数：
// ["-t","nat","PREROUTING", rest...] + "-I" => ["-t","nat","-I","PREROUTING","1", rest...]
// ["FORWARD", rest...]                 + "-I" => ["-I","FORWARD","1", rest...]
func buildRuleArgs(spec []string, action string) []string {
	chainIndex := 0
	if spec[0] == "-t" {
		chainIndex = 2 // -t <table> <chain>
	}

	args := append([]string{}, spec[:chainIndex]...)
	args = append(args, action, spec[chainIndex])
	if action == "-I" {
		args = append(args, "1") // 插入到链首
	}
	args = append(args, spec[chainIndex+1:]...)
	return args
}

// runIPTablesOutput 执行 sudo -n iptables <args...> 并返回输出。
// -n 表示非交互，避免卡在密码输入。
func runIPTablesOutput(args ...string) (string, error) {
	cmd := exec.Command("sudo", append([]string{"-n", "iptables"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("iptables %s: %w (输出: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// runIPTables 只关心是否执行成功，输出交给 runIPTablesOutput。
func runIPTables(args ...string) error {
	_, err := runIPTablesOutput(args...)
	return err
}

// destinationPattern 抓 --to-destination 后面的 "IP:端口"。
var destinationPattern = regexp.MustCompile(`(?:^|\s)--to-destination\s+(\S+)`)

// destHostPattern 抓规则里的 -d 宿主机地址（形如 192.168.48.51/32）。
var destHostPattern = regexp.MustCompile(`(?:^|\s)-d\s+(\S+)`)

// matchFirst 返回第一个捕获组，没匹配到返回空串。
func matchFirst(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

// importExisting 把当前 nat PREROUTING 里已有的 DNAT 规则登记进配置文件。
// 用途：之前手工或旧版本配过的规则，一次性「写死」到配置里，
// 之后程序不再动它们，只处理后续新建的容器。
// 规则里只有容器 IP 没有名字，所以用 docker inspect 反查 IP -> 容器名。
func importExisting(cfg *config, path string) error {
	rules, err := runIPTablesOutput("-t", "nat", "-S", "PREROUTING")
	if err != nil {
		return err
	}

	nameByIP, idByIP, err := containerIPIndex()
	if err != nil {
		return err
	}

	added, skipped := 0, 0
	for _, line := range strings.Split(rules, "\n") {
		if !strings.Contains(line, "-j DNAT") {
			continue
		}

		port := matchFirst(dportPattern, line)
		dest := matchFirst(destinationPattern, line)
		if port == "" || dest == "" {
			log.Printf("跳过无法解析的规则: %s", line)
			skipped++
			continue
		}

		// --to-destination 可能是 "172.17.0.5:20003"，也可能只有 IP
		ip := dest
		if host, _, err := net.SplitHostPort(dest); err == nil {
			ip = host
		}
		if net.ParseIP(ip) == nil {
			log.Printf("跳过目标地址非法的规则: %s", line)
			skipped++
			continue
		}

		name, ok := nameByIP[ip]
		if !ok {
			log.Printf("跳过：目标 %s 找不到对应容器（容器已删除或不在本机），可手工补一条记录", ip)
			skipped++
			continue
		}
		portNum, err := strconv.Atoi(port)
		if err != nil {
			log.Printf("跳过端口非法的规则: %s", line)
			skipped++
			continue
		}
		if _, exists := cfg.findPort(name, portNum); exists {
			continue // 同一个容器的同一个端口已经登记过，不重复写
		}

		host := strings.TrimSuffix(matchFirst(destHostPattern, line), "/32")
		cfg.add(mapping{
			Container: name,
			ID:        idByIP[ip],
			IP:        ip,
			Port:      portNum,
			Host:      host,
			CreatedAt: time.Now().Format(time.RFC3339),
		})
		log.Printf("导入: 容器 %s (%s) %s:%d -> %s", name, idByIP[ip], host, portNum, dest)
		added++
	}

	if err := cfg.save(path); err != nil {
		return err
	}
	log.Printf("导入完成：新增 %d 条，跳过 %d 条，已写入 %s", added, skipped, path)
	return nil
}

// adoptExisting 把当前已存在的容器名收编进配置，端口记为 0（表示没有转发规则）。
// 目的：这些容器以后即使重建也不会被重新配置，程序只处理配置里没有的新名字。
// 只收编能被 filter 命中的容器——命中不了的本来就不会被程序处理。
func adoptExisting(cfg *config, path string, filter containuum.Filter) error {
	list, err := listContainers()
	if err != nil {
		return err
	}

	host := ""
	if ip, err := resolveHostIP(); err == nil {
		host = ip
	}

	adopted := 0
	for _, c := range list {
		if !filter(containuum.Container{Name: c.Name}) {
			continue
		}
		if _, exists := cfg.find(c.Name); exists {
			continue // 配置里已经有它了（可能刚被 -import 导进来）
		}

		cfg.add(mapping{
			Container: c.Name,
			ID:        c.ID,
			IP:        c.IP,
			Port:      0, // 0 = 仅标记已存在，没有转发规则
			Host:      host,
			CreatedAt: time.Now().Format(time.RFC3339),
		})
		log.Printf("收编: 容器 %s (%s) 已存在，登记为不再配置", c.Name, c.ID)
		adopted++
	}

	if err := cfg.save(path); err != nil {
		return err
	}
	log.Printf("收编完成：新增 %d 个容器名，已写入 %s", adopted, path)
	return nil
}

// containerInfo 收编/导入时需要的最小容器信息。
type containerInfo struct {
	ID   string
	Name string
	IP   string
}

// listContainers 列出本机所有容器（含已停止的），取 短ID/名字/第一个非空 IP。
// 走 docker 命令行，避免绑定 docker Go SDK 的具体版本类型。
func listContainers() ([]containerInfo, error) {
	idsOut, err := exec.Command("docker", "ps", "-aq").Output()
	if err != nil {
		return nil, fmt.Errorf("执行 docker ps 失败: %w", err)
	}

	ids := strings.Fields(string(idsOut))
	if len(ids) == 0 {
		return nil, nil
	}

	args := append([]string{"inspect", "--format",
		"{{.Id}}|{{.Name}}|{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"}, ids...)
	inspectOut, err := exec.Command("docker", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("执行 docker inspect 失败: %w", err)
	}

	var list []containerInfo
	for _, line := range strings.Split(string(inspectOut), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			continue
		}

		info := containerInfo{
			ID:   shortID(strings.TrimSpace(parts[0])),
			Name: strings.TrimPrefix(strings.TrimSpace(parts[1]), "/"),
		}
		for _, ip := range strings.Fields(parts[2]) {
			if ip != "" {
				info.IP = ip
				break
			}
		}
		list = append(list, info)
	}
	return list, nil
}

// containerIPIndex 建立 容器IP -> 容器名/短ID 的索引，供导入 iptables 规则时反查。
func containerIPIndex() (nameByIP, idByIP map[string]string, err error) {
	nameByIP = make(map[string]string)
	idByIP = make(map[string]string)

	list, err := listContainers()
	if err != nil {
		return nil, nil, err
	}

	for _, c := range list {
		if c.IP == "" {
			continue
		}
		if _, dup := nameByIP[c.IP]; !dup {
			nameByIP[c.IP] = c.Name
			idByIP[c.IP] = c.ID
		}
	}
	return nameByIP, idByIP, nil
}

func main() {
	// -import：把现有 iptables 的 DNAT 规则登记进配置文件后退出，不进入监听。
	// 用于「之前已经配过的规则」一次性收编，之后只处理新建的容器。
	importOnly := flag.Bool("import", false, "导入现有 iptables DNAT 规则到配置文件后退出")
	flag.Parse()

	// 收到 SIGINT/SIGTERM 时取消 context，让 Run 正常退出
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 按名字通配过滤，模式非法时直接启动失败，而不是静默匹配不到
	filter, err := containerNameMatches(targetContainerName)
	if err != nil {
		log.Fatal(err)
	}

	// 读持久化记录：文件不存在按空配置处理，解析失败直接退出，
	// 避免把一份坏掉的配置当成空配置覆盖掉。
	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}
	// 打印绝对路径，方便确认配置文件到底落在哪（configPath 是相对工作目录的）
	absPath, absErr := filepath.Abs(configPath)
	if absErr != nil {
		absPath = configPath
	}
	log.Printf("配置文件: %s，已加载 %d 条转发记录", absPath, len(cfg.Mappings))

	if *importOnly {
		// 1) 收编现有 iptables 规则
		if err := importExisting(cfg, configPath); err != nil {
			log.Fatal(err)
		}
		// 2) 收编现有容器名：它们以后重建也不会再被配置，只处理新名字
		if err := adoptExisting(cfg, configPath, filter); err != nil {
			log.Fatal(err)
		}
		return
	}

	err = containuum.Run(
		ctx,
		newMonitor(cfg, configPath).handle,
		// 过滤发生在去重之前，因此其他容器的变动不会触发回调。
		containuum.WithFilter(filter),
	)
	if err != nil {
		log.Fatal(err)
	}
}
