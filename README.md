# Docker 容器端口转发工具

基于 Go 的 Docker 容器监听工具，自动为符合名称规则的新容器分配端口并配置 iptables 转发。

## 功能特点

- 监听 Docker 容器变化，支持多个名称匹配模式。
- 从指定区间分配可用端口，配置 TCP DNAT 和 FORWARD 规则。
- 将映射保存到 YAML 文件，避免重复配置。
- 支持导入已有规则及容器记录。

## 项目结构

```text
.
├── README.md
└── iptable-docker/
    ├── go.mod
    ├── go.sum
    └── iptables.go
```

## 环境要求

- Linux 宿主机及可访问的 Docker 服务
- Go 1.26.5 或更高版本
- `iptables` 和 `sudo`，运行账号需能通过 `sudo -n iptables` 非交互执行命令
- 容器内的服务需要监听分配到的端口

## 快速开始

```bash
cd iptable-docker
go build -o iptable-docker .
./iptable-docker
```

也可以在模块目录下执行 `go run .`。程序首次回调用于建立容器基线，随后新出现且符合匹配规则的容器才会触发配置。按 `Ctrl+C` 或发送 `SIGTERM` 可退出程序。

## 配置说明

配置项位于 `iptable-docker/iptables.go` 顶部，修改后需要重新编译。

| 配置项 | 说明 |
| --- | --- |
| `targetContainerName` | 容器名称匹配规则，支持逗号分隔的多个 `path.Match` 模式；留空匹配所有容器。请按实际环境设置，源码中保留当前默认值。 |
| `hostPortStart` / `hostPortEnd` | 端口分配区间，默认 `20000` 至 `30000`。 |
| `configPath` | 状态文件路径，默认为工作目录下的 `iptable_config.yaml`。 |
| `hostIP` | 宿主机对外 IP；留空时根据默认出口路由探测。 |
| `probeAddr` | 出口 IP 探测地址，默认 `8.8.8.8:80`，使用 UDP 路由选择。 |

## 工作流程

1. 建立已有容器的基线，并按名称规则筛选后续出现的容器。
2. 为尚未记录的容器选择本机空闲且未被 iptables 占用的端口。
3. 检查并添加 `nat` 表的 `PREROUTING` DNAT 规则和 `filter` 表的 `FORWARD` 放行规则。
4. 将容器名称、ID、IP、端口、宿主机 IP 和时间写入状态文件。

例如，分配端口 `20004` 时，流量转发到容器 IP 的 `20004` 端口。程序以容器名称判断是否已有记录，同名容器重建后也会跳过配置；容器 IP 变化时应核对现有规则和状态记录。

## 状态文件

`iptable_config.yaml` 示例：

```yaml
mappings:
  - container: app-demo
    id: 4465b87b1ad6
    ip: 172.17.0.6
    port: 20006
    host: 192.168.48.51
    created_at: "2026-09-20T12:19:09+08:00"
```

状态文件中的容器名称用于跳过重复配置。`port: 0` 的记录不会占用分配端口，可用于标记无需配置的容器。变更记录或现有规则前，请先核对当前流量及恢复方式。

## 导入已有环境

首次接入已有 iptables 规则和容器的宿主机时，可执行一次导入：

```bash
cd iptable-docker
./iptable-docker -import
cat iptable_config.yaml
./iptable-docker
```

导入先处理现有 iptables 规则，再记录符合名称规则的已有容器。导入完成后新建的匹配容器仍由常驻进程处理。

## 运行注意事项

- 状态文件相对于启动程序时的工作目录，请保持工作目录一致并妥善保存该文件。
- 程序按状态记录跳过已有容器。宿主机重启后应确认 iptables 规则是否由系统持久化机制恢复，避免记录存在但规则缺失。
- 端口分配后，容器服务必须监听同一端口，转发才能正常访问。
- 在生产环境启用前，请检查端口范围、容器匹配规则、现有防火墙策略及回滚方案。

## 主要依赖

- [containuum](https://github.com/csmith/containuum)：监听 Docker 容器变化。
- [yaml.v3](https://github.com/go-yaml/yaml)：读写 YAML 状态文件。