# SSH Exporter
[English](README.md) | 中文

## 介绍

SSH Exporter 是一个基于 Prometheus 规范的监控工具，通过 SSH 协议远程收集目标服务器的系统性能数据，如 CPU 使用率、内存使用情况、磁盘和网络 I/O 等，并将这些数据暴露为 Prometheus 格式的 metrics，以便被 Prometheus Server 抓取和存储。

## 功能特性

- **远程监控**：通过 SSH 协议连接到远程服务器，无需在被监控服务器上安装额外的 agent。
- **全面的系统监控**：支持监控 CPU、内存、磁盘和网络等多个方面的性能指标。
- **动态配置**：支持从 YAML 配置文件中读取监控目标和参数，便于动态管理监控节点。
- **异步收集**：使用线程池异步收集数据，提高数据收集效率。
- **错误处理与重试机制**：对于 SSH 连接失败的情况，提供自动重试机制，确保数据收集的可靠性。
- **多语言环境支持**：在解析某些命令输出时，根据系统语言自动适配，支持中文和英文环境。

## 使用方法

### 1. 配置

首先，需要编辑 `config.yml` 文件，配置需要监控的节点和监控指标。例如：

```yaml
nodes:
  - ip: 192.168.1.101
    port: 22
    username: <username>
    password: <password>
  - ip: 192.168.1.102
    port: 22
    username: <username>
    password: <password>

metrics:
  - ssh_cpu_utilization
  - ssh_cpu_utilization_user
  - ssh_cpu_utilization_system
  - ssh_cpu_utilization_top5
  - ssh_cpu_percentage_wait
  - ssh_cpu_percentage_idle
  - ssh_cpu_count
  - ssh_memory_utilization
  - ssh_memory_utilization_top5
  - ssh_memory_utilization_swap
  - ssh_memory_available_bytes
  - ssh_memory_available_swap_bytes
  - ssh_disk_utilization
  - ssh_disk_used_bytes
  - ssh_disk_available_bytes
  - ssh_disk_read_bytes_total
  - ssh_disk_write_bytes_total
  - ssh_network_receive_bytes_total
  - ssh_network_transmit_bytes_total
```

### 2. 运行

直接运行 `ssh_exporter.py` 脚本即可启动 SSH Exporter 服务。服务将监听默认的 9122 端口，等待 Prometheus Server 的抓取请求。

```bash
python3 ssh_exporter.py
```

> 支持的Python版本：python>=3.8

### 3. Prometheus 配置

在 Prometheus 的配置文件中添加一个新的 job，指定 SSH Exporter 的地址，以便 Prometheus 可以抓取数据。

```yaml
scrape_configs:
  - job_name: 'ssh-exporter'
    static_configs:
      - targets: ['localhost:9122']
```

## 注意事项

- **安全性**：请确保 SSH 凭证（用户名和密码）的安全，避免泄露。
- **网络配置**：确保 Prometheus Server 可以访问运行 SSH Exporter 的服务器。
- **性能影响**：频繁的 SSH 连接和数据收集可能会对远程服务器造成一定的性能影响，请根据实际需求调整数据收集频率。

## 开发与维护

- **问题反馈**：请在 GitHub 仓库中提交 issues。
- **贡献代码**：欢迎提交 PR，共同完善 SSH Exporter。

## 许可证

SSH Exporter 采用 LGPL 许可证发布，详情请参阅 LICENSE 文件。
