# SSH Exporter
English | [中文](https://github.com/2018-11-27/ssh-exporter/blob/master/README_CN.md)

## Introduction

SSH Exporter is a monitoring tool based on the Prometheus specification. It remotely collects system performance data, such as CPU usage, memory utilization, disk and network I/O, from target servers via the SSH protocol. The collected data is exposed as Prometheus-formatted metrics, allowing it to be scraped and stored by a Prometheus Server.

## Features

- **Remote Monitoring**: Connects to remote servers via SSH, eliminating the need to install additional agents on the monitored servers.
- **Comprehensive System Monitoring**: Supports monitoring of multiple performance indicators including CPU, memory, disk, and network.
- **Dynamic Configuration**: Allows reading monitoring targets and parameters from a YAML configuration file, facilitating dynamic management of monitoring nodes.
- **Asynchronous Collection**: Uses a thread pool for asynchronous data collection, enhancing data collection efficiency.
- **Error Handling and Retry Mechanism**: Provides an automatic retry mechanism for SSH connection failures, ensuring reliable data collection.
- **Multi-language Environment Support**: Automatically adapts to the system language when parsing certain command outputs, supporting both Chinese and English environments.

## Usage

### 1. Configuration

First, edit the `config.yml` file to configure the nodes and metrics to be monitored. For example:

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

### 2. Running

Run the `ssh_exporter.py` script to start the SSH Exporter service. The service listens on the default port 9122, waiting for scraping requests from the Prometheus Server.

```bash
python3 ssh_exporter.py
```

> Supported Python versions: python>=3.8

### 3. Prometheus Configuration

Add a new job to the Prometheus configuration file, specifying the SSH Exporter's address so that Prometheus can scrape the data.

```yaml
scrape_configs:
  - job_name: 'ssh-exporter'
    static_configs:
      - targets: ['localhost:9122']
```

## Notes

- **Security**: Ensure the security of SSH credentials (username and password) to avoid leakage.
- **Network Configuration**: Ensure that the Prometheus Server can access the server running SSH Exporter.
- **Performance Impact**: Frequent SSH connections and data collection may have some performance impact on remote servers. Adjust the data collection frequency according to actual needs.

## Development and Maintenance

- **Feedback**: Please submit issues in the GitHub repository.
- **Contributing Code**: Contributions via pull requests are welcome to jointly improve SSH Exporter.

## License

SSH Exporter is released under the LGPL license. Please refer to the LICENSE file for details.
