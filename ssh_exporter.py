"""
Copyright (c) 2022 Lenovo. All right reserved.
Confidential and Proprietary

@date: 2022.12.05 11:02:43
@author: zhuyk4@lenovo.com
"""
import os
import re
import sys
import time
import copy
import socket
import select
import inspect
import threading

from socket import AF_INET
from socket import SOCK_STREAM
from socket import SOL_SOCKET
from socket import SO_REUSEADDR

import yaml
import prometheus_client

import gqylpy_cache
import gqylpy_log   as glog

from gqylpy_datastruct import DataStruct
from gqylpy_dict       import gdict
from gqylpy_ssh        import GqylpySSH
from gqylpy_ssh        import SSHException
from gqylpy_ssh        import NoValidConnectionsError

from prometheus_client         import generate_latest
from prometheus_client.metrics import MetricWrapperBase
from prometheus_client.metrics import Gauge

from typing import Generator

metrics = gdict(
    ssh_cpu_utilization={
        'type'         : 'Gauge',
        'documentation': 'utilization of cpu used',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name'
        )
    },
    ssh_cpu_utilization_user={
        'type'         : 'Gauge',
        'documentation': 'utilization of cpu used by user',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name'
        )
    },
    ssh_cpu_utilization_system={
        'type'         : 'Gauge',
        'documentation': 'utilization of cpu used by system',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name'
        )
    },
    ssh_cpu_utilization_top5={
        'type'         : 'Gauge',
        'documentation': 'utilization top 5 of cpu used by process',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id',  'device_name', 'pid',
            'command'
        )
    },
    ssh_cpu_percentage_wait={
        'type'         : 'Gauge',
        'documentation': 'percentage of cpu wait',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name'
        )
    },
    ssh_cpu_percentage_idle={
        'type'         : 'Gauge',
        'documentation': 'percentage of cpu idle',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name'
        )
    },
    ssh_cpu_count={
        'type': 'Gauge',
        'documentation': 'number of cpu',
        'labelnames': (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name'
        )
    },
    ssh_memory_utilization={
        'type'         : 'Gauge',
        'documentation': 'utilization of memory used',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name'
        )
    },
    ssh_memory_utilization_top5={
        'type'         : 'Gauge',
        'documentation': 'utilization top 5 of memory used by process',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name', 'pid',
            'command'
        )
    },
    ssh_memory_utilization_swap={
        'type'         : 'Gauge',
        'documentation': 'utilization of swap memory used',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name'
        )
    },
    ssh_memory_available_bytes={
        'type'         : 'Gauge',
        'documentation': 'available of memory in bytes',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name'
        )
    },
    ssh_memory_available_swap_bytes={
        'type'         : 'Gauge',
        'documentation': 'available of swap memory in bytes',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name'
        )
    },
    ssh_disk_utilization={
        'type'         : 'Gauge',
        'documentation': 'utilization of mount point',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name', 'device',
            'fstype', 'mountpoint'
        )
    },
    ssh_disk_used_bytes={
        'type'         : 'Gauge',
        'documentation': 'used of mount point in bytes',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name', 'device',
            'fstype', 'mountpoint'
        )
    },
    ssh_disk_available_bytes={
        'type'         : 'Gauge',
        'documentation': 'available of mount point in bytes',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name', 'device',
            'fstype', 'mountpoint'
        )
    },
    ssh_disk_read_bytes_total={
        'type'         : 'Gauge',
        'documentation': 'total disk read size in bytes',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name', 'device'
        )
    },
    ssh_disk_write_bytes_total={
        'type'         : 'Gauge',
        'documentation': 'total disk write size in bytes',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name', 'device'
        )
    },
    ssh_network_receive_bytes_total={
        'type'         : 'Gauge',
        'documentation': 'total interface receive in bytes',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name', 'device'
        )
    },
    ssh_network_transmit_bytes_total={
        'type'         : 'Gauge',
        'documentation': 'total interface transmit in bytes',
        'labelnames'   : (
            'hostname', 'hostuuid', 'ip', 'device_id', 'device_name', 'device'
        )
    }
)


class Time2Second(
    metaclass=type('', (type,), {'__call__': lambda *a: type.__call__(*a)()})
):
    matcher = re.compile(r'''^
        (?:(\d+(?:\.\d+)?)y)?
        (?:(\d+(?:\.\d+)?)d)?
        (?:(\d+(?:\.\d+)?)h)?
        (?:(\d+(?:\.\d+)?)m)?
        (?:(\d+(?:\.\d+)?)s)?
    $''', flags=re.X)

    m = 60
    h = 60  * m
    d = 24  * h
    y = 365 * d

    def __init__(self, unit_time: str, /):
        self.unit_time = unit_time

    def __call__(self) -> 'int | float':
        if self.unit_time.__class__ in (int, float):
            return self.unit_time
        elif self.unit_time.isdigit():
            return float(self.unit_time)
        y, d, h, m, s = self.matcher.findall(self.unit_time.lower())[0]
        y, d, h, m, s = self.g(y), self.g(d), self.g(h), self.g(m), self.g(s)
        return self.y * y + self.d * d + self.h * h + self.m * m + s

    @staticmethod
    def g(x: str) -> 'int | float':
        if not x:
            return 0
        try:
            return int(x)
        except ValueError:
            return float(x)


def init_socket(config: gdict) -> socket.socket:
    host, port = config['host'], config['port']

    skt = socket.socket(family=AF_INET, type=SOCK_STREAM)
    skt.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    skt.setblocking(0)

    skt.bind((host, port))
    skt.listen()

    glog.info(f'bind http://{host}:{port}')

    return skt


def init_ssh_connection(node: gdict) -> gdict:
    ip: str = node.pop('ip')
    not_ssh_params = {}

    for param in set(node) - {
        *inspect.signature(GqylpySSH.connect).parameters,
        'command_timeout', 'auto_sudo', 'reconnect'
    }:
        not_ssh_params[param] = node.pop(param)

    asynchronous: bool = \
        sys._getframe().f_back.f_code.co_name == 'init_ssh_connection_async'

    try:
        ssh = GqylpySSH(ip, **node)
    except (SSHException, NoValidConnectionsError, TimeoutError, OSError) as e:
        node.ip = ip
        for param, value in not_ssh_params.items():
            node[param] = value

        if asynchronous:
            raise e

        glog.warning(
            f'SSH connection to "{ip}" failed, '
            'will switch to background try until succeed.'
        )
        async_init_ssh_connection(node)
        return node

    ssh.cmd('echo Hi, SSH Exporter')
    node.hostname = ssh.cmd('hostname').output_else_raise()
    node.hostuuid = ssh.cmd(
        "dmidecode -t 1 | grep 'UUID: ' | awk '{print $NF}'"
    ).output_else_raise()

    node.ssh = ssh
    node.ip  = ip

    for param, value in not_ssh_params.items():
        node[param] = value

    if not asynchronous:
        glog.info(f'SSH connection to "{ip}" has been established.')

    return node


def async_init_ssh_connection(node: gdict, /, *, __nodes__=[]) -> None:
    __nodes__.append(node)
    if 'InitSSHConnectionAsync' in (
            child_thread.name for child_thread in threading.enumerate()
    ):
        return

    def init_ssh_connection_async():
        time.sleep(10)
        i = -1
        while __nodes__:
            try:
                n: gdict = __nodes__[i]
            except IndexError:
                time.sleep(10)
                i = -1
                n: gdict = __nodes__[i]
            try:
                init_ssh_connection(n)
            except (
                    SSHException, NoValidConnectionsError,
                    TimeoutError, OSError
            ):
                glog.warning(f'try SSH connection to "{n.ip}" failed once.')
                i -= 1
            else:
                glog.info(
                    f'try SSH connection to "{n.ip}" has been established.'
                )
                __nodes__.remove(n)

    threading.Thread(
        target=init_ssh_connection_async,
        name  ='InitSSHConnectionAsync',
        daemon=True
    ).start()


def init_metrics_wrapper(metric_list: list) -> list:
    for i, metric in enumerate(metric_list):
        config: gdict = metrics[metric]

        if config.__class__ is gdict:
            wrapper: MetricWrapperBase = getattr(
                prometheus_client.metrics, config.pop('type')
            )(metric, **config)
            metrics[metric] = metric_list[i] = wrapper
        else:
            metric_list[i]: MetricWrapperBase = config

    return metric_list


def delete_unused_metrics(metric_list: list):
    for metric, wrapper in metrics.copy().items():
        if wrapper.__class__ is gdict:
            del metrics[metric]
    return metric_list


branch       = 'branch'
items        = 'items'
coerce       = 'coerce'
default      = 'default'
env          = 'env'
option       = 'option'
enum         = 'enum'
verify       = 'verify'
params       = 'params'
optional     = 'optional'
delete_none  = 'delete_none'
delete_empty = 'delete_empty'
ignore_if_in = 'ignore_if_in'
callback     = 'callback'

re_ip     = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
re_domain = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'

config_struct = DataStruct({
    'server': {
        branch: {
            'host': {
                type   : str,
                default: '0.0.0.0',
                env    : 'HOST',
                option : '--host',
                verify : [re_ip, re_domain, lambda x: x == 'localhost'],
                params : [delete_empty]
            },
            'port': {
                type   : (int, str),
                coerce : int,
                default: 80,
                env    : 'PORT',
                option : '--port',
                verify : lambda x: 0 < x < 65536,
                params : [delete_empty]
            }
        },
        default : {'host': '0.0.0.0', 'port': 80},
        params  : [delete_empty],
        callback: init_socket
    },
    'log': {
        branch: {
            'level': {
                type   : str,
                default: 'INFO',
                env    : 'LOG_LEVEL',
                option : '--log-level',
                enum   : ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'FATAL'),
                params : [delete_empty]
            },
            'output': {
                type    : str,
                default : 'stream',
                set     : ('stream', 'file'),
                params  : [delete_empty],
                callback: lambda x: ','.join(x)
            },
            'logfile': {
                type  : str,
                params: [optional, delete_empty]
            },
            'datefmt': {
                type   : str,
                default: '%F %T',
                params : [delete_empty]
            },
            'logfmt': {
                type   : str,
                default: '[%(asctime)s] [%(funcName)s.line%(lineno)d] '
                         '[%(levelname)s] %(message)s',
                params : [delete_empty]
            }
        },
        default: {
            'level'  : 'INFO',
            'output' : 'stream',
            'datefmt': '%F %T',
            'logfmt' : '[%(asctime)s] [%(funcName)s.line%(lineno)d] '
                       '[%(levelname)s] %(message)s'
        },
        params  : [delete_empty],
        callback: lambda x: glog.__init__(__name__, **x, gname=__name__) and x
    },
    'nodes': {
        items: {
            branch: {
                'ip': {
                    type  : str,
                    verify: [re_ip, re_domain]
                },
                'port': {
                    type   : (int, str),
                    coerce : int,
                    default: 22,
                    verify : lambda x: 0 < x < 65536,
                    params : [delete_empty]
                },
                'username': {
                    type   : str,
                    default: 'ssh_exporter',
                    params : [delete_empty]
                },
                'password': {
                    type  : str,
                    params: [optional, delete_empty]
                },
                'key_filename': {
                    type  : str,
                    params: [optional, delete_empty]
                },
                'key_password': {
                    type  : str,
                    params: [optional, delete_empty]
                },
                'timeout': {
                    type    : (int, str),
                    coerce  : int,
                    default : 30,
                    env     : 'SSH_CONNECT_TIMEOUT',
                    option  : '--ssh-connect-timeout',
                    params  : [delete_empty],
                    callback: Time2Second
                },
                'command_timeout': {
                    type    : (int, str),
                    coerce  : int,
                    default : 10,
                    env     : 'SSH_COMMAND_TIMEOUT',
                    option  : '--ssh-command-timeout',
                    params  : [delete_empty],
                    callback: Time2Second
                },
                'allow_agent': {
                    type   : bool,
                    default: False,
                    params : [delete_empty]
                },
                'auto_sudo': {
                    type   : bool,
                    default: True,
                    params : [delete_empty]
                },
                'reconnect': {
                    type   : bool,
                    default: False,
                    params : [delete_empty]
                },
                'device_id': {
                    type   : (int, str),
                    default: 0
                },
                'device_name': {
                    type: str,
                    default: ''
                },
                'metrics': {
                    type    : list,
                    set     : tuple(metrics),
                    params  : [optional, delete_empty],
                    callback: init_metrics_wrapper
                },
                'collector': {
                    branch: {
                        'ignore_fstype': {
                            type    : list,
                            env     : 'COLLECTOR_IGNORE_FSTYPE',
                            option  : '--collector-ignore-fstype',
                            params  : [delete_empty],
                            callback: lambda x: '-x ' + ' -x '.join(x)
                        }
                    },
                    params: [optional, delete_empty]
                }
            },
            callback: init_ssh_connection
        },
        ignore_if_in: [[]]
    },
    'collector': {
        branch: {
            'ignore_fstype': {
                type: list,
                default: ['tmpfs', 'devtmpfs', 'overlay'],
                env: 'COLLECTOR_IGNORE_FSTYPE',
                option: '--collector-ignore-fstype',
                params: [delete_empty],
                callback: lambda x: '-x ' + ' -x '.join(x)
            }
        },
        default: {
            'ignore_fstype': ['tmpfs', 'devtmpfs', 'overlay']
        },
        params: [delete_empty]
    },
    'metrics': {
        type    : list,
        default : list(metrics),
        set     : tuple(metrics),
        params  : [delete_empty],
        callback: lambda x: delete_unused_metrics(init_metrics_wrapper(x))
    }
}, etitle='Config', eraise=True, ignore_undefined_data=True)


def output_config():
    config: gdict = copy.deepcopy(cnf)

    config.server = str(config.server)

    for i, wrapper in enumerate(config.metrics):
        config.metrics[i] = wrapper._name

    for node in config.nodes:
        if 'ssh' in node:
            node.ssh = str(node.ssh)
        if 'metrics' in node:
            node.metrics = [wrapper._name for wrapper in node.metrics]

    glog.info(f'config \n{yaml.dump(config, sort_keys=False)}')


class Collector(metaclass=gqylpy_cache):
    __shared_instance_cache__ = False

    def __init__(self, ssh: GqylpySSH, /, *, config: gdict):
        self.ssh    = ssh
        self.config = config

    @staticmethod
    def output2dict(output: str, /) -> Generator:
        lines = ([
            column.strip() for column in line.split()
        ] for line in output.splitlines())

        titles: list = next(lines)
        point:  int  = len(titles) - 1

        for line in lines:
            front, back = line[:point], line[point:]
            front.append(' '.join(back))
            yield dict(zip(titles, front))

    __not_cache__ = [output2dict]


class CPUCollector(Collector):
    matcher = re.compile(
        r'(?P<us>[\d.]+) us, *'
        r'(?P<sy>[\d.]+) sy, *'
        r'(?P<ni>[\d.]+) ni, *'
        r'(?P<id>[\d.]+) id, *'
        r'(?P<wa>[\d.]+) wa, *'
        r'(?P<hi>[\d.]+) hi, *'
        r'(?P<si>[\d.]+) si, *'
        r'(?P<st>[\d.]+) st'
    )

    @property
    def utilization(self) -> float:
        return float(self.info['us']) + float(self.info['sy'])

    @property
    def utilization_user(self) -> str:
        return self.info['us']

    @property
    def utilization_system(self) -> str:
        return self.info['sy']

    @property
    def utilization_top5(self) -> Generator:
        top5_processes: str = self.ssh.cmd('''
            ps aux --sort -pcpu | head -6 | 
            awk '{$1=$4=$5=$6=$7=$8=$9=$10=""; print $0}'
        ''').output_else_raise()
        return self.output2dict(top5_processes)

    @property
    def count(self) -> str:
        return self.ssh.cmd('''
            grep "^physical id" /proc/cpuinfo | sort | uniq | wc -l
        ''').output_else_raise()

    @property
    def percentage_idle(self) -> str:
        return self.info['id']

    @property
    def percentage_wait(self) -> str:
        return self.info['wa']

    @property
    def info(self) -> dict:
        info: str = self.ssh.cmd(
            'top -b -p0 -n1 | grep "^%Cpu(s):"'
        ).output_else_raise()
        return self.matcher.search(info, pos=8).groupdict()


class MemoryCollector(Collector):

    @property
    def utilization(self) -> float:
        return 1 - ((self.free + self.buffers + self.cached) / self.total)

    @property
    def utilization_top5(self) -> Generator:
        top5_processes: str = self.ssh.cmd('''
            ps aux --sort -pmem | head -6 | 
            awk '{$1=$3=$5=$6=$7=$8=$9=$10=""; print $0}'
        ''').output_else_raise()
        return self.output2dict(top5_processes)

    @property
    def utilization_swap(self) -> float:
        try:
            return 1 - (self.swap_free / self.swap_total)
        except ZeroDivisionError:
            return 0

    @property
    def available_bytes(self) -> int:
        return (self.total - (self.free + self.buffers + self.cached)) * 1024

    @property
    def available_swap_bytes(self) -> int:
        return self.swap_free * 1024

    @property
    def total(self) -> int:
        return int(self.info['MemTotal'])

    @property
    def free(self) -> int:
        return int(self.info['MemFree'])

    @property
    def buffers(self) -> int:
        return int(self.info['Buffers'])

    @property
    def cached(self) -> int:
        return int(self.info['Cached'])

    @property
    def swap_total(self) -> int:
        return int(self.info['SwapTotal'])

    @property
    def swap_free(self) -> int:
        return int(self.info['SwapFree'])

    @property
    def info(self) -> dict:
        info: str = self.ssh.cmd('''
            grep -E "^(MemTotal|MemFree|Buffers|Cached|SwapTotal|SwapFree)" \
                /proc/meminfo |
            awk '{print $1, $2}'
        ''').output_else_raise()
        return dict(line.split(': ') for line in info.splitlines())


class DiskCollector(Collector):

    @property
    def utilization_of_mountpoint(self) -> Generator:
        return (info['Use%'][:-1] for info in self.info_of_mountpoint)

    @property
    def used_bytes_of_mountpoint(self) -> Generator:
        return (info['Used'] for info in self.info_of_mountpoint)

    @property
    def available_bytes_of_mountpoint(self) -> Generator:
        return (info['Available'] for info in self.info_of_mountpoint)

    @property
    def read_bytes_total(self) -> Generator:
        return (int(info[1]) / 2 * 1024 for info in self.info_of_disk)

    @property
    def write_bytes_total(self) -> Generator:
        return (int(info[2]) / 2 * 1024 for info in self.info_of_disk)

    @property
    def filesystems(self) -> list:
        return [info['Filesystem'] for info in self.info_of_mountpoint]

    @property
    def filesystem_types(self) -> list:
        return [info['Type'] for info in self.info_of_mountpoint]

    @property
    def mountpoints(self) -> list:
        return [info['Mounted'] for info in self.info_of_mountpoint]

    @property
    def disks(self) -> list:
        return [info[0] for info in self.info_of_disk]

    @property
    def info_of_mountpoint(self) -> list:
        return list(self.ssh.cmd('''
            df -T --block-size=1 %s | awk '{$3=""; print $0}'
        ''' % self.config.ignore_fstype).table2dict())

    @property
    def info_of_disk(self) -> list:
        return list(self.ssh.cmd('''
            vmstat -d | grep -vE "^(disk| +?total)" | awk '{print $1, $4, $8}'
        ''').line2list())


class NetworkCollector(Collector):

    @property
    def receive_bytes_total(self) -> Generator:
        return (info[1] for info in self.info)

    @property
    def transmit_bytes_total(self) -> Generator:
        return (info[2] for info in self.info)

    @property
    def interfaces(self) -> list:
        return [info[0][:-1] for info in self.info]

    @property
    def info(self) -> list:
        return list(self.ssh.cmd('''
            grep -vE "^(Inter-| face)" /proc/net/dev | awk '{print $1, $2, $10}'
        ''').line2list())


class MetricsHandler:

    @classmethod
    def get(cls) -> Generator:
        for node in cnf.nodes:
            try:
                ssh: GqylpySSH = node.ssh
            except KeyError:
                continue

            collector_config: gdict = node.get('collector', cnf.collector)

            cpu     = CPUCollector    (ssh, config=collector_config)
            memory  = MemoryCollector (ssh, config=collector_config)
            disk    = DiskCollector   (ssh, config=collector_config)
            network = NetworkCollector(ssh, config=collector_config)

            for wrapper in node.get('metrics', cnf.metrics):
                try:
                    getattr(cls, f'get_{wrapper._name}')(
                        wrapper, node,
                        cpu    =cpu,
                        memory =memory,
                        disk   =disk,
                        network=network
                    )
                except (SSHException, TimeoutError, OSError):
                    glog.warning(
                        f'SSH connection to "{node.ip}" is break, will try '
                        f're-establish until succeed, always skip this node '
                        f'during this period.'
                    )
                    del node.ssh, node.hostname, node.hostuuid
                    async_init_ssh_connection(node)
                    break
                except Exception as e:
                    glog.error({
                        'msg'   : 'get metric error.',
                        'metric': wrapper._name,
                        'node'  : node.ip,
                        'e'     : e
                    })

        # for wrapper in metrics.values():
        #     try:
        #         yield generate_latest(wrapper)
        #     except Exception as e:
        #         glog.error({
        #             'msg'   : 'generate latest error.',
        #             'metric': wrapper._name,
        #             'e'     : e
        #         })
        #     wrapper.clear()
        for w in metrics.values():
            try:
                yield generate_latest(w)
            except Exception as e:
                wrappers = list(metrics.values())
                for ww in wrappers[wrappers.index(w):]:
                    ww.clear()
                raise e
            w.clear()

    @staticmethod
    def get_ssh_cpu_utilization(
            wrapper: Gauge,
            node:    gdict,
            *,
            cpu:     CPUCollector,
            **other_collectors
    ) -> None:
        v: float = cpu.utilization
        wrapper.labels(
            hostname   =node.hostname,
            hostuuid   =node.hostuuid,
            ip         =node.ip,
            device_id  =node.device_id,
            device_name=node.device_name
        ).set(v)

    @staticmethod
    def get_ssh_cpu_utilization_user(
            wrapper: Gauge,
            node:    gdict,
            *,
            cpu:     CPUCollector,
            **other_collectors
    ) -> None:
        v: str = cpu.utilization_user
        wrapper.labels(
            hostname   =node.hostname,
            hostuuid   =node.hostuuid,
            ip         =node.ip,
            device_id  =node.device_id,
            device_name=node.device_name
        ).set(v)

    @staticmethod
    def get_ssh_cpu_utilization_system(
            wrapper: Gauge,
            node:    gdict,
            *,
            cpu:     CPUCollector,
            **other_collectors
    ) -> None:
        v: str = cpu.utilization_system
        wrapper.labels(
            hostname   =node.hostname,
            hostuuid   =node.hostuuid,
            ip         =node.ip,
            device_id  =node.device_id,
            device_name=node.device_name
        ).set(v)

    @staticmethod
    def get_ssh_cpu_utilization_top5(
            wrapper: Gauge,
            node:    gdict,
            *,
            cpu:     CPUCollector,
            **other_collectors
    ) -> None:
        for top in cpu.utilization_top5:
            wrapper.labels(
                hostname   =node.hostname,
                hostuuid   =node.hostuuid,
                ip         =node.ip,
                device_id  =node.device_id,
                device_name=node.device_name,
                pid        =top['PID'],
                command    =top['COMMAND']
            ).set(top['%CPU'])

    @staticmethod
    def get_ssh_cpu_percentage_idle(
            wrapper: Gauge,
            node:    gdict,
            *,
            cpu:     CPUCollector,
            **other_collectors
    ) -> None:
        v: str = cpu.percentage_idle
        wrapper.labels(
            hostname   =node.hostname,
            hostuuid   =node.hostuuid,
            ip         =node.ip,
            device_id  =node.device_id,
            device_name=node.device_name
        ).set(v)

    @staticmethod
    def get_ssh_cpu_percentage_wait(
            wrapper: Gauge,
            node:    gdict,
            *,
            cpu:     CPUCollector,
            **other_collectors,
    ) -> None:
        v: str = cpu.percentage_wait
        wrapper.labels(
            hostname   =node.hostname,
            hostuuid   =node.hostuuid,
            ip         =node.ip,
            device_id  =node.device_id,
            device_name=node.device_name
        ).set(v)

    @staticmethod
    def get_ssh_cpu_count(
            wrapper: Gauge,
            node:    gdict,
            *,
            cpu:     CPUCollector,
            **other_collectors,
    ) -> None:
        v: str = cpu.count
        wrapper.labels(
            hostname   =node.hostname,
            hostuuid   =node.hostuuid,
            ip         =node.ip,
            device_id  =node.device_id,
            device_name=node.device_name
        ).set(v)

    @staticmethod
    def get_ssh_memory_utilization(
            wrapper: Gauge,
            node:    gdict,
            *,
            memory:  MemoryCollector,
            **other_collectors
    ) -> None:
        v: float = memory.utilization
        wrapper.labels(
            hostname   =node.hostname,
            hostuuid   =node.hostuuid,
            ip         =node.ip,
            device_id  =node.device_id,
            device_name=node.device_name
        ).set(v)

    @staticmethod
    def get_ssh_memory_utilization_top5(
            wrapper: Gauge,
            node:    gdict,
            *,
            memory:  MemoryCollector,
            **other_collectors
    ) -> None:
        for top in memory.utilization_top5:
            wrapper.labels(
                hostname   =node.hostname,
                hostuuid   =node.hostuuid,
                ip         =node.ip,
                device_id  =node.device_id,
                device_name=node.device_name,
                pid        =top['PID'],
                command    =top['COMMAND']
            ).set(top['%MEM'])

    @staticmethod
    def get_ssh_memory_utilization_swap(
            wrapper: Gauge,
            node:    gdict,
            *,
            memory:  MemoryCollector,
            **other_collectors
    ) -> None:
        v: float = memory.utilization_swap
        wrapper.labels(
            hostname   =node.hostname,
            hostuuid   =node.hostuuid,
            ip         =node.ip,
            device_id  =node.device_id,
            device_name=node.device_name
        ).set(v)

    @staticmethod
    def get_ssh_memory_available_bytes(
            wrapper: Gauge,
            node:    gdict,
            *,
            memory:  MemoryCollector,
            **other_collectors
    ) -> None:
        v: int = memory.available_bytes
        wrapper.labels(
            hostname   =node.hostname,
            hostuuid   =node.hostuuid,
            ip         =node.ip,
            device_id  =node.device_id,
            device_name=node.device_name
        ).set(v)

    @staticmethod
    def get_ssh_memory_available_swap_bytes(
            wrapper: Gauge,
            node:    gdict,
            *,
            memory:  MemoryCollector,
            **other_collectors
    ) -> None:
        v: int = memory.available_swap_bytes
        wrapper.labels(
            hostname   =node.hostname,
            hostuuid   =node.hostuuid,
            ip         =node.ip,
            device_id  =node.device_id,
            device_name=node.device_name
        ).set(v)

    @staticmethod
    def get_ssh_disk_utilization(
            wrapper: Gauge,
            node:    gdict,
            *,
            disk:    DiskCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(disk.utilization_of_mountpoint):
            wrapper.labels(
                hostname   =node.hostname,
                hostuuid   =node.hostuuid,
                ip         =node.ip,
                device_id  =node.device_id,
                device_name=node.device_name,
                device     =disk.filesystems[i],
                fstype     =disk.filesystem_types[i],
                mountpoint =disk.mountpoints[i]
            ).set(v)

    @staticmethod
    def get_ssh_disk_used_bytes(
            wrapper: Gauge,
            node:    gdict,
            *,
            disk:    DiskCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(disk.used_bytes_of_mountpoint):
            wrapper.labels(
                hostname   =node.hostname,
                hostuuid   =node.hostuuid,
                ip         =node.ip,
                device_id  =node.device_id,
                device_name=node.device_name,
                device     =disk.filesystems[i],
                fstype     =disk.filesystem_types[i],
                mountpoint =disk.mountpoints[i]
            ).set(v)

    @staticmethod
    def get_ssh_disk_available_bytes(
            wrapper: Gauge,
            node:    gdict,
            *,
            disk:    DiskCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(disk.available_bytes_of_mountpoint):
            wrapper.labels(
                hostname   =node.hostname,
                hostuuid   =node.hostuuid,
                ip         =node.ip,
                device_id  =node.device_id,
                device_name=node.device_name,
                device     =disk.filesystems[i],
                fstype     =disk.filesystem_types[i],
                mountpoint =disk.mountpoints[i]
            ).set(v)

    @staticmethod
    def get_ssh_disk_read_bytes_total(
            wrapper: Gauge,
            node:    gdict,
            *,
            disk:    DiskCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(disk.read_bytes_total):
            wrapper.labels(
                hostname   =node.hostname,
                hostuuid   =node.hostuuid,
                ip         =node.ip,
                device_id  =node.device_id,
                device_name=node.device_name,
                device     =disk.disks[i]
            ).set(v)

    @staticmethod
    def get_ssh_disk_write_bytes_total(
            wrapper: Gauge,
            node:    gdict,
            *,
            disk:    DiskCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(disk.write_bytes_total):
            wrapper.labels(
                hostname   =node.hostname,
                hostuuid   =node.hostuuid,
                ip         =node.ip,
                device_id  =node.device_id,
                device_name=node.device_name,
                device     =disk.disks[i]
            ).set(v)

    @staticmethod
    def get_ssh_network_receive_bytes_total(
            wrapper: Gauge,
            node:    gdict,
            *,
            network: NetworkCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(network.receive_bytes_total):
            wrapper.labels(
                hostname   =node.hostname,
                hostuuid   =node.hostuuid,
                ip         =node.ip,
                device_id  =node.device_id,
                device_name=node.device_name,
                device     =network.interfaces[i]
            ).set(v)

    @staticmethod
    def get_ssh_network_transmit_bytes_total(
            wrapper: Gauge,
            node:    gdict,
            *,
            network: NetworkCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(network.transmit_bytes_total):
            wrapper.labels(
                hostname   =node.hostname,
                hostuuid   =node.hostuuid,
                ip         =node.ip,
                device_id  =node.device_id,
                device_name=node.device_name,
                device     =network.interfaces[i]
            ).set(v)


if __name__ == '__main__':
    basedir: str = os.path.dirname(os.path.abspath(__file__))

    with open(os.path.join(basedir, 'config.yml'), encoding='utf8') as f:
        user_config: dict = yaml.safe_load(f)

    cnf = gdict(user_config)
    config_struct.verify(cnf)
    output_config()

    index = b'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>SSH Exporter</title>
        </head>
            <body>
                <h1>SSH Exporter</h1>
                <a href="/metrics">metrics</a>
            </body>
        </html>
    '''  #

    server: socket.socket = cnf.server
    rlist = [server]

    while True:
        for read_event in select.select(rlist, [], [])[0]:
            if read_event is server:
                rlist.append(server.accept()[0])
            else:
                try:
                    body: bytes = read_event.recv(8192)
                    if body[:21] == b'GET /metrics HTTP/1.1':
                        start = time.time()
                        response: bytes = b''.join(MetricsHandler.get())
                        runtime = round(time.time() - start, 2)
                        glog.info(f'GET /metrics 200 (runtime:{runtime}s)')
                    else:
                        response: bytes = index
                        glog.info('GET /<any> 200')
                    read_event.sendall(b'HTTP/1.1 200 OK\r\n\r\n' + response)
                except Exception as ee:
                    glog.error(f'server error, {ee}')
                finally:
                    rlist.remove(read_event)
                    read_event.close()
