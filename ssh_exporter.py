"""
This file is part of ssh-exporter.

ssh-exporter is free software: you can redistribute it and/or modify it under the
terms of the GNU Lesser General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

ssh-exporter is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with ssh-exporter. If not, see <https://www.gnu.org/licenses/>.
"""
import os
import re
import sys
import time
import socket
import select
import inspect
import threading

from socket import AF_INET
from socket import SOCK_STREAM
from socket import SOL_SOCKET
from socket import SO_REUSEADDR

from concurrent.futures import ThreadPoolExecutor

import yaml
import prometheus_client
import funccache
import gqylpy_log as glog

from gqylpy_datastruct import DataStruct
from gqylpy_dict import gdict
from gqylpy_ssh import GqylpySSH
from gqylpy_ssh import SSHException
from gqylpy_ssh import NoValidConnectionsError
from systempath import File
from systempath import Directory
from prometheus_client import generate_latest
from prometheus_client.metrics import MetricWrapperBase
from prometheus_client.metrics import Gauge

from typing import Final, Union, Generator, Callable, Any

basedir: Final[Directory] = File(__file__, strict=True).dirname

god: Final = gdict(
    yaml.safe_load(basedir['config.yml'].open.rb()), basedir=basedir
)

metrics: Final = gdict(
    ssh_cpu_utilization={
        'type': 'Gauge',
        'documentation': 'utilization of cpu used',
        'labelnames': ('hostname', 'hostuuid', 'ip')
    },
    ssh_cpu_utilization_user={
        'type': 'Gauge',
        'documentation': 'utilization of cpu used by user',
        'labelnames': ('hostname', 'hostuuid', 'ip')
    },
    ssh_cpu_utilization_system={
        'type': 'Gauge',
        'documentation': 'utilization of cpu used by system',
        'labelnames': ('hostname', 'hostuuid', 'ip')
    },
    ssh_cpu_utilization_top5={
        'type': 'Gauge',
        'documentation': 'utilization top 5 of cpu used by process',
        'labelnames': ('hostname', 'hostuuid', 'ip', 'pid', 'command', 'args')
    },
    ssh_cpu_percentage_wait={
        'type': 'Gauge',
        'documentation': 'percentage of cpu wait',
        'labelnames': ('hostname', 'hostuuid', 'ip')
    },
    ssh_cpu_percentage_idle={
        'type': 'Gauge',
        'documentation': 'percentage of cpu idle',
        'labelnames': ('hostname', 'hostuuid', 'ip')
    },
    ssh_cpu_count={
        'type': 'Gauge',
        'documentation': 'number of cpu',
        'labelnames': ('hostname', 'hostuuid', 'ip')
    },
    ssh_memory_utilization={
        'type': 'Gauge',
        'documentation': 'utilization of memory used',
        'labelnames': ('hostname', 'hostuuid', 'ip')
    },
    ssh_memory_utilization_top5={
        'type': 'Gauge',
        'documentation': 'utilization top 5 of memory used by process',
        'labelnames': ('hostname', 'hostuuid', 'ip', 'pid', 'command', 'args')
    },
    ssh_memory_utilization_swap={
        'type': 'Gauge',
        'documentation': 'utilization of swap memory used',
        'labelnames': ('hostname', 'hostuuid', 'ip')
    },
    ssh_memory_available_bytes={
        'type': 'Gauge',
        'documentation': 'available of memory in bytes',
        'labelnames': ('hostname', 'hostuuid', 'ip')
    },
    ssh_memory_available_swap_bytes={
        'type': 'Gauge',
        'documentation': 'available of swap memory in bytes',
        'labelnames': ('hostname', 'hostuuid', 'ip')
    },
    ssh_disk_utilization={
        'type': 'Gauge',
        'documentation': 'utilization of mount point',
        'labelnames': (
            'hostname', 'hostuuid', 'ip', 'device', 'fstype', 'mountpoint'
        )
    },
    ssh_disk_used_bytes={
        'type': 'Gauge',
        'documentation': 'used of mount point in bytes',
        'labelnames': (
            'hostname', 'hostuuid', 'ip', 'device', 'fstype', 'mountpoint'
        )
    },
    ssh_disk_available_bytes={
        'type': 'Gauge',
        'documentation': 'available of mount point in bytes',
        'labelnames': (
            'hostname', 'hostuuid', 'ip', 'device', 'fstype', 'mountpoint'
        )
    },
    ssh_disk_read_bytes_total={
        'type': 'Gauge',
        'documentation': 'total disk read size in bytes',
        'labelnames': ('hostname', 'hostuuid', 'ip', 'device')
    },
    ssh_disk_write_bytes_total={
        'type': 'Gauge',
        'documentation': 'total disk write size in bytes',
        'labelnames': ('hostname', 'hostuuid', 'ip', 'device')
    },
    ssh_network_receive_bytes_total={
        'type': 'Gauge',
        'documentation': 'total interface receive in bytes',
        'labelnames': ('hostname', 'hostuuid', 'ip', 'device')
    },
    ssh_network_transmit_bytes_total={
        'type': 'Gauge',
        'documentation': 'total interface transmit in bytes',
        'labelnames': ('hostname', 'hostuuid', 'ip', 'device')
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
    h = 60 * m
    d = 24 * h
    y = 365 * d

    def __init__(self, unit_time: str, /):
        self.unit_time = unit_time

    def __call__(self) -> Union[int, float]:
        if isinstance(self.unit_time, (int, float)):
            return self.unit_time
        elif self.unit_time.isdigit():
            return float(self.unit_time)
        y, d, h, m, s = self.matcher.findall(self.unit_time.lower())[0]
        y, d, h, m, s = self.g(y), self.g(d), self.g(h), self.g(m), self.g(s)
        return self.y * y + self.d * d + self.h * h + self.m * m + s

    @staticmethod
    def g(x: str) -> Union[int, float]:
        return 0 if not x else int(x) if x.isdigit() else float(x)


def init_socket(config: gdict) -> socket.socket:
    host, port = config.host, config.port

    skt = socket.socket(family=AF_INET, type=SOCK_STREAM)
    skt.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    skt.setblocking(False)

    skt.bind((host, port))
    skt.settimeout(config.timeout)
    skt.listen()

    glog.info(f'bind http://{host}:{port}')

    return skt


def init_ssh_connection(nodes: list) -> list:
    node_number: int = len(nodes)

    if node_number > 1:
        with ThreadPoolExecutor(node_number, 'InitSSHConnection') as pool:
            pool.map(init_ssh_connection_each, nodes)
    else:
        init_ssh_connection_each(nodes[0])

    return nodes


def init_ssh_connection_each(node: gdict):
    ip: str = node.pop('ip')

    not_ssh_params = dict((param, node.pop(param)) for param in set(node) - {
        *inspect.signature(GqylpySSH.connect).parameters,
        'command_timeout', 'auto_sudo', 'reconnect'
    })

    retry: bool = sys._getframe(1).f_code.co_name == 'init_ssh_connection_retry'

    try:
        ssh = GqylpySSH(ip, **node)
        ssh.cmd('echo Hi, SSH Exporter')

        node.hostname = ssh.cmd('hostname').output_else_raise()
        node.hostuuid = ssh.cmd(
            "dmidecode -t 1 | grep 'UUID: ' | awk '{print $NF}'"
        ).output_else_raise()

        node.system_lang = ssh.cmd('echo $LANG').output_else_raise()[:5].lower()
    except (SSHException, NoValidConnectionsError, OSError, EOFError) as e:
        node.ip = ip
        node.update(not_ssh_params)

        if retry:
            raise e

        glog.warning(
            f'SSH connection to "{ip}" failed, '
            'will switch to asynchronous try until succeed.'
        )

        init_ssh_connection_again(node)
    else:
        node.ssh = ssh
        node.ip = ip
        node.update(not_ssh_params)

        if not retry:
            glog.info(f'SSH connection to "{ip}" has been established.')


def init_ssh_connection_again(node: gdict, *, __nodes__=[]) -> None:
    __nodes__.append(node)

    if 'InitSSHConnectionAgain' in (x.name for x in threading.enumerate()):
        return

    def init_ssh_connection_retry():
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
                init_ssh_connection_each(n)
            except (SSHException, NoValidConnectionsError, OSError, EOFError):
                glog.warning(f'try SSH connection to "{n.ip}" failed once.')
                i -= 1
            else:
                glog.info(
                    f'try SSH connection to "{n.ip}" has been established.'
                )
                __nodes__.remove(n)

    threading.Thread(
        target=init_ssh_connection_retry,
        name='InitSSHConnectionAgain',
        daemon=True
    ).start()


def init_collector_ignore_fstype(ignore_fstype: Union[list, str]) -> str:
    if not ignore_fstype:
        return ''

    if ignore_fstype.__class__ is list:
        x: str = ' -x '.join(ignore_fstype)
    else:
        x: str = ' -x '.join(i.strip() for i in ignore_fstype.split(','))

    return '-x ' + x


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


def delete_unused_metrics(metric_list: list) -> list:
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
delete_empty = 'delete_empty'
ignore_if_in = 'ignore_if_in'
callback     = 'callback'

re_ip = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
re_domain = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'

DataStruct({
    'log': {
        branch: {
            'level': {
                type: str,
                default: 'INFO',
                env: 'LOG_LEVEL',
                option: '--log-level',
                enum: ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'FATAL'),
                params: [delete_empty]
            },
            'output': {
                type: (str, list),
                default: 'stream',
                set: ('stream', 'file'),
                params: [delete_empty],
                callback: lambda x: ','.join(x)
            },
            'logfile': {
                type: str,
                params: [optional, delete_empty]
            },
            'datefmt': {
                type: str,
                default: '%F %T',
                params: [delete_empty]
            },
            'logfmt': {
                type: str,
                default: '[%(asctime)s] [%(funcName)s.line%(lineno)d] '
                         '[%(levelname)s] %(message)s',
                params: [delete_empty]
            }
        },
        default: {},
        params: [delete_empty],
        callback: lambda x: glog.__init__(__name__, **x, gname=__name__) and x
    },
    'nodes': {
        items: {
            branch: {
                'ip': {
                    type: str,
                    verify: [re_ip, re_domain]
                },
                'port': {
                    type: (int, str),
                    coerce: int,
                    default: 22,
                    verify: lambda x: -1 < x < 1 << 16,
                    params: [delete_empty]
                },
                'username': {
                    type: str,
                    default: 'ssh_exporter',
                    params: [delete_empty],
                    callback: lambda x: x.strip()
                },
                'password': {
                    type: str,
                    params: [optional, delete_empty]
                },
                'key_filename': {
                    type: str,
                    params: [optional, delete_empty]
                },
                'key_password': {
                    type: str,
                    params: [optional, delete_empty]
                },
                'timeout': {
                    type: (int, str),
                    default: 30,
                    env: 'SSH_CONNECT_TIMEOUT',
                    option: '--ssh-connect-timeout',
                    params: [delete_empty],
                    callback: Time2Second
                },
                'command_timeout': {
                    type: (int, str),
                    default: 10,
                    env: 'SSH_COMMAND_TIMEOUT',
                    option: '--ssh-command-timeout',
                    params: [delete_empty],
                    callback: Time2Second
                },
                'allow_agent': {
                    type: bool,
                    default: False,
                    params: [delete_empty]
                },
                'auto_sudo': {
                    type: bool,
                    default: True,
                    params: [optional, delete_empty]
                },
                'reconnect': {
                    type: bool,
                    default: False,
                    params: [delete_empty]
                },
                'metrics': {
                    type: list,
                    set: tuple(metrics),
                    params: [optional, delete_empty],
                    callback: init_metrics_wrapper
                },
                'collector': {
                    branch: {
                        'ignore_fstype': {
                            type: list,
                            params: [optional],
                            callback: init_collector_ignore_fstype
                        }
                    },
                    params: [optional, delete_empty]
                }
            }
        },
        callback: lambda x: init_ssh_connection(x),
        ignore_if_in: [[]]
    },
    'collector': {
        branch: {
            'ignore_fstype': {
                type: (list, str),
                default: ['tmpfs', 'devtmpfs', 'overlay'],
                env: 'COLLECTOR_IGNORE_FSTYPE',
                option: '--collector-ignore-fstype',
                params: [delete_empty],
                callback: init_collector_ignore_fstype
            }
        },
        default: {}
    },
    'metrics': {
        type: list,
        default: list(metrics),
        set: tuple(metrics),
        params: [delete_empty],
        callback: lambda x: delete_unused_metrics(init_metrics_wrapper(x))
    },
    'server': {
        branch: {
            'host': {
                type: str,
                default: '0.0.0.0',
                env: 'HOST',
                option: '--host',
                verify: [re_ip, re_domain, lambda x: x == 'localhost'],
                params: [delete_empty]
            },
            'port': {
                type: (int, str),
                coerce: int,
                default: 9122,
                env: 'PORT',
                option: '--port',
                verify: lambda x: -1 < x < 1 << 16,
                params: [delete_empty]
            },
            'timeout': {
                type: (int, str),
                default: '1m',
                env: 'SERVER_TIMEOUT',
                option: '--server-timeout',
                params: [delete_empty],
                callback: Time2Second
            }
        },
        default: {},
        callback: init_socket
    }
}, etitle='Config', eraise=True, ignore_undefined_data=True).verify(god)


class Collector(metaclass=funccache):
    __shared_instance_cache__ = False

    def __init__(self, node: gdict, /, *, config: gdict):
        self.ssh: GqylpySSH = node.ssh
        self.system_lang: str = node.system_lang
        self.config = config

    @staticmethod
    def output2dict_for_utilization_top5(output: str, /) -> Generator:
        lines = ([
            column.strip() for column in line.split()
        ] for line in output.splitlines())

        title: list = next(lines)
        point: int = len(title)
        title.append('ARGS')

        for line in lines:
            front = line[:point]
            front.append(' '.join(line[point:]))
            yield dict(zip(title, front))


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
        return self.output2dict_for_utilization_top5(top5_processes)

    @property
    def count(self) -> str:
        return self.ssh.cmd('''
            grep "^processor" /proc/cpuinfo | sort | uniq | wc -l
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
        return 100 - self.available / self.total * 100

    @property
    def utilization_top5(self) -> Generator:
        top5_processes: str = self.ssh.cmd('''
            ps aux --sort -pmem | head -6 | 
            awk '{$1=$3=$5=$6=$7=$8=$9=$10=""; print $0}'
        ''').output_else_raise()
        return self.output2dict_for_utilization_top5(top5_processes)

    @property
    def utilization_swap(self) -> Union[float, int]:
        try:
            return 1 - (self.swap_free / self.swap_total)
        except ZeroDivisionError:
            return 0

    @property
    def available_bytes(self) -> int:
        return (self.total - self.available) * 1024

    @property
    def available_swap_bytes(self) -> int:
        return self.swap_free * 1024

    @property
    def available(self) -> int:
        return self.free + self.buffers + self.cached

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
    system_lang_mapping = {
        'utilization_of_mountpoint': {'zh_cn': '已用%', 'en_us': 'Use%'},
        'used_bytes_of_mountpoint': {'zh_cn': '已用', 'en_us': 'Used'},
        'available_bytes_of_mountpoint': {'zh_cn': '可用', 'en_us': 'Available'},
        'filesystems': {'zh_cn': '文件系统', 'en_us': 'Filesystem'},
        'filesystem_types': {'zh_cn': '类型', 'en_us': 'Type'},
        'mountpoints': {'zh_cn': '挂载点', 'en_us': 'Mounted'}
    }

    def system_lang_selector(func) -> Callable[['DiskCollector'], Callable]:
        def inner(self: 'DiskCollector') -> Any:
            mapping: dict = self.system_lang_mapping[func.__name__]
            title: str = mapping.get(self.system_lang, mapping['en_us'])
            return func(self, title=title)

        return inner

    @property
    @system_lang_selector
    def utilization_of_mountpoint(self, *, title) -> Generator:
        return (info[title][:-1] for info in self.info_of_mountpoint)

    @property
    @system_lang_selector
    def used_bytes_of_mountpoint(self, *, title) -> Generator:
        return (info[title] for info in self.info_of_mountpoint)

    @property
    @system_lang_selector
    def available_bytes_of_mountpoint(self, *, title) -> Generator:
        return (info[title] for info in self.info_of_mountpoint)

    @property
    def read_bytes_total(self) -> Generator:
        return (int(info[1]) / 2 * 1024 for info in self.info_of_disk)

    @property
    def write_bytes_total(self) -> Generator:
        return (int(info[2]) / 2 * 1024 for info in self.info_of_disk)

    @property
    @system_lang_selector
    def filesystems(self, *, title) -> list:
        return [info[title] for info in self.info_of_mountpoint]

    @property
    @system_lang_selector
    def filesystem_types(self, *, title) -> list:
        return [info[title] for info in self.info_of_mountpoint]

    @property
    @system_lang_selector
    def mountpoints(self, *, title) -> list:
        return [info[title] for info in self.info_of_mountpoint]

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
        disks: list = self.ssh.cmd('''
            lsblk -d -o name,type | grep " disk$" | awk '{print $1}'
        ''').output_else_raise().splitlines()

        disk_performance: Generator = self.ssh.cmd('''
            vmstat -d | grep -vE "^(disk| +?total)" | awk '{print $1, $4, $8}'
        ''').line2list()

        return [disk for disk in disk_performance if disk[0] in disks]


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
        nodes = [node for node in god.nodes if 'ssh' in node]

        pool = ThreadPoolExecutor(
            max_workers=min(len(nodes) * len(metrics), os.cpu_count() * 5),
            thread_name_prefix='Collector'
        )

        for node in nodes:
            collector_config: gdict = node.get('collector', god.collector)

            cpu = CPUCollector(node, config=collector_config)
            memory = MemoryCollector(node, config=collector_config)
            disk = DiskCollector(node, config=collector_config)
            network = NetworkCollector(node, config=collector_config)

            for wrapper in node.get('metrics', god.metrics):
                pool.submit(
                    cls.get_metric, wrapper, node,
                    cpu=cpu, memory=memory, disk=disk, network=network
                )

        pool.shutdown()

        for w in metrics.values():
            try:
                yield generate_latest(w)
            except Exception as e:
                wrappers = list(metrics.values())
                for ww in wrappers[wrappers.index(w):]:
                    ww.clear()
                raise e
            w.clear()

    @classmethod
    def get_metric(cls, wrapper: Gauge, node: gdict, **collectors) -> None:
        try:
            getattr(cls, f'get_metric__{wrapper._name}')(
                wrapper, node, **collectors
            )
        except (SSHException, OSError, EOFError):
            del node.ssh, node.hostname, node.hostuuid
            glog.warning(
                f'SSH connection to "{node.ip}" is break, will try '
                're-establish until succeed, always skip this node '
                'during this period.'
            )
            init_ssh_connection_again(node)
        except Exception as e:
            glog.error({
                'msg': 'get metric error.',
                'metric': wrapper._name,
                'node': node.ip,
                'e': e
            })

    @staticmethod
    def get_metric__ssh_cpu_utilization(
            wrapper: Gauge,
            node: gdict,
            *,
            cpu: CPUCollector,
            **other_collectors
    ) -> None:
        v: float = cpu.utilization
        wrapper.labels(
            hostname=node.hostname,
            hostuuid=node.hostuuid,
            ip=node.ip
        ).set(v)

    @staticmethod
    def get_metric__ssh_cpu_utilization_user(
            wrapper: Gauge,
            node: gdict,
            *,
            cpu: CPUCollector,
            **other_collectors
    ) -> None:
        v: str = cpu.utilization_user
        wrapper.labels(
            hostname=node.hostname,
            hostuuid=node.hostuuid,
            ip=node.ip
        ).set(v)

    @staticmethod
    def get_metric__ssh_cpu_utilization_system(
            wrapper: Gauge,
            node: gdict,
            *,
            cpu: CPUCollector,
            **other_collectors
    ) -> None:
        v: str = cpu.utilization_system
        wrapper.labels(
            hostname=node.hostname,
            hostuuid=node.hostuuid,
            ip=node.ip
        ).set(v)

    @staticmethod
    def get_metric__ssh_cpu_utilization_top5(
            wrapper: Gauge,
            node: gdict,
            *,
            cpu: CPUCollector,
            **other_collectors
    ) -> None:
        for top in cpu.utilization_top5:
            wrapper.labels(
                hostname=node.hostname,
                hostuuid=node.hostuuid,
                ip=node.ip,
                pid=top['PID'],
                command=top['COMMAND'],
                args=top['ARGS']
            ).set(top['%CPU'])

    @staticmethod
    def get_metric__ssh_cpu_percentage_idle(
            wrapper: Gauge,
            node: gdict,
            *,
            cpu: CPUCollector,
            **other_collectors
    ) -> None:
        v: str = cpu.percentage_idle
        wrapper.labels(
            hostname=node.hostname,
            hostuuid=node.hostuuid,
            ip=node.ip
        ).set(v)

    @staticmethod
    def get_metric__ssh_cpu_percentage_wait(
            wrapper: Gauge,
            node: gdict,
            *,
            cpu: CPUCollector,
            **other_collectors,
    ) -> None:
        v: str = cpu.percentage_wait
        wrapper.labels(
            hostname=node.hostname,
            hostuuid=node.hostuuid,
            ip=node.ip
        ).set(v)

    @staticmethod
    def get_metric__ssh_cpu_count(
            wrapper: Gauge,
            node: gdict,
            *,
            cpu: CPUCollector,
            **other_collectors,
    ) -> None:
        v: str = cpu.count
        wrapper.labels(
            hostname=node.hostname,
            hostuuid=node.hostuuid,
            ip=node.ip
        ).set(v)

    @staticmethod
    def get_metric__ssh_memory_utilization(
            wrapper: Gauge,
            node: gdict,
            *,
            memory: MemoryCollector,
            **other_collectors
    ) -> None:
        v: float = memory.utilization
        wrapper.labels(
            hostname=node.hostname,
            hostuuid=node.hostuuid,
            ip=node.ip
        ).set(v)

    @staticmethod
    def get_metric__ssh_memory_utilization_top5(
            wrapper: Gauge,
            node: gdict,
            *,
            memory: MemoryCollector,
            **other_collectors
    ) -> None:
        for top in memory.utilization_top5:
            wrapper.labels(
                hostname=node.hostname,
                hostuuid=node.hostuuid,
                ip=node.ip,
                pid=top['PID'],
                command=top['COMMAND'],
                args=top['ARGS']
            ).set(top['%MEM'])

    @staticmethod
    def get_metric__ssh_memory_utilization_swap(
            wrapper: Gauge,
            node: gdict,
            *,
            memory: MemoryCollector,
            **other_collectors
    ) -> None:
        v: float = memory.utilization_swap
        wrapper.labels(
            hostname=node.hostname,
            hostuuid=node.hostuuid,
            ip=node.ip
        ).set(v)

    @staticmethod
    def get_metric__ssh_memory_available_bytes(
            wrapper: Gauge,
            node: gdict,
            *,
            memory: MemoryCollector,
            **other_collectors
    ) -> None:
        v: int = memory.available_bytes
        wrapper.labels(
            hostname=node.hostname,
            hostuuid=node.hostuuid,
            ip=node.ip
        ).set(v)

    @staticmethod
    def get_metric__ssh_memory_available_swap_bytes(
            wrapper: Gauge,
            node: gdict,
            *,
            memory: MemoryCollector,
            **other_collectors
    ) -> None:
        v: int = memory.available_swap_bytes
        wrapper.labels(
            hostname=node.hostname,
            hostuuid=node.hostuuid,
            ip=node.ip
        ).set(v)

    @staticmethod
    def get_metric__ssh_disk_utilization(
            wrapper: Gauge,
            node: gdict,
            *,
            disk: DiskCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(disk.utilization_of_mountpoint):
            wrapper.labels(
                hostname=node.hostname,
                hostuuid=node.hostuuid,
                ip=node.ip,
                device=disk.filesystems[i],
                fstype=disk.filesystem_types[i],
                mountpoint=disk.mountpoints[i]
            ).set(v)

    @staticmethod
    def get_metric__ssh_disk_used_bytes(
            wrapper: Gauge,
            node: gdict,
            *,
            disk: DiskCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(disk.used_bytes_of_mountpoint):
            wrapper.labels(
                hostname=node.hostname,
                hostuuid=node.hostuuid,
                ip=node.ip,
                device=disk.filesystems[i],
                fstype=disk.filesystem_types[i],
                mountpoint=disk.mountpoints[i]
            ).set(v)

    @staticmethod
    def get_metric__ssh_disk_available_bytes(
            wrapper: Gauge,
            node: gdict,
            *,
            disk: DiskCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(disk.available_bytes_of_mountpoint):
            wrapper.labels(
                hostname=node.hostname,
                hostuuid=node.hostuuid,
                ip=node.ip,
                device=disk.filesystems[i],
                fstype=disk.filesystem_types[i],
                mountpoint=disk.mountpoints[i]
            ).set(v)

    @staticmethod
    def get_metric__ssh_disk_read_bytes_total(
            wrapper: Gauge,
            node: gdict,
            *,
            disk: DiskCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(disk.read_bytes_total):
            wrapper.labels(
                hostname=node.hostname,
                hostuuid=node.hostuuid,
                ip=node.ip,
                device=disk.disks[i]
            ).set(v)

    @staticmethod
    def get_metric__ssh_disk_write_bytes_total(
            wrapper: Gauge,
            node: gdict,
            *,
            disk: DiskCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(disk.write_bytes_total):
            wrapper.labels(
                hostname=node.hostname,
                hostuuid=node.hostuuid,
                ip=node.ip,
                device=disk.disks[i]
            ).set(v)

    @staticmethod
    def get_metric__ssh_network_receive_bytes_total(
            wrapper: Gauge,
            node: gdict,
            *,
            network: NetworkCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(network.receive_bytes_total):
            wrapper.labels(
                hostname=node.hostname,
                hostuuid=node.hostuuid,
                ip=node.ip,
                device=network.interfaces[i]
            ).set(v)

    @staticmethod
    def get_metric__ssh_network_transmit_bytes_total(
            wrapper: Gauge,
            node: gdict,
            *,
            network: NetworkCollector,
            **other_collectors
    ) -> None:
        for i, v in enumerate(network.transmit_bytes_total):
            wrapper.labels(
                hostname=node.hostname,
                hostuuid=node.hostuuid,
                ip=node.ip,
                device=network.interfaces[i]
            ).set(v)


if __name__ == '__main__':
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
    '''

    server: socket.socket = god.server
    http_timeout: int = server.timeout
    next_collect_time = 0

    rlist = [server]

    while True:
        for read_event in select.select(rlist, [], [])[0]:
            if read_event is server:
                fd, addr = server.accept()
                rlist.append(fd)
                glog.debug(f'establish connection, remote address: {addr}')
                continue
            try:
                read_event.settimeout(http_timeout)
                body: bytes = read_event.recv(8192)
                if body[:21] == b'GET /metrics HTTP/1.1':
                    start = time.monotonic()
                    if start > next_collect_time:
                        metrics_response: bytes = b''.join(MetricsHandler.get())
                    response: bytes = metrics_response
                    end = time.monotonic()
                    glog.info(f'GET /metrics 200 (runtime:{end - start:.2f}s)')
                    next_collect_time = end + .01
                else:
                    response: bytes = index
                    glog.info('GET /<any> 200')
                read_event.sendall(b'HTTP/1.1 200 OK\r\n\r\n' + response)
            except Exception as ee:
                glog.error(f'server error: {repr(ee)}, clients: {rlist[1:]}')
            finally:
                rlist.remove(read_event)
                read_event.close()
