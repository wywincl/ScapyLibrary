#!/usr/bin/env python
# -*- coding: utf8 -*-
import os
from Scapy2Library.utils import *
from keywordgroup import KeywordGroup


try:
    from robot.api import logger
except ImportError:
    logger = None


class _ScapyKeywords(KeywordGroup):
    def __init__(self):
        self._keywords_version = '1.0.0'
        self._count = 0

    # Public

    def send_igmp_query(self, src_mac, vlan_id, src_ip):
        """
        函数简介：创建IGMP通用查询报文，并且发送该报文

        给定参数源MAC地址，VLAN ID, 源IP地址，构造IGMP Query报文

        核心实现是使用关键字`Send Igmp` 来构造igmp query报文并发送

        Examples:
        | Send Igmp Query  | 00:00:00:00:01:10 |  1111  |  192.168.0.233  |

        在Scapy2Library v1.0.0 实现

        """
        _dst_mac = "01:00:5E:00:00:01"
        _dst_ip = "224.0.0.1"
        _proto_type = 0x11
        _mcast_addr = "0.0.0.0"
        _max_rsp_time = 10
        _ttl = 1
        _validate = 1
        self._info("send igmp query packet")
        self._send_igmp(dst_mac=_dst_mac, src_mac=src_mac, vlan_id=int(vlan_id), dst_ip=_dst_ip, src_ip=src_ip,
                        proto_type=_proto_type, mcast_addr=_mcast_addr, ttl=_ttl, max_rsp_time=_max_rsp_time,
                        validate=_validate)

    def send_igmp_report(self, dst_mac, src_mac, vlan_id, dst_ip, src_ip):
        """
        函数简介：创建IGMP V2报告报文，并且发送该报文

        给定参数目的MAC地址，源MAC地址，VLAN ID, 目的IP地址, 源IP地址，构造IGMP Report报文

        核心实现是使用关键字`Send Igmp` 来构造igmp report报文并发送

        Examples:
        | Send Igmp Report  | 01:00:5E:01:01:01 | 00:00:00:00:01:10 |  1111  |  226.1.1.1  | 192.168.0.233  |

        在Scapy2Library v1.0.0 实现
        """
        _proto_type = 0x16
        _mcast_addr = dst_ip
        _max_rsp_time = 0
        _ttl = 1
        _validate = 1
        self._info("send igmp report packet")
        self._send_igmp(dst_mac=dst_mac, src_mac=src_mac, vlan_id=int(vlan_id), dst_ip=dst_ip, src_ip=src_ip,
                        proto_type=_proto_type, mcast_addr=_mcast_addr, ttl=_ttl, max_rsp_time=_max_rsp_time,
                        validate=_validate)

    def send_igmp_leave(self, src_mac, vlan_id, src_ip, mcast_addr):
        """
        函数简介：创建IGMP V2离开报文，并且发送该报文

        给定参数源MAC地址，VLAN ID, 源IP地址，组地址，构造IGMP Leave报文

        核心实现是使用关键字`Send Igmp` 来构造igmp leave报文并发送

        Examples:
        | Send Igmp Leave  | 00:00:00:00:01:10 |  1111  |  192.168.0.233  |  226.1.1.1  |

        在Scapy2Library v1.0.0 实现
        """
        _dst_mac = "01:00:5E:00:00:02"
        _dst_ip = "224.0.0.2"
        _proto_type = 0x17
        _mcast_addr = mcast_addr
        _max_rsp_time = 0
        _ttl = 1
        _validate = 1
        self._info("send igmp leave packet")
        self._send_igmp(dst_mac=_dst_mac, src_mac=src_mac, vlan_id=int(vlan_id), dst_ip=_dst_ip, src_ip=src_ip,
                        proto_type=_proto_type, mcast_addr=_mcast_addr, ttl=_ttl, max_rsp_time=_max_rsp_time,
                        validate=_validate)

    def send_igmp(self, dst_mac, src_mac, vlan_id, dst_ip, src_ip, proto_type, mcast_addr, ttl, max_rsp_time,
                  validate=1):
        """
        函数简介：创建IGMP报文，并且发送该报文

        在Scapy2Library v1.0.0 实现
        """
        self._send_igmp(dst_mac=dst_mac, src_mac=src_mac, vlan_id=int(vlan_id), dst_ip=dst_ip, src_ip=src_ip,
                        proto_type=int(proto_type), mcast_addr=mcast_addr, ttl=int(ttl), max_rsp_time=int(max_rsp_time),
                        validate=int(validate))

    # -----------------------------------------------------------------------------------------------------------------#

    def send_ip(self, dst_mac, src_mac, vlan_id, dst_ip, src_ip, ttl, data):
        """
        函数简介：创建IPv4数据包，并且发送该数据包

        在Scapy2Library v1.0.0 实现
        """
        self._send_ip(dst_mac=dst_mac, src_mac=src_mac, vlan_id=int(vlan_id), dst_ip=dst_ip, src_ip=src_ip,
                      ttl=int(ttl), data=data)

    def send_udp(self, dst_mac, src_mac, vlan_id, dst_ip, src_ip, ttl, sport, dport, data):
        """
        函数简介：创建UDP数据包，并且发送该数据包

        给定参数目的MAC地址，源MAC地址，VLAN ID，目的IP地址，源IP地址，TTL值， 源端口号，目的端口号，以及负载来构造UDP数据包

        核心实现是利用关键字`Send Ip`来构造UDP报文并发送

        Examples:
        | Send Udp  | 00:00:00:00:01:10 | 00:00:01:00:01:10 | 1111 | 192.168.1.233 | 192.168.0.111 | 11 | 9998 |
        | ...       |  9999             | 0101010101        |

        在Scapy2Library v1.0.0 实现
        """
        udp = generate_udp_pkt(sport=int(sport), dport=int(dport))
        data = udp / data
        self._send_ip(dst_mac=dst_mac, src_mac=src_mac, vlan_id=int(vlan_id), dst_ip=dst_ip, src_ip=src_ip,
                      ttl=int(ttl), data=data)

    def send_tcp(self, dst_mac, src_mac, vlan_id, dst_ip, src_ip, ttl, sport, dport, data):
        """
        函数简介：创建TCP数据包，并且发送该数据包

        给定参数目的MAC地址，源MAC地址，VLAN ID，目的IP地址，源IP地址，TTL值， 源端口号，目的端口号，以及负载来构造TCP数据包

        核心实现是利用关键字`Send Ip`来构造TCP报文并发送

        Examples:
        | Send Tcp  | 00:00:00:00:01:10 | 00:00:01:00:01:10 | 1111 | 192.168.1.233 | 192.168.0.111 | 11 | 8000 |
        | ...       |       80          | 0101010101        |

        在Scapy2Library v1.0.0 实现
        """
        tcp = generate_tcp_pkt(sport=int(sport), dport=int(dport))
        data = tcp / data
        self._send_ip(dst_mac=dst_mac, src_mac=src_mac, vlan_id=int(vlan_id), dst_ip=dst_ip, src_ip=src_ip,
                      ttl=int(ttl), data=data)

    def send_packet_from_pcap(self, packet_file_path):
        """
        函数简介：从文件中导入数据包，并发送.

        参数：packet_file_path: pcap格式的数据包文件

        Examples:
        | Send Packet From Pcap | E:/capture_2.cap  |

        在Scapy2Library v1.0.0 实现
        """
        if not os.path.isfile(packet_file_path):
            raise AssertionError("File '%s' does not exist" % packet_file_path)

        try:
            self._info("send packet from '%s'. " % packet_file_path)
            self._send_packet(packet_path=packet_file_path)
        except Exception:
            raise AssertionError("ERROR, send packet from pcap file failed!")

    def capture_packet(self, r_filter, count, timeout, save_path):
        """
        函数简介：根据规则，抓取数据包，并保存到指定路径.

        给定过滤规则r_filter, 在超时时间timeout内，抓取指定个数count的数据包，并保存到文件中

        Information:

        过滤规则请参考scapy官方文档

        Examples:
        | Capture Packet  | tcp |  1  |  10  |  E:/capture_1.cap  |

        在Scapy2Library v1.0.0 实现
        """
        ret = self._capture_packet(r_filter=r_filter, count=int(count), timeout=int(timeout), save_path=save_path)
        if ret is not True:
            raise AssertionError("ERROR, capture packet failed!")
        return ret

    def _send_igmp(self, dst_mac, src_mac, vlan_id, dst_ip, src_ip, proto_type, mcast_addr, ttl, max_rsp_time,
                   validate=1):
        self._count += 1
        try:
            send_igmp_pkt(dst_mac=dst_mac, src_mac=src_mac, vlan_id=vlan_id, dst_ip=dst_ip, src_ip=src_ip,
                          proto_type=proto_type, mcast_addr=mcast_addr, ttl=ttl, max_rsp_time=max_rsp_time,
                          validate=validate)
        except Exception:
            raise AssertionError("ERROR, send igmp packet failed!")

    def _send_ip(self, dst_mac, src_mac, vlan_id, dst_ip, src_ip, ttl, data):
        self._count += 1
        try:
            send_ip_pkt(dst_mac=dst_mac, src_mac=src_mac, vlan_id=vlan_id, dst_ip=dst_ip, src_ip=src_ip,
                        ttl=ttl, data=data)
        except Exception:
            raise AssertionError("ERROR, send ip packet failed!")

    def _capture_packet(self, r_filter, count, timeout, save_path):
        self._count += 1
        try:
            return capture_packet(r_filter=r_filter, count=count, timeout=timeout, save_path=save_path)
        except Exception:
            raise AssertionError("ERROR, capture packet failed!")

    def _send_packet(self, packet_path):
        self._count += 1
        try:
            send_packet(packet_file_path=packet_path)
        except Exception:
            raise


# -------------------------------------------------- Test Modules  --------------------------------------------------#


def test_send_igmp():
    _src_mac = '00:00:01:02:03:04'
    _dst_mac = '01:00:5E:00:00:01'
    _vlan_id = 1110
    _src_ip = '192.168.0.233'
    _dst_ip = '224.0.0.1'
    _igmp_type = 0x11
    _multicast_address = '0.0.0.0'
    _ttl = 2
    _max_rsp_time = 10
    _p = _ScapyKeywords()
    _p.send_igmp(dst_mac=_dst_mac, src_mac=_src_mac, vlan_id=_vlan_id, dst_ip=_dst_ip, src_ip=_src_ip,
                 proto_type=_igmp_type, mcast_addr=_multicast_address, ttl=_ttl, max_rsp_time=_max_rsp_time)


def main():
    p = _ScapyKeywords()
    # p.send_igmp_query(src_mac='00:00:00:00:01:10', vlan_id=1113, src_ip='192.168.0.233')
    # p.send_igmp_report(dst_mac='01:00:5E:01:01:03', src_mac='00:00:00:00:01:11', vlan_id=1113,
    # dst_ip='226.1.1.3', src_ip='192.168.0.233')
    # p.send_igmp_leave(src_mac='00:00:00:00:01:10', vlan_id=1113, src_ip='192.168.0.233', mcast_addr='226.1.1.3')
    p.send_udp(dst_mac='01:00:5E:01:01:03', src_mac='00:00:00:00:01:11', vlan_id=0,
               dst_ip='226.1.1.3', src_ip='192.168.0.233', ttl=11, sport=9999, dport=9994, data='\0' * 18)
    # p.send_tcp(dst_mac='00:00:5E:01:01:03', src_mac='00:00:00:00:01:11', vlan_id=1113,
    # dst_ip='10.10.10.3', src_ip='192.168.0.233', ttl=11, sport=8000, dport=80, data='\0'*18)
    # p.send_ip(dst_mac='00:00:5E:01:01:03', src_mac='00:00:00:00:01:11', vlan_id=1113,
    #          dst_ip='10.10.10.3', src_ip='192.168.0.233', ttl=11, data='\0\1'*12)
    # p.capture_packet("tcp", count=1, timeout=10, save_path='E:/capture_1.cap')
    # p.send_packet_from_pcap("E:/capture_2.cap")


if __name__ == "__main__":
    main()
