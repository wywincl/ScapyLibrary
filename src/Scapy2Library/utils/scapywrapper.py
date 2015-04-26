from scapy.all import *
import scapy.contrib.igmp


def send_igmp_pkt(dst_mac, src_mac, vlan_id, dst_ip, src_ip, proto_type, mcast_addr, ttl, max_rsp_time, validate=1):
    """
    brief: create igmp packet and send it
    :param dst_mac:         destination MAC address
    :param src_mac:         source MAC address
    :param vlan_id:         a specific vlan id
    :param dst_ip:          destination IP address
    :param src_ip:          source IP address
    :param proto_type:      IGMP protocol type including 0x11, 0x16, 0x17, 0x12
    :param mcast_addr:      multicast group address
    :param ttl:             Time to Live
    :param max_rsp_time:    max response time for membership query
    :param validate:        set to 1 to examine the IGMP message to assure proper format,
                             it may change the field above you have just set. If you need to
                            create any format of the IGMP message, set it to 0.
    :return:
    """
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip, ttl=ttl)
    igmp_proto = scapy.contrib.igmp.IGMP(type=proto_type, gaddr=mcast_addr, mrtime=max_rsp_time)
    vlan_field = Dot1Q(vlan=vlan_id)

    if validate == 1:
        igmp_proto.igmpize(ip, eth)

    data = '\0'*14
    try:
        i_face = _get_interface_list()[0]
        print i_face
        sendp(eth/vlan_field/ip/igmp_proto/data, iface=i_face)
    except IndexError:
        print "*ERROR* Can not get the interface list!"


def send_ip_pkt(dst_mac, src_mac, vlan_id, dst_ip, src_ip, ttl, data):
    """
    brief:  create ip packet and send it
    :param dst_mac:         destination MAC address
    :param src_mac:         source MAC address
    :param vlan_id:         a specific vlan id
    :param dst_ip:          destination IP address
    :param src_ip:          source IP address
    :param ttl:             Time to Live
    :param data:            overload
    :return:
    """
    eth = Ether(dst=dst_mac, src=src_mac)
    ip = IP(src=src_ip, dst=dst_ip, ttl=ttl)
    vlan_field = Dot1Q(vlan=vlan_id)
    data = data
    try:
        i_face = _get_interface_list()[0]
        sendp(eth/vlan_field/ip/data, iface=i_face)
    except IndexError:
        print "*ERROR* Can not get the interface list!"


def send_packet(packet_file_path):
    """
    brief: send packet from a pcap file.
    :param packet_file_path:        the path of the pcap file
    :return:
    """
    try:
        p = rdpcap(packet_file_path)
        print _get_interface_list()
        i_face = _get_interface_list()[0]
        sendp(p, iface=i_face)
    except Exception:
        raise


def capture_packet(r_filter, count, timeout, save_path):
    """
    brief:  capture the packet with the filter rule and save it.
    :param r_filter:            filter rule
    :param count:               capture count
    :param timeout:             time to end
    :param save_path:           the captured file save path
    :return:
    """
    try:
        i_face = _get_interface_list()[0]
        p = sniff(iface=i_face, filter=r_filter, count=count, timeout=timeout)
    except Exception:
        raise AssertionError("ERROR, capture packet failed!")

    if p is not None:
        if len(p) != 0:
            try:
                wrpcap(save_path, p)
                return True
            except Exception:
                raise
        else:
            return False
    else:
        return False


def _get_interface_list():
    """
    brief: get the ethernet interface list
    :return:
    """
    return get_if_list()


# ----------------------------------------------------Test Modules----------------------------------------------------#

def _test_send_igmp_pkt():
    _src_mac = '00:00:01:02:03:04'
    _dst_mac = '01:00:5E:00:00:01'
    _vlan_id = 1110
    _src_ip = '192.168.0.233'
    _dst_ip = '224.0.0.1'
    _igmp_type = 0x11
    _multicast_address = '0.0.0.0'
    _ttl = 2
    _max_rsp_time = 10

    send_igmp_pkt(dst_mac=_dst_mac, src_mac=_src_mac, vlan_id=_vlan_id, dst_ip=_dst_ip, src_ip=_src_ip,
                  proto_type=_igmp_type, mcast_addr=_multicast_address, ttl=_ttl, max_rsp_time=_max_rsp_time)


if __name__ == "__main__":
    # send_ip_pkt(dst_mac='00:01:01:01:02:01', src_mac='00:00:91:02:03:05', vlan_id=1110,
    #            dst_ip='192.168.1.2', src_ip='192.168.0.1', ttl=1, data='\0\1'*512)
    # print capture_packet("tcp", count=1, timeout=10, save_path='E:/capture_1.cap')
    # for i in range(1, 2):
    #     _test_send_igmp_pkt()
    send_packet('E:/capture_2.cap')
