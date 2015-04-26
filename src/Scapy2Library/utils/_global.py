from scapy.all import UDP, TCP


def generate_udp_pkt(sport, dport):
    return UDP(sport=sport, dport=dport)


def generate_tcp_pkt(sport, dport):
    return TCP(sport=sport, dport=dport)


if __name__ == "__main__":
    udp = generate_udp_pkt(sport=56, dport=54)
    udp.show()
    tcp = generate_tcp_pkt(sport=8000, dport=80)
    tcp.show()
