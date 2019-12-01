import numpy as np

import frame as f


def get_l2_protocol_from_packet(packet):
    third_field = packet.packet[24:28]
    if int(third_field, 16) > int("0x05dc", 0):
        return 'Ethernet II'
    else:
        # fourth_field = packet.packet[28:32]
        # if int(fourth_field, 16) == int("0xAAAA", 0):
        #     return '802.3 LLC + SNAP'
        # elif int(fourth_field, 16) == int("0xFFFF", 0):
        #     return '802.3 RAW'
        # else:
        #     return '802.3 LLC'
        return 'LLC'


def get_llc_l3_protocol_from_packet(packet, p_name_by_val):
    l3_protocol_code = packet.packet[28:30]
    l3_code_str = l3_protocol_code.decode('utf-8')
    l3_protocol_name = p_name_by_val.get(int(l3_code_str, 16))
    return l3_protocol_name


def get_l4_protocol_from_snap_packet(packet, p_name_by_val):
    l4_protocol_code = packet.packet[40:44]
    l4_code_str = l4_protocol_code.decode('utf-8')
    l4_protocol_name = p_name_by_val.get(int(l4_code_str, 16))
    return l4_protocol_name


def get_mac_addresses(packet):
    dst = packet.packet[0:12]
    src = packet.packet[12:24]
    return src, dst


def group_by_two(addr):
    addr_str = addr.decode('utf-8')
    i = 0
    grouped_str = ''
    for hexa_char in addr_str:
        if i % 2 == 0:
            grouped_str += ' '
        grouped_str += str(hexa_char)
        i += 1
    return grouped_str


def get_l3_protocol_from_packet(packet, p_name_by_val):
    l3_protocol_code = packet.packet[24:28]
    l3_code_str = l3_protocol_code.decode('utf-8')
    l3_protocol_name = p_name_by_val.get(int(l3_code_str, 16))
    # if l3_protocol_name is None:
    #     return f'konfiguračný súbor neobsahuje protokol s kódom {l3_code_str}'
    # else:
    return l3_protocol_name


def get_ip_addresses(packet):
    src_ip_bytes = packet.packet[52:60]
    dst_ip_bytes = packet.packet[60:68]
    return src_ip_bytes, dst_ip_bytes


def dec_ip_from_bytes(ip_addr_b):
    ip_addr_str = ip_addr_b.decode('utf-8')
    ip_dec = ''
    for i in range(0, 8, 2):
        ip_dec += str(int(ip_addr_str[i:(i+2)], 16))
        if i < 6:
            ip_dec += '.'
    return ip_dec


def get_l4_protocol_from_ip_packet(packet, p_name_by_val):
    l4_protocol_code = packet.packet[46:48]
    l4_code_str = l4_protocol_code.decode('utf-8')
    l4_protocol_name = p_name_by_val.get(int(l4_code_str, 16))
    # if l3_protocol_name is None:
    #     return f'konfiguračný súbor neobsahuje protokol s kódom {l3_code_str}'
    # else:
    return l4_protocol_name


def get_ports_from_segment(packet):
    source_port_bytes = packet.packet[68:72]
    destination_port_bytes = packet.packet[72:76]

    source_port = int(source_port_bytes.decode('utf-8'), 16)
    destination_port = int(destination_port_bytes.decode('utf-8'), 16)
    # source_port = source_port_bytes.decode('utf-8')
    # destination_port = destination_port_bytes.decode('utf-8')

    return source_port, destination_port


def get_app_layer_name_from_ports(src_p, dst_p, p_name_by_val):
    if p_name_by_val.get(src_p) is not None:
        return p_name_by_val[src_p]
    elif p_name_by_val.get(dst_p) is not None:
        return p_name_by_val[dst_p]
    else:
        return None


def categorize_by_port_number(packet, http, https, telnet, ssh, ftp_c, ftp_d, p_name_by_val):
    name = get_app_layer_name_from_ports(packet.src_port, packet.dest_port, p_name_by_val)
    packet.l5_prot = name
    if name == 'HTTP':
        http.append(packet)
    elif name == 'HTTPS':
        https.append(packet)
    elif name == 'TELNET':
        telnet.append(packet)
    elif name == 'SSH':
        ssh.append(packet)
    elif name == 'FTP-control':
        ftp_c.append(packet)
    elif name == 'FTP-data':
        ftp_d.append(packet)
    return http, https, telnet, ssh, ftp_c, ftp_d


def print_packet_bytes(packet):
    for i in range(0, len(packet.packet), 1):
        print(chr(packet.packet[i]), end="")
        if (i + 1) % 32 == 0 and (i + 1) != len(packet.packet):
            print()
        elif (i + 1) % 16 == 0:
            print('   ', end="")
        elif (i + 1) % 2 == 0:
            print(' ', end="")


def add_src_ip_to_list(src_ip, src_ip_addresses):
    # if src_ip not in src_ip_addresses:
    src_ip_addresses.append(src_ip)


def get_ip_with_most_sent_packets(addresses):
    values, counts = np.unique(addresses, return_counts=True)
    return values, values[list(counts).index(max(counts))], max(counts)


def ip_statistics(src_ips):
    ips, ip, pocet_paketov = get_ip_with_most_sent_packets(src_ips)
    print('IP adresy vysielajúcich uzlov:')
    for addr in ips:
        print(dec_ip_from_bytes(addr))
    print()
    print('Adresa uzla s najväčším počtom odoslaných paketov:')
    print(f'{dec_ip_from_bytes(ip)}\t{pocet_paketov} paketov')


def vypis_ramcov_hex(packets, p_name_by_val, p_val_by_name):
    src_ip_addresses = []
    frame_objects = []
    i = 0
    for p in packets:
        i += 1
        print(f'rámec {i}')
        dlzka_ramca = p.packet_len
        dlzka_po_mediu = (dlzka_ramca + 4) if (dlzka_ramca >= 60) else 64
        l2_protocol = get_l2_protocol_from_packet(p)
        src_mac, dst_mac = get_mac_addresses(p)
        l3_protocol = dst_ip = src_ip = l4_protocol = None

        print(f'dĺžka rámca poskytnutá pcap API - {dlzka_ramca} B')
        print(f'dĺžka rámca prenášaná po médiu - {dlzka_po_mediu} B')
        print(l2_protocol)
        print(f'Zdrojová MAC adresa:{group_by_two(src_mac)}')
        print(f'Cieľová MAC adresa:{group_by_two(dst_mac)}')

        if l2_protocol == 'Ethernet II':
            l3_protocol = get_l3_protocol_from_packet(p, p_name_by_val)
            if l3_protocol is not None:
                print(l3_protocol)
                if l3_protocol == 'IPv4':
                    src_ip, dst_ip = get_ip_addresses(p)
                    add_src_ip_to_list(src_ip, src_ip_addresses)
                    l4_protocol = get_l4_protocol_from_ip_packet(p, p_name_by_val)
                    print(f'zdrojová IP adresa: {dec_ip_from_bytes(src_ip)}')
                    print(f'cieľová IP adresa: {dec_ip_from_bytes(dst_ip)}')
                    print(l4_protocol)

            frame = f.Frame(i, dlzka_ramca, l2_protocol, dst_mac, src_mac, l3_protocol,
                            dst_ip, src_ip, l4_protocol, p.packet)
            frame_objects.append(frame)
        elif l2_protocol == 'LLC':
            l3_protocol = get_llc_l3_protocol_from_packet(p, p_name_by_val)
            if l3_protocol is not None:
                print(l3_protocol)
                if l3_protocol == 'SNAP':
                    l4_protocol = get_l4_protocol_from_snap_packet(p, p_name_by_val)
                    if l4_protocol is not None:
                        print(l4_protocol)
                    else:
                        print('Unknown Protocol')
        print_packet_bytes(p)
        print('\n')

    ip_statistics(src_ip_addresses)
    return frame_objects


def parse_by_l3(ether_obj, p_name_by_val, p_val_by_name):
    arps = []
    ipv4s = []
    for packet in ether_obj:
        if packet.l3_prot == 'IPv4':
            ipv4s.append(packet)
        elif packet.l3_prot == 'ARP':
            arps.append(packet)
    return arps, ipv4s


def parse_ipv4_by_l4(ipv4_obj, p_name_by_val, p_val_by_name):
    tcps = []
    udps = []
    icmps = []
    for packet in ipv4_obj:
        if packet.l4_prot is None:
            packet.l4_prot = get_l4_protocol_from_ip_packet(packet, p_name_by_val)
        if packet.l4_prot == 'TCP':
            tcps.append(packet)
        elif packet.l4_prot == 'UDP':
            udps.append(packet)
        elif packet.l4_prot == 'ICMP':
            icmps.append(packet)
    return tcps, udps, icmps


def parse_tcp_by_app(tcp_obj, p_name_by_val, p_val_by_name):
    http = []
    https = []
    telnet = []
    ssh = []
    ftp_c = []
    ftp_d = []

    for packet in tcp_obj:
        if packet.dest_port is None or packet.src_port is None:
            packet.src_port, packet.dest_port = get_ports_from_segment(packet)
        http, https, telnet, ssh, ftp_c, ftp_d = categorize_by_port_number(packet,
                            http, https, telnet, ssh, ftp_c, ftp_d, p_name_by_val)

    return http, https, telnet, ssh, ftp_c, ftp_d


def fill_udp_ports(udps):
    datagrams = []
    for datagram in udps:
        source_port_bytes = datagram.packet[68:72]
        destination_port_bytes = datagram.packet[72:76]

        datagram.dest_port = int(destination_port_bytes.decode('utf-8'), 16)
        datagram.src_port = int(source_port_bytes.decode('utf-8'), 16)
        datagrams.append(datagram)
    return datagrams


def tftp_filter(udp_obj, p_val_by_name):
    tftps = []
    for datagram in udp_obj:
        if datagram.dest_port == p_val_by_name['TFTP'] or datagram.dest_port > 1023:
            if datagram.src_port == p_val_by_name['TFTP'] or datagram.src_port > 1023:
                datagram.l5_prot = "TFTP"
                tftps.append(datagram)
    return tftps


def fill_icmp_type_and_seq_n(icmp_obj, p_val_by_name):
    for p in icmp_obj:
        ihl = int(p.packet[29:30].decode('utf-8'), 16)
        type_index = 8 * ihl + 28
        type_bytes = p.packet[type_index:(type_index + 2)]
        p.icmp_type = int(type_bytes.decode('utf-8'), 16)
        if p.icmp_type in [p_val_by_name['Echo'], p_val_by_name['EchoReply']]:
            seq_n_bytes = p.packet[(type_index + 12):(type_index + 16)]
            p.icmp_seq_n = int(seq_n_bytes.decode('utf-8'), 16)
    return icmp_obj


def print_packets(packets):
    for p in packets:
        print(f'rámec {p.number}')
        print(f'dĺžka rámca poskytnutá pcap API - {p.length} B')
        print(f'dĺžka rámca prenášaná po médiu - {(p.length + 4)} B')
        print("Ethernet II")
        print(f'Zdrojová MAC adresa:{group_by_two(p.src_mac)}')
        print(f'Cieľová MAC adresa:{group_by_two(p.dest_mac)}')
        print(p.l3_prot)
        print(f'zdrojová IP adresa: {dec_ip_from_bytes(p.src_ip)}')
        print(f'cieľová IP adresa: {dec_ip_from_bytes(p.dest_ip)}')
        print(p.l4_prot)
        print(p.l5_prot)
        print(f'zdrojový port: {p.src_port}')
        print(f'cieľový port: {p.dest_port}')
        print_packet_bytes(p)
        print('\n')


def print_icmp_packets(packets, p_name_by_val):
    for p in packets:
        print(f'rámec {p.number}')
        print(f'dĺžka rámca poskytnutá pcap API - {p.length} B')
        print(f'dĺžka rámca prenášaná po médiu - {(p.length + 4)} B')
        print("Ethernet II")
        print(f'Zdrojová MAC adresa:{group_by_two(p.src_mac)}')
        print(f'Cieľová MAC adresa:{group_by_two(p.dest_mac)}')
        print(p.l3_prot)
        print(f'zdrojová IP adresa: {dec_ip_from_bytes(p.src_ip)}')
        print(f'cieľová IP adresa: {dec_ip_from_bytes(p.dest_ip)}')
        print(p.l4_prot)
        print(p_name_by_val[p.icmp_type])
        print_packet_bytes(p)
        print('\n')


def print_tcp_comms(compl, incompl):

    print("Kompletná komunikácia:\n")
    if compl is None:
        print('nenachadza sa taka v subore')
    elif len(compl) > 20:
        print_packets(compl[:10])
        print('.\n.\n.\n')
        print_packets(compl[-10:])
    else:
        print_packets(compl)

    print("Nekompletná komunikácia:\n")
    if incompl is None:
        print('nenachadza sa taka v subore')
    elif len(incompl) > 20:
        print_packets(compl[:10])
        print('.\n.\n.\n')
        print_packets(compl[-10:])
    else:
        print_packets(incompl)


def print_tftp_comms(comms):
    if len(comms) == 0:
        print('TFTP sa nenachadza v subore')
        return
    i = 0
    for comm in comms:
        i += 1
        print(f'Komunikacia {i}:')
        print_packets(comm)


def print_icmp_comms(comms, p_name_by_val):
    if len(comms) == 0:
        print('ICMP sa nenachadza v subore')
        return
    i = 0
    for comm in comms:
        i += 1
        print(f'Komunikacia {i}:')
        print_icmp_packets(comm, p_name_by_val)
