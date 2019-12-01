

def same_communication(p1, p2):
    ips = [p1.src_ip, p1.dest_ip]
    ports = [p1.src_port, p1.dest_port]
    if p2.src_ip in ips and p2.dest_ip in ips and p2.src_port in ports and p2.dest_port in ports:
        return True
    else:
        return False


def same_icmp_communication(p1, p2):
    ips = [p1.src_ip, p1.dest_ip]
    seq_n = p1.icmp_seq_n
    if p2.src_ip in ips and p2.dest_ip in ips and p2.icmp_seq_n == seq_n:
        return True
    else:
        return False


def get_flag_byte_from_packet(p):
    return p.packet[94:96].decode('utf-8')


def contains_flag(all_flags, requested_flags):
    for fl in requested_flags:
        if fl == 'syn':
            if int(all_flags, 16) & (1 << 1) != 0:
                return True
        elif fl == 'rst':
            if int(all_flags, 16) & (1 << 2) != 0:
                return True
        elif fl == 'fin':
            if int(all_flags, 16) & 1 != 0:
                return True
    return False


def is_complete(communication):
    flag_syn = get_flag_byte_from_packet(communication[0])
    flag_fin = get_flag_byte_from_packet(communication[-2])
    flag_rst = get_flag_byte_from_packet(communication[-1])
    if contains_flag(flag_syn, ['syn']) and (contains_flag(flag_fin, ['fin']) or contains_flag(flag_rst, ['rst'])):
        return True
    else:
        return False


def find_comms(packets):
    incomplete_communications = []
    complete_communications = []
    communication = []
    packet = None
    get_packet = 1
    i = 0

    while packets:
        if get_packet:
            packet = packets.pop(0)
            i -= 1
            get_packet = 0
            communication.append(packet)
        else:
            p = packets[i]
            if same_communication(packet, p):
                communication.append(p)
                packets.pop(i)
                i -= 1

        i += 1
        if i == len(packets):
            get_packet = 1
            i = 0
            if is_complete(communication):
                complete_communications.append(communication.copy())
            else:
                incomplete_communications.append(communication.copy())
            communication.clear()
    return next(iter(complete_communications or []), None), next(iter(incomplete_communications or []), None)


def find_tftp_comms(tftp_datagrams, p_val_by_name):
    communication = []
    ips = []
    port = 0
    packet = None
    get_packet = 1
    i = 0

    while tftp_datagrams:
        if get_packet:
            packet = tftp_datagrams.pop(0)
            i -= 1
            get_packet = 0
            communication.append(packet)
        else:
            p = tftp_datagrams[i]

            ips.append(packet.src_ip)
            ips.append(packet.dest_ip)
            if packet.src_port != p_val_by_name['TFTP']:
                port = packet.src_port
            elif packet.dest_port != p_val_by_name['TFTP']:
                port = packet.dest_port

            if p.src_ip in ips and p.dest_ip in ips:
                if p.src_port == port or p.dest_port == port:
                    communication.append(p)
                    tftp_datagrams.pop(i)
                    i -= 1
        i += 1
        if i == len(tftp_datagrams):
            return communication
    return None


def find_icmp_comms(packets, p_name_by_val, p_val_by_name):
    communications = []
    communication = []
    packet = None
    get_packet = 1
    i = 0

    while packets:
        if get_packet:
            packet = packets.pop(0)
            i -= 1
            get_packet = 0
            communication.append(packet)
        else:
            p = packets[i]
            if same_icmp_communication(packet, p):
                communication.append(p)
                packets.pop(i)
                i -= 1

        i += 1
        if i == len(packets):
            get_packet = 1
            i = 0
            communications.append(communication.copy())
            communication.clear()
    return communications
