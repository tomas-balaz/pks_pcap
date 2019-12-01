from pcapfile import savefile
import os
import numpy as np

import protocols
import vypis_vsetkych_ramcov as vsetky_ramce
import comm_finder


def file_path(filename):
    dirname = os.path.dirname(__file__)
    filepath = os.path.join(dirname, f'vzorky_pcap_na_analyzu\\{filename}.pcap')
    return filepath


def get_packets_from_pcap_file(pcap_file):
    test_cap = open(file_path(pcap_file), 'rb')
    cap_file = savefile.load_savefile(test_cap)
    return cap_file.packets


# nacitanie suboru, ktory chceme analyzovat
# file_name = input("File name without directory and extension: ")
file_name = 'trace_ip_nad_20_B'

# ziskanie paketov z suboru pomocou kniznice
packets = get_packets_from_pcap_file(file_name)

# ziskanie slovnikov nazvov portov a ich hodnot
p_name_by_val, p_val_by_name = protocols.get_protocol_dicts()

# vypis vsetkych ramcov + statistika (ulohy 1. - 3.)
ether_obj = vsetky_ramce.vypis_ramcov_hex(packets, p_name_by_val, p_val_by_name)
arp_obj, ipv4_obj = vsetky_ramce.parse_by_l3(ether_obj, p_name_by_val, p_val_by_name)
tcp_obj, udp_obj, icmp_obj = vsetky_ramce.parse_ipv4_by_l4(ipv4_obj, p_name_by_val, p_val_by_name)

http_obj, https_obj, telnet_obj, ssh_obj, ftp_c_obj, ftp_d_obj = \
    vsetky_ramce.parse_tcp_by_app(tcp_obj, p_name_by_val, p_val_by_name)

udp_obj = vsetky_ramce.fill_udp_ports(udp_obj)
tftp_obj = vsetky_ramce.tftp_filter(udp_obj, p_val_by_name)

icmp_obj = vsetky_ramce.fill_icmp_type_and_seq_n(icmp_obj, p_val_by_name)

http_complete, http_incomplete = comm_finder.find_comms(http_obj.copy())
https_complete, https_incomplete = comm_finder.find_comms(https_obj.copy())
telnet_complete, telnet_incomplete = comm_finder.find_comms(telnet_obj.copy())
ssh_complete, ssh_incomplete = comm_finder.find_comms(ssh_obj.copy())
ftp_c_complete, ftp_c_incomplete = comm_finder.find_comms(ftp_c_obj.copy())
ftp_d_complete, ftp_d_incomplete = comm_finder.find_comms(ftp_d_obj.copy())

tftp_communication = comm_finder.find_tftp_comms(tftp_obj.copy(), p_val_by_name)

icmp_comms = comm_finder.find_icmp_comms(icmp_obj.copy(), p_name_by_val, p_val_by_name)
print()
