from pcapfile import savefile
import os
import numpy as np

import protocols
import vypis_vsetkych_ramcov as vsetky_ramce


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
file_name = 'eth-2'

# ziskanie paketov z suboru pomocou kniznice
packets = get_packets_from_pcap_file(file_name)

# ziskanie slovnikov nazvov portov a ich hodnot
p_name_by_val, p_val_by_name = protocols.get_protocol_dicts()

# vypis vsetkych ramcov + statistika (ulohy 1. - 3.)
ether_obj = vsetky_ramce.vypis_ramcov_hex(packets, p_name_by_val, p_val_by_name)
arp_obj, ipv4_obj = vsetky_ramce.parse_by_l3(ether_obj, p_name_by_val, p_val_by_name)
tcp_obj, udp_obj, icmp_obj = vsetky_ramce.parse_ipv4_by_l4(ipv4_obj, p_name_by_val, p_val_by_name)
print()
