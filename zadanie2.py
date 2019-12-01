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


def print_menu():
    print('\n-------------------------------')
    print('MENU:\n')
    print('  1    HTTP')
    print('  2    HTTPS')
    print('  3    TELNET')
    print('  4    SSH')
    print('  5    FTP control')
    print('  6    FTP data')
    print('  7    TFTP')
    print('  8    ICMP')
    print('  9    ARP')
    print('-------------------------------\n')


# nacitanie suboru, ktory chceme analyzovat
file_name = input("File name without directory and extension: ")
# file_name = 'eth-4'

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

tftp_comms = comm_finder.find_tftp_comms(tftp_obj.copy(), p_val_by_name)

icmp_comms = comm_finder.find_icmp_comms(icmp_obj.copy(), p_name_by_val, p_val_by_name)

while True:
    print_menu()
    choice = int(input("Vyberte z moznosti: "))
    if choice == 1:
        vsetky_ramce.print_tcp_comms(http_complete, http_incomplete)
    elif choice == 2:
        vsetky_ramce.print_tcp_comms(https_complete, https_incomplete)
    elif choice == 3:
        vsetky_ramce.print_tcp_comms(telnet_complete, telnet_incomplete)
    elif choice == 4:
        vsetky_ramce.print_tcp_comms(ssh_complete, ssh_incomplete)
    elif choice == 5:
        vsetky_ramce.print_tcp_comms(ftp_c_complete, ftp_c_incomplete)
    elif choice == 6:
        vsetky_ramce.print_tcp_comms(ftp_d_complete, ftp_d_incomplete)
    elif choice == 7:
        vsetky_ramce.print_tftp_comms(tftp_comms)
    elif choice == 8:
        vsetky_ramce.print_icmp_comms(icmp_comms, p_name_by_val)
    elif choice == 9:
        print('ARP communication not implemented')
    else:
        print('Bad input, try again')


print()
