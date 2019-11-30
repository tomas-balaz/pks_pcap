class MFrame:
    def __init__(self, number, length, frame_type, dest_mac, src_mac, l3_prot, dest_ip, src_ip, l4_prot, packet):
        self.number = number
        self.length = length
        self.frame_type = frame_type
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.l3_prot = l3_prot
        self.dest_ip = dest_ip
        self.src_ip = src_ip
        self.l4_prot = l4_prot
        self.packet = packet
        self.dest_port = None
        self.src_port = None