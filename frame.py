class Frame:
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
        self.icmp_type = None
        self.icmp_seq_n = None

    def get_number(self):
        return self.number

    def set_number(self, number):
        self.number = number

    def get_length(self):
        return self.length

    def set_length(self, length):
        self.length = length
        
    def get_dest_mac(self):
        return self.dest_mac

    def set_dest_mac(self, dest_mac):
        self.dest_mac = dest_mac

    def get_src_mac(self):
        return self.src_mac

    def set_src_mac(self, src_mac):
        self.src_mac = src_mac

    def get_frame_type(self):
        return self.frame_type

    def set_frame_type(self, frame_type):
        self.frame_type = frame_type
