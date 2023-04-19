import argparse
import socket
import struct


class Packet:
    def __init__(self, packet, from_address):
        outer_header = packet[:21]
        inner_header = packet[21:30]

        self.priority, self.int_src_ip, self.src_port, \
            self.int_dest_ip, self.dest_port, self.ttl, \
            self.outer_length = struct.unpack("!BIHIHII", outer_header)
        self.src_ip = self.convert_int_to_ip(self.int_src_ip)

        self.src_hostname = socket.gethostbyaddr(self.src_ip)[0].split('.')[0]
        self.dest_ip = self.convert_int_to_ip(self.int_dest_ip)
        self.dest_hostname = socket.gethostbyaddr(self.dest_ip)[0].split('.')[0]

        self.type, self.seq_num, self.length = struct.unpack("!cII", inner_header)
        self.type = str(self.type, 'UTF-8')
        self.seq_num = socket.ntohl(self.seq_num)

        self.data = packet[30:]
        self.data = self.data.decode() if len(self.data) > 0 else ''

        self.packet = packet
        self.from_address = from_address
        self.next_hop_address = None
        self.drop_prob = 0

    def convert_int_to_ip(self, int_ip):
        return socket.inet_ntoa(struct.pack('!L', int_ip))

    def print_debug_info(self):
        print('================== PACKET ==================')
        print('TTL              ' + str(self.ttl))
        print('Source Name      ' + str(self.src_hostname))
        print('Source IP        ' + str(self.src_ip))
        print('Source Port      ' + str(self.src_port))
        print('Destination Name ' + str(self.dest_hostname))
        print('Destination IP   ' + str(self.dest_ip))
        print('Destination Port ' + str(self.dest_port))
        print('============================================')
        print('')


class TraceSocket:
    def __init__(self, listening_port_num):
        self.listen_address = (socket.gethostbyname(socket.gethostname()), listening_port_num)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(self.listen_address)
        self.socket.settimeout(10)
        self.ttl = 0

    def trace_route(self, src_ip, src_port, dest_ip, dest_port, debug):
        rec_packet = None
        path = []
        while rec_packet is None or rec_packet.src_ip != rec_packet.dest_ip \
                or rec_packet.src_port != rec_packet.dest_port:
            outgoing_packet = self.build_full_packet(self.listen_address[0], self.listen_address[1],
                                                     dest_ip, dest_port, self.ttl,
                                                     self.build_inner_packet('T', 0, None))
            outgoing_packet.next_hop_address = (src_ip, src_port)

            if debug:
                outgoing_packet.print_debug_info()

            self.send_packet(outgoing_packet)

            rec_packet = self.await_packet()
            rec_packet.print_debug_info()
            self.ttl += 1

            path.append([self.ttl, rec_packet.src_ip, rec_packet.src_port])

        print_path(path)

    def build_inner_packet(self, pack_type, seq_num, data):
        inner_packet = struct.pack("!cII", pack_type.encode('ascii'), socket.htonl(seq_num),
                                   0 if data is None else len(data))
        if data is not None:
            inner_packet += data.encode()

        return inner_packet

    def build_full_packet(self, src_ip, src_port, dest_ip, dest_port, ttl, inner_packet):
        src_ip = self.convert_ip_to_int(src_ip)
        dest_ip = self.convert_ip_to_int(dest_ip)

        outer_header = struct.pack("!BIHIHII", 1, src_ip, src_port, dest_ip, dest_port, ttl, len(inner_packet))

        return Packet(outer_header + inner_packet, self.listen_address)

    def convert_ip_to_int(self, ip_string):
        return struct.unpack("!L", socket.inet_aton(ip_string))[0]

    def send_packet(self, packet):
        self.socket.sendto(packet.packet, packet.next_hop_address)

    def await_packet(self):
        try:
            full_packet, from_address = self.socket.recvfrom(5500)
            return Packet(full_packet, from_address)
        except Exception as e:
            pass


def run_trace():
    args = get_args()
    should_debug = False if args.f == 0 else True
    trace_socket = TraceSocket(args.a)
    trace_socket.trace_route(socket.gethostbyname(args.b), int(args.c),
                             socket.gethostbyname(args.d), int(args.e),
                             should_debug)


def get_args():
    parser = argparse.ArgumentParser(
        usage="python3 trace.py -a <routetrace port> -b < source hostname> -c <source port>"
              " -d <destination hostname> -e <destination port> -f <debug option>")
    parser.add_argument('-a', choices=range(2050, 65536), type=int,
                        help='Port number the tracer should wait for packets on', required=True)
    parser.add_argument('-b', type=str, help='Hostname of source node', required=True)
    parser.add_argument('-c', type=int, choices=range(2050, 65536), help='Port of the source node', required=True)
    parser.add_argument('-d', type=str, help='Hostname of the destination node', required=True)
    parser.add_argument('-e', type=int, choices=range(2050, 65536), help='Port of the destination node', required=True)
    parser.add_argument('-f', type=int, choices=range(2), help='1 for debug info', required=False)
    return parser.parse_args()


def print_path(path):
    print("Hop#,   (IP, Port)")
    for hop in path:
        print(hop[0], '\t\t(' + str(hop[1]) + ',' + str(hop[2]) + ')')


if __name__ == '__main__':
    run_trace()
