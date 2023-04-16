import argparse
import time
from datetime import datetime
import os
import socket
import struct


class OutgoingPacket:
    def __init__(self, priority, type, seq_num, data, source_address, destination_address):
        self.priority = priority
        self.type = type
        self.seq_num = seq_num
        self.length = len(data)
        self.data = data

        self.source_address = source_address
        self.destination_address = destination_address

        self.inner_header = struct.pack("!cII", type.encode('ascii'), socket.htonl(seq_num), self.length)
        self.data = data.encode()
        self.inner_packet = self.inner_header + self.data

        self.outer_header = self.create_outer_header()
        self.packet = self.outer_header + self.inner_packet
        self.sent_time = None
        self.attempts = 1

    def convert_ip_to_int(self, ip_string):
        return struct.unpack("!L", socket.inet_aton(ip_string))[0]

    def create_outer_header(self):
        int_src_ip = self.convert_ip_to_int(self.source_address[0])
        int_dest_ip = self.convert_ip_to_int(self.destination_address[0])
        src_port = self.source_address[1]
        dest_port = self.destination_address[1]

        return struct.pack("!BIHIHI", self.priority, int_src_ip, src_port, int_dest_ip, dest_port, 9 + self.length)

    def print_packet_info(self):
        pack_type = 'DATA' if self.type == 'D' else 'END'
        print(pack_type, "Packet")
        print('send time:      ', datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3])
        print('requester addr: ', self.destination_address[0] + ':' + str(self.destination_address[1]))
        print('sequence:       ', self.seq_num)
        print('length:         ', self.length)
        print('payload:        ', self.data.decode()[:4])
        print()

        return int(time.time() * 1000)


class IncomingPacket:
    def __init__(self, packet):
        outer_header = packet[:17]
        inner_header = packet[17:26]

        self.priority, self.src_ip, self.src_port, self.dest_ip, self.dest_port, self.outer_length = struct.unpack("!BIHIHI", outer_header)
        self.type, self.seq_num, self.length = struct.unpack("!cII", inner_header)

        self.type = str(self.type, 'UTF-8')
        self.seq_num = socket.ntohl(self.seq_num)

        self.data = packet[26:]
        self.data = self.data.decode() if len(self.data) > 0 else ''

        self.requester_address = (self.convert_int_to_ip(self.src_ip), self.src_port)

        if args.d:
            self.print_debug_info()

    def convert_int_to_ip(self, int_ip):
        return socket.inet_ntoa(struct.pack('!L', int_ip))

    def print_debug_info(self):
        print('==============INCOMING PACKET===============')
        print('Priority         ' + str(self.priority))
        print('Source IP        ' + str(self.src_ip))
        print('Source Port      ' + str(self.src_port))
        print('Destination IP   ' + str(self.dest_ip))
        print('Destination Port ' + str(self.dest_port))
        print('Outer Packet Len ' + str(self.outer_length))
        print('Type             ' + str(self.type))
        print('Sequence Number  ' + str(self.seq_num))
        print('Inner Packet Len ' + str(self.length))
        print('Data:            ' + str(self.data[:4]))
        print('Requester Addr   ' + str(self.requester_address[0]))
        print('Requester Port   ' + str(self.requester_address[1]))
        print('============================================')
        print('')


class SenderSocket:
    def __init__(self, listening_port_num, emulator_address):
        self.listen_address = (socket.gethostbyname(socket.gethostname()), listening_port_num)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(self.listen_address)

        self.emulator_address = emulator_address
        self.total_retransmissions = 0
        self.total_transmissions = 0

    def await_file_request(self):
        full_packet, requester_address = self.socket.recvfrom(5500)

        return IncomingPacket(full_packet)

    def await_ack(self):
        full_packet, requester_address = self.socket.recvfrom(5500)

        return IncomingPacket(full_packet)

    def send_packet(self, packet, transmission_type = 'I'):
        if (transmission_type == 'R'):
            self.total_retransmissions += 1

        self.total_transmissions += 1

        packet.sent_time = int(time.time() * 1000)
        self.socket.sendto(packet.packet, self.emulator_address)

    def settimeout(self, timeout):
        self.socket.settimeout(timeout)


def get_args():
    parser = argparse.ArgumentParser(usage="sender.py -p <port> -g <requester port> -r <rate> -q <seq_no> -l <length> "
                                           "-f <f_hostname> -e <f_port> -i <priority> -t <timeout>")

    parser.add_argument('-p', choices=range(2050, 65536), type=int,
                        help='Port number the sender should wait for requests on', required=True)
    parser.add_argument('-g', choices=range(2050, 65536), type=int,
                        help='Port the requestor is waiting on', required=True)
    parser.add_argument('-r', type=int, help='Packets to be sent per second', required=True)
    parser.add_argument('-q', type=int, help='Initial sequence of the packet exchange', required=True)
    parser.add_argument('-l', type=int, help='Length of packet payload in bytes', required=True)
    parser.add_argument('-f', type=str, help='Host name of the emulator', required=True)
    parser.add_argument('-e', choices=range(2050, 65536), type=int, help='the port of the emulator.', required=True)
    parser.add_argument('-i', choices=range(1, 4), type=int, help='Priority level to send packets at.', required=True)
    parser.add_argument('-t', type=int, help='Timeout for retransmission for lost packs in milliseconds', required=True)
    parser.add_argument('-d', type=bool, default=False, help='Debug mode', required=False)
    return parser.parse_args()


def await_acks(sent_packets, sender_socket, timeout, packet_rate):
    sender_socket.settimeout(0)

    while len(sent_packets) > 0:
        try:
            incoming_packet = sender_socket.await_ack()

            if incoming_packet.type == 'A' and incoming_packet.seq_num in sent_packets:
                del sent_packets[incoming_packet.seq_num]
        except BlockingIOError as e:
            pass

        for key in list(sent_packets.keys()):
            outgoing_packet = sent_packets[key]
            if int(time.time() * 1000) - outgoing_packet.sent_time > timeout:
                if outgoing_packet.attempts >= 6:
                    print("ERROR: Attempted sending packet with sequence number " + str(outgoing_packet.seq_num)
                          + " six total times without acknowledgement. Packet dropped.")
                    print("")
                    del sent_packets[key]
                else:
                    outgoing_packet.attempts += 1
                    send_time = int(time.time() * 1000)
                    sender_socket.send_packet(outgoing_packet, 'R')

                    while int(time.time() * 1000) < send_time + packet_rate:
                        pass


def send_file(sender_socket, request_packet, args):
    filename = request_packet.data
    window_len = request_packet.length

    try:
        file = open(filename, 'r')
    except IOError:
        print(f"{filename} does not exist in this folder")
        exit(-1)

    sent_packets = {}
    packet_rate = 1000 / args.r
    seq_num = 1
    rem_file_size = os.path.getsize(filename)

    while rem_file_size > 0:
        for window in range(window_len):
            if rem_file_size <= 0:
                break

            packet = OutgoingPacket(args.i, 'D', seq_num, file.read(args.l),
                                    sender_socket.listen_address, request_packet.requester_address)
            sent_packets[seq_num] = packet

            send_time = packet.print_packet_info()
            sender_socket.send_packet(packet)

            while int(time.time() * 1000) < send_time + packet_rate:
                pass

            seq_num += 1
            rem_file_size -= packet.length

        await_acks(sent_packets, sender_socket, args.t, packet_rate)

    packet = OutgoingPacket(args.i, 'E', seq_num, '', sender_socket.listen_address, request_packet.requester_address)
    packet.print_packet_info()
    sender_socket.send_packet(packet)

    print('Packet Loss Rate: ' + str((sender_socket.total_retransmissions / sender_socket.total_transmissions) * 100)
          + '% on ' + str(sender_socket.total_retransmissions) + ' retransmissions and '
          + str(sender_socket.total_transmissions) + ' total transmissions')


if __name__ == '__main__':
    args = get_args()

    emulator_address = (socket.gethostbyname(args.f), args.e)
    sender_socket = SenderSocket(args.p, emulator_address)
    request_packet = sender_socket.await_file_request()

    send_file(sender_socket, request_packet, args)



