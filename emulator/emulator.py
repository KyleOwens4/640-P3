import argparse
import socket
import struct
import time
from queue import PriorityQueue


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
        print('==============INCOMING PACKET===============')
        print('Priority         ' + str(self.priority))
        print('Source Name      ' + str(self.src_hostname))
        print('Source IP        ' + str(self.src_ip))
        print('Source Port      ' + str(self.src_port))
        print('Destination Name ' + str(self.dest_hostname))
        print('Destination IP   ' + str(self.dest_ip))
        print('Destination Port ' + str(self.dest_port))
        print('Outer Packet Len ' + str(self.outer_length))
        print('Type             ' + str(self.type))
        print('Sequence Number  ' + str(self.seq_num))
        print('Inner Packet Len ' + str(self.length))
        print('Data:            ' + str(self.data[:4]))
        print('From Addr        ' + str(self.from_address[0]))
        print('From Port        ' + str(self.from_address[1]))
        print('============================================')
        print('')


class EmulatorSocket:
    def __init__(self, listening_port_num, topology):
        self.listen_address = (socket.gethostbyname(socket.gethostname()), listening_port_num)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(self.listen_address)
        self.socket.settimeout(0)
        self.topology = topology
        self.root_node = self.topology.get_root_node(self.listen_address)
        self.forwarding_table = ForwardingTable(self.topology, self.listen_address)

    def send_hellos(self):
        for node in self.topology.get_neighbors(self.root_node):
            packet = self.build_hello(self.root_node, node)
            packet.next_hop_address = node.full_address
            self.send_packet(packet)

    def build_hello(self, src_node, dest_node):
        src_ip = self.convert_ip_to_int(src_node.ip_address)
        src_port = src_node.port
        dest_ip = self.convert_ip_to_int(dest_node.ip_address)
        dest_port = dest_node.port

        inner_packet = self.build_inner_packet('H', 0, None)
        return self.build_full_packet(src_ip, src_port, dest_ip, dest_port, 100, inner_packet)

    def build_inner_packet(self, pack_type, seq_num, data):
        inner_packet = struct.pack("!cII", pack_type.encode('ascii'), seq_num, 0 if data is None else len(data))
        if data is not None:
            inner_packet += data.encode()

        return inner_packet

    def build_full_packet(self, src_ip, src_port, dest_ip, dest_port, ttl, inner_packet):
        outer_header = struct.pack("!BIHIHII", 1, src_ip, src_port, dest_ip, dest_port, ttl, len(inner_packet))

        return Packet(outer_header + inner_packet, self.listen_address)

    def check_neighbor_health(self):
        for node in self.topology.get_neighbors(self.root_node):
            needs_removal = not self.forwarding_table.is_healthy(node)

    def refresh_neighbor_health(self, packet):
        node = Node(packet.src_ip, packet.src_port)
        self.forwarding_table.refresh_node_heatlh(node)

    def convert_ip_to_int(self, ip_string):
        return struct.unpack("!L", socket.inet_aton(ip_string))[0]

    def send_packet(self, packet):
        self.socket.sendto(packet.packet, packet.next_hop_address)

    def await_packet(self):
        full_packet, from_address = self.socket.recvfrom(5500)

        return Packet(full_packet, from_address)


class Node:
    def __init__(self, ip_address, port):
        self.ip_address = ip_address
        self.port = int(port)

        self.full_address = (ip_address, self.port)

    def __str__(self):
        return self.ip_address + "," + str(self.port)

    def __lt__(self, other):
        return self.full_address < other.full_address

    def __eq__(self, other):
        return self.full_address == other.full_address

    def __hash__(self):
        return hash(self.full_address)


class NetworkTopology:
    def __init__(self):
        self.node_table = {}

    def add_node_details(self, node_details):
        root_node = node_details[0]
        node_neighbors = node_details[1:]

        self.node_table[root_node] = node_neighbors

    def get_root_node(self, address):
        for node in self.node_table.keys():
            if node.full_address == address:
                return node

    def get_all_nodes(self):
        return self.node_table.keys()

    def get_neighbors(self, node):
        return self.node_table[node]

    def print_network_topology(self):
        print("====== Current Topology ======")
        for key in self.node_table.keys():
            row_text = str(key)
            for neighbor in self.node_table[key]:
                row_text += " " + str(neighbor)

            print(row_text)
        print()


class ForwardingTable:
    def __init__(self, topology, root_address):
        self.forwarding_table = {}
        self.topology = topology
        self.root_address = root_address
        self.build()

    def build(self):
        all_nodes = self.topology.get_all_nodes()
        visited_nodes = []

        root_node = self.topology.get_root_node(self.root_address)
        root_neighbors = self.topology.get_neighbors(root_node)
        next_hop_node = None

        cost_queue = PriorityQueue()
        cost_queue.put((0, root_node))

        while set(visited_nodes) != set(all_nodes) and not cost_queue.empty():
            cur_cost, cur_node = cost_queue.get()
            visited_nodes.append(cur_node)

            # keep track of the root neighbor we last went through so we can use it as the next hop
            if cur_node in root_neighbors:
                next_hop_node = cur_node

            for node in self.topology.get_neighbors(cur_node):
                cost_queue.put((cur_cost + 1, node))

                self.update_forwarding_table(node, cur_cost + 1, root_node, next_hop_node)

        self.topology.print_network_topology()
        self.print_forwarding_table()

    def update_forwarding_table(self, node, cost_to_node, root_node, next_hop_node):
        if node == root_node:
            return

        next_hop_node = node if next_hop_node is None else next_hop_node

        if node not in self.forwarding_table:
            self.forwarding_table[node] = [next_hop_node, cost_to_node, int(time.time() * 1000)]
        elif self.forwarding_table[node][1] > cost_to_node:
            self.forwarding_table[node] = [next_hop_node, cost_to_node, int(time.time() * 1000)]

    def get_entry(self, node):
        return self.forwarding_table[node]

    def is_healthy(self, node):
        entry = self.forwarding_table[node]
        time_rem = int(time.time() * 1000) - entry[2]

        if time_rem >= 2000:
            print("deleting entry")
            return False

        return True

    def refresh_node_heatlh(self, node):
        entry = self.forwarding_table[node]
        entry[2] = int(time.time() * 1000)

    def print_forwarding_table(self):
        print("====== Current Forwarding Table ======")
        for key in self.forwarding_table.keys():
            row_text = str(key)
            row_text += " " + str(self.forwarding_table[key][0])

            print(row_text)
        print()


def start_emulator():
    args = get_args()

    topology = readtopology(args.f)
    emulator_socket = EmulatorSocket(args.p, topology)

    listen_for_packets(emulator_socket)


def get_args():
    parser = argparse.ArgumentParser(usage="emulator.py -p <port> -f <filename>")

    parser.add_argument('-p', choices=range(2050, 65536), type=int,
                        help='Port number emulator should wait for packets on', required=True)
    parser.add_argument('-f', type=str, help='Name of the file containing the static forwarding table', required=True)
    parser.add_argument('-d', type=bool, default=False, help='Debug mode', required=False)

    return parser.parse_args()


def readtopology(filename):
    topology = NetworkTopology()

    try:
        file = open(filename, 'r')
    except IOError as e:
        print(str(e))
        exit(-1)

    lines = file.readlines()
    for line in lines:
        row = []
        cols = line.split(' ')

        for col in cols:
            node_info = col.split(',')
            node = Node(node_info[0], node_info[1])

            row.append(node)

        topology.add_node_details(row)

    return topology


def listen_for_packets(emulator_socket):
    last_update_time = int(time.time() * 1000)

    while True:
        last_update_time = createroutes(last_update_time, emulator_socket)
        try:
            incoming_packet = emulator_socket.await_packet()

            if incoming_packet.type == 'H':
                emulator_socket.refresh_neighbor_health(incoming_packet)

            # forwardpacket(emulator_socket, incoming_packet)

        except BlockingIOError as e:
            pass


def createroutes(last_update_time, emulator_socket):
    current_time = int(time.time() * 1000)

    emulator_socket.check_neighbor_health()
    if current_time - last_update_time >= 1000:
        emulator_socket.send_hellos()
        return current_time

    return last_update_time


def forwardpacket(emulator_socket, incoming_packet):
    return


if __name__ == '__main__':
    start_emulator()