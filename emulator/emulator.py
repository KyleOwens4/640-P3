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

    def set_src_ip(self, ip):
        self.src_ip = ip
        self.int_src_ip = self.convert_ip_to_int(ip)

    def set_dest_ip(self, ip):
        self.dest_ip = ip
        self.int_dest_ip = self.convert_ip_to_int(ip)

    def convert_int_to_ip(self, int_ip):
        return socket.inet_ntoa(struct.pack('!L', int_ip))

    def convert_ip_to_int(self, ip_string):
        return struct.unpack("!L", socket.inet_aton(ip_string))[0]

    def repack(self):
        inner_packet = struct.pack("!cII", self.type.encode('ascii'),
                                   socket.htonl(self.seq_num), 0 if self.data is None else len(self.data))
        if self.data is not None:
            inner_packet += self.data.encode()

        outer_header = struct.pack("!BIHIHII", 1, self.int_src_ip, self.src_port, self.int_dest_ip, self.dest_port, self.ttl, len(inner_packet))

        self.packet = outer_header + inner_packet

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
        self.seq_num = 0
        self.unacked_packets = {}

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

    def send_linkstates(self):
        neighbors = self.topology.get_neighbors(self.root_node)
        data = ' '.join(str(neighbor) + ',1' for neighbor in neighbors)
        self.seq_num += 1

        for key in list(self.unacked_packets.keys()):
            packet, sent_time, retries = self.unacked_packets[key]
            time_elapsed = int(time.time() * 1000) - sent_time

            if time_elapsed >= 1000:
                if retries == 5:
                    del self.unacked_packets[key]
                else:
                    self.unacked_packets[key] = (packet, int(time.time() * 1000), retries + 1)
                    self.send_packet(packet)

        for node in neighbors:
            packet = self.build_lsp(self.root_node, node, data)
            packet.next_hop_address = node.full_address
            self.unacked_packets[(node, self.seq_num)] = (packet, int(time.time() * 1000), 0)
            self.send_packet(packet)

    def build_lsp(self, src_node, dest_node, data):
        src_ip = self.convert_ip_to_int(src_node.ip_address)
        src_port = src_node.port
        dest_ip = self.convert_ip_to_int(dest_node.ip_address)
        dest_port = dest_node.port

        inner_packet = self.build_inner_packet('L', self.seq_num, data)
        return self.build_full_packet(src_ip, src_port, dest_ip, dest_port, 100, inner_packet)

    def handle_trace(self, packet):
        if packet.ttl == 0:
            packet.next_hop_address = (packet.src_ip, packet.src_port)
            packet.ttl = 64
            packet.set_src_ip(self.listen_address[0])
            packet.src_port = self.listen_address[1]

            self.send_packet(packet)
        else:
            packet.ttl -= 1
            packet.next_hop_address = self.forwarding_table.get_next_hop(Node(packet.dest_ip, packet.dest_port))
            self.send_packet(packet)

    def send_ack(self, packet_to_ack):
        inner_packet = self.build_inner_packet('A', packet_to_ack.seq_num, None)

        packet = self.build_full_packet(self.convert_ip_to_int(self.listen_address[0]), self.listen_address[1],
                                        packet_to_ack.int_src_ip, packet_to_ack.src_port, 1, inner_packet)

        packet.next_hop_address = packet_to_ack.from_address
        self.send_packet(packet)

    def build_inner_packet(self, pack_type, seq_num, data):
        inner_packet = struct.pack("!cII", pack_type.encode('ascii'), socket.htonl(seq_num), 0 if data is None else len(data))
        if data is not None:
            inner_packet += data.encode()

        return inner_packet

    def build_full_packet(self, src_ip, src_port, dest_ip, dest_port, ttl, inner_packet):
        outer_header = struct.pack("!BIHIHII", 1, src_ip, src_port, dest_ip, dest_port, ttl, len(inner_packet))

        return Packet(outer_header + inner_packet, self.listen_address)

    def check_neighbor_health(self):
        for node in self.topology.get_neighbors(self.root_node):
            if not self.forwarding_table.validate_node_health(node):
                self.send_linkstates()

    def refresh_neighbor_health(self, packet):
        node = Node(packet.src_ip, packet.src_port)
        if self.topology.contains_node(node) and node in self.topology.get_neighbors(self.root_node):
            self.forwarding_table.refresh_node_heatlh(node)
        else:
            self.forwarding_table.add_node(node)
            self.send_linkstates()

    def handle_lsp(self, packet):
        self.send_ack(packet)
        is_new = self.forwarding_table.update_lsp(packet)

        if is_new and packet.ttl > 0:
            packet.ttl -= 1
            neighbors = self.topology.get_neighbors(self.root_node)

            for neighbor in neighbors:
                if neighbor.full_address != packet.from_address:
                    packet.next_hop_address = neighbor.full_address
                    self.send_packet(packet)

    def handle_ack(self, packet):
        node = Node(packet.src_ip, packet.src_port)
        key = (node, packet.seq_num)

        if key in self.unacked_packets:
            del self.unacked_packets[key]

    def convert_ip_to_int(self, ip_string):
        return struct.unpack("!L", socket.inet_aton(ip_string))[0]

    def forward_packet(self, packet):
        if packet.ttl > 0:
            print('forwarding packet')
            packet.ttl -= 1
            packet.next_hop_address = self.forwarding_table.get_next_hop(Node(packet.dest_ip, packet.dest_port))
            print(packet.src_port)
            self.send_packet(packet)

    def send_packet(self, packet):
        packet.repack()
        self.socket.sendto(packet.packet, packet.next_hop_address)

    def await_packet(self):
        try:
            full_packet, from_address = self.socket.recvfrom(5500)
            return Packet(full_packet, from_address)
        except Exception as e:
            pass


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
        self.root_node = None

    def add_node_details(self, node_details, update_packet = None):
        root_node = node_details[0]
        node_neighbors = node_details[1:]

        self.node_table[root_node] = (node_neighbors, update_packet)

    def contains_node(self, node):
        if node in self.node_table:
            return True

        return False

    def get_root_node(self, address):
        for node in self.node_table.keys():
            if node.full_address == address:
                self.root_node = node
                return node

    def get_all_nodes(self):
        return self.node_table.keys()

    def get_neighbors(self, node):
        return [] if node not in self.node_table else self.node_table[node][0]

    def add_neighbor(self, node, neighbor_node, update_packet=None):
        if neighbor_node not in self.node_table:
            self.node_table[neighbor_node] = ([node], update_packet)

        if node not in self.node_table[neighbor_node][0]:
            self.node_table[neighbor_node][0].append(node)

        if neighbor_node not in self.node_table[node][0]:
            self.node_table[node][0].append(neighbor_node)

    def remove_node(self, node, neighbor_node):
        self.node_table[node][0].remove(neighbor_node)
        self.node_table[neighbor_node][0].remove(node)
        if not self.node_reachable(node):
            del self.node_table[neighbor_node]

    def update_node(self, packet, node, neighbors):
        if node not in self.node_table:
            self.node_table[node] = (neighbors, packet)
            for neighbor in neighbors:
                if neighbor not in self.node_table:
                    self.node_table[neighbor] = ([node], packet)
            return True, True

        if self.node_table[node][1] is None or self.node_table[node][1].seq_num < packet.seq_num:

            if set(self.node_table[node][0]) != set(neighbors):
                self.node_table[node] = (neighbors, packet)
                for neighbor in neighbors:
                    if neighbor not in self.node_table:
                        self.node_table[neighbor] = ([node], packet)
                return True, True
            else:
                self.node_table[node] = (self.node_table[node][0], packet)
                return False, True

        return False, False

    def remove_unreachable(self):
        remove = []
        for node in self.node_table.keys():
            if not self.node_reachable(node):
                remove.append(node)

        for node in remove:
            del self.node_table[node]

    def node_reachable(self, node):
        if node == self.root_node:
            return True

        for key in self.node_table.keys():
            if node in self.node_table[key][0]:
                return True

        return False

    def print_network_topology(self):
        print("====== Current Topology ======")
        for key in sorted(self.node_table.keys()):
            row_text = str(key)
            for neighbor in sorted(self.node_table[key][0]):
                row_text += " " + str(neighbor)

            print(row_text)
        print()


class ForwardingTable:
    def __init__(self, topology, root_address):
        self.forwarding_table = {}
        self.topology = topology
        self.root_address = root_address
        self.buildForwardTable()

    def buildForwardTable(self):
        self.forwarding_table = {}
        self.topology.remove_unreachable()

        all_nodes = self.topology.get_all_nodes()
        visited_nodes = []

        root_node = self.topology.get_root_node(self.root_address)
        root_neighbors = self.topology.get_neighbors(root_node)
        next_hop_node = None

        cost_queue = PriorityQueue()
        cost_queue.put((0, root_node))

        cur_cost = 0
        while set(visited_nodes) != set(all_nodes) and not cost_queue.empty() and cur_cost <= len(all_nodes):
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

    def validate_node_health(self, node):
        entry = self.forwarding_table[node]
        time_rem = int(time.time() * 1000) - entry[2]

        if time_rem >= 700:
            self.topology.remove_node(self.topology.get_root_node(self.root_address), node)
            self.buildForwardTable()
            return False

        return True

    def refresh_node_heatlh(self, node):
        entry = self.forwarding_table[node]
        entry[2] = int(time.time() * 1000)

    def add_node(self, node):
        self.topology.add_neighbor(self.topology.get_root_node(self.root_address), node)
        self.buildForwardTable()

    def update_lsp(self, packet):
        from_node = Node(packet.src_ip, packet.src_port)
        augmented_neighbors = packet.data.split(' ')
        neighbors = []

        for augmented_neighbor in augmented_neighbors:
            ip, port, cost = augmented_neighbor.split(',')
            port = int(port)
            neighbors.append(Node(ip, port))

        table_refresh, is_new = self.topology.update_node(packet, from_node, neighbors)

        if table_refresh:
            self.buildForwardTable()

        return is_new

    def get_next_hop(self, node):
        return self.forwarding_table[node][0].full_address

    def print_forwarding_table(self):
        print("====== Current Forwarding Table ======")
        for key in sorted(self.forwarding_table.keys()):
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
    last_hello_time = int(time.time() * 1000)
    last_lsp_time = int(time.time() * 1000)
    emulator_socket.send_hellos()
    while True:
        last_hello_time, last_lsp_time = createroutes(last_hello_time, last_lsp_time, emulator_socket)
        try:
            incoming_packet = emulator_socket.await_packet()
            forwardpacket(emulator_socket, incoming_packet)

        except BlockingIOError as e:
            print(str(e))
            pass


def createroutes(last_hello_time, last_lsp_time, emulator_socket):
    current_time = int(time.time() * 1000)

    emulator_socket.check_neighbor_health()
    if current_time - last_hello_time >= 500:
        emulator_socket.send_hellos()
        last_hello_time = int(time.time() * 1000)

    if current_time - last_lsp_time >= 1000:
        emulator_socket.send_linkstates()
        last_lsp_time = int(time.time() * 1000)

    return last_hello_time, last_lsp_time


def forwardpacket(emulator_socket, incoming_packet):
    if incoming_packet is None:
        return

    if incoming_packet.type == 'H':
        emulator_socket.refresh_neighbor_health(incoming_packet)
        return

    if incoming_packet.type == 'L':
        emulator_socket.handle_lsp(incoming_packet)
        return

    if incoming_packet.type == 'T':
        emulator_socket.handle_trace(incoming_packet)
        return

    if incoming_packet.type == 'A':
        emulator_socket.handle_ack(incoming_packet)
        return

    emulator_socket.forward_packet(incoming_packet)


if __name__ == '__main__':
    start_emulator()
