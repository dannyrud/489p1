#!/usr/bin/env python

############################################################################
##
##     This file is part of the University of Michigan (U-M) EECS 489.
##
##     U-M EECS 489 is free software: you can redistribute it and/or modify
##     it under the terms of the GNU General Public License as published by
##     the Free Software Foundation, either version 3 of the License, or
##     (at your option) any later version.
##
##     U-M EECS 489 is distributed in the hope that it will be useful,
##     but WITHOUT ANY WARRANTY; without even the implied warranty of
##     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##     GNU General Public License for more details.
##
##     You should have received a copy of the GNU General Public License
##     along with U-M EECS 489. If not, see <https://www.gnu.org/licenses/>.
##
#############################################################################

from scapy.all import *
from scapy.layers.inet import IP, TCP
import threading

SEND_PACKET_SIZE = 1000  # should be less than max packet size of 1500 bytes

# A client class for implementing TCP's three-way-handshake connection
# establishment and closing protocol, along with data transmission.


class Client3WH:

    def __init__(self, dip, dport):
        """Initializing variables"""
        self.dip = dip
        self.dport = dport
        # selecting a source port at random
        self.sport = random.randrange(0, 2**16)

        self.next_seq = 0                       # TCP's next sequence number
        self.next_ack = 0                       # TCP's next acknowledgement number

        self.ip = IP(dst=self.dip)              # IP header

        self.connected = False
        self.timeout = 3

    def _start_sniffer(self):
        t = threading.Thread(target=self._sniffer)
        t.start()

    def _filter(self, pkt):
        if not (IP in pkt and TCP in pkt):
            return False
        return True

    def _sniffer(self):
        while self.connected:
            sniff(prn=lambda x: self._handle_packet(
                x), lfilter=lambda x: self._filter(x), count=1, timeout=self.timeout)

    def _handle_packet(self, pkt):
        """TODO(1): Handle incoming packets from the server and acknowledge them accordingly. Here are some pointers on
           what you need to do:
           1. If the incoming packet has data (or payload), send an acknowledgement (TCP) packet with correct 
              `sequence` and `acknowledgement` numbers.
           2. If the incoming packet is a FIN (or FINACK) packet, send an appropriate acknowledgement or FINACK packet
              to the server with correct `sequence` and `acknowledgement` numbers.
        """
        # Only process packets from the server (not outgoing packets)
        if pkt[IP].src != self.dip:
            return
        if pkt[TCP].sport != self.dport:
            return
        if pkt[TCP].dport != self.sport:
            return
        tcp = pkt[TCP]
        
        # Case 1: Handle Data
        payload_len = len(tcp.payload)
        if payload_len > 0:
            if tcp.seq == self.next_ack:
                self.next_ack += payload_len

            ack = self.ip / TCP(
                sport=self.sport, dport=self.dport,
                flags="A", seq=self.next_seq, ack=self.next_ack
            )
            send(ack)
            return
        
        # Case 2: Handle FIN from server
        if tcp.flags.F:
            # Fin consumes one sequence number, we acknowlege the fin by increasing next ack
            if tcp.seq == self.next_ack:
                self.next_ack += 1
                
            ack = self.ip / TCP(
                sport=self.sport, dport=self.dport,
                flags="A", seq=self.next_seq, ack=self.next_ack
            )
            send(ack, verbose=False)
            return
            

    def connect(self):
        """TODO(2): Implement TCP's three-way-handshake protocol for establishing a connection. Here are some
           pointers on what you need to do:
           1. Handle SYN -> SYNACK -> ACK packets.
           2. Make sure to update the `sequence` and `acknowledgement` numbers correctly, along with the 
              TCP `flags`.
        """
        syn_packet = self.ip / TCP(
            sport=self.sport, dport=self.dport,
            flags="S", seq=self.next_seq
        )
        self.next_seq += 1
        
        bpf = (
            "tcp and "
            "src host %s and "
            "src port %d and "
            "dst port %d and "
            "tcp[13] & 0x12 == 0x12"
        ) % (self.dip, self.dport, self.sport)

        while True:
            synack = sr1(syn_packet, timeout=self.timeout, filter=bpf)
            if synack is None:
                continue
            if synack[TCP].ack != self.next_seq:
                continue
            # synack packet received    
            self.next_ack = synack[TCP].seq + 1
            ack_packet = self.ip / TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.next_seq, ack=self.next_ack)
            send(ack_packet)
            break
        self.connected = True
        self._start_sniffer()
        print('Connection Established')

    def close(self):
        """TODO(3): Implement TCP's three-way-handshake protocol for closing a connection. Here are some
           pointers on what you need to do:
           1. Handle FIN -> FINACK -> ACK packets.
           2. Make sure to update the `sequence` and `acknowledgement` numbers correctly, along with the 
              TCP `flags`.
        """
        fin_packet = self.ip / TCP(sport=self.sport, dport=self.dport, flags="FA", seq=self.next_seq, ack= self.next_ack)
        self.next_seq += 1
        def finack_filter(p):
            if not (IP in p and TCP in p):
                return False
            return (
                p[IP].src == self.dip and
                p[TCP].sport == self.dport and
                p[TCP].dport == self.sport and
                p[TCP].flags.A and p[TCP].ack == self.next_seq
            )
        bpf = (
            "tcp and "
            "src host %s and "
            "src port %d and "
            "dst port %d and "
            "tcp[13] & 0x10 != 0"
        ) % (self.dip, self.dport, self.sport)
        while True:
            finack = sr1(fin_packet, timeout=self.timeout, filter=bpf) 
            if finack is None:
                continue
            if finack[TCP].ack == self.next_seq:
                break
        # Server fin handled in other thread
        self.connected = False
        print('Connection Closed')

    def send(self, payload):
        """TODO(4): Create and send TCP's data packets for sharing the given message (or file):
           1. Make sure to update the `sequence` and `acknowledgement` numbers correctly, along with the 
              TCP `flags`.
        """
        data = self.ip / TCP(sport=self.sport, dport=self.dport, flags="PA", seq=self.next_seq, ack=self.next_ack) / payload

        self.next_seq += len(payload)
        bpf = (
            "tcp and "
            "src host %s and "
            "src port %d and "
            "dst port %d and "
            "tcp[13] & 0x10 != 0"
        ) % (self.dip, self.dport, self.sport)
        while True:
            ack = sr1(data, timeout=self.timeout, filter=bpf)
            if ack is None:
                continue
            if ack[TCP].ack == self.next_seq:
                break

def main():
    """Parse command-line arguments and call client function """
    if len(sys.argv) != 3:
        sys.exit(
            "Usage: ./client-3wh.py [Server IP] [Server Port] < [message]")
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])

    client = Client3WH(server_ip, server_port)
    client.connect()

    message = sys.stdin.read(SEND_PACKET_SIZE)
    while message:
        client.send(message)
        message = sys.stdin.read(SEND_PACKET_SIZE)

    client.close()


if __name__ == "__main__":
    main()
