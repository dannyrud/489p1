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
        
        
        self.ack_recieved = False
        self.finack_recieved = False
        self.lock = threading.Lock()
        self.ack_cv = threading.Condition(self.lock)
        self.finack_cv = threading.Condition(self.lock)
        # Needed to differentiate between FINACK segments
        self.fin_sent = False

    def _start_sniffer(self):
        t = threading.Thread(target=self._sniffer)
        t.start()

    def _filter(self, pkt):
        if (IP in pkt) and (TCP in pkt):  # capture only IP and TCP packets
            return True
        return False

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
        # Case 1: Handle Data
        if len(pkt[TCP].payload) > 0:
            # If not a duplicate increase next ack
            if pkt[TCP].seq == self.next_ack:
                self.next_ack += len(pkt[TCP].payload)
            # Send ack even if packet is a duplicate
            ack_packet = self.ip / TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.next_seq, ack=self.next_ack)
            send(ack_packet)
        # Case 2: Handle ACK's
        elif pkt[TCP].flags.A and not pkt[TCP].flags.F:
            if pkt[TCP].ack == self.next_seq:
                # We have recieved our ack, notify main sending thread
                with self.ack_cv:
                    self.ack_recieved = True
                    self.ack_cv.notify()
        # Case 3: Handle FIN/FINACK
        elif pkt[TCP].flags.A and pkt[TCP].flags.F:
            if self.fin_sent:
                # We must ack this finack packet (we started the closing)
            else:
                # This is the initial fin from the server, we must ACK it
            
            

    def connect(self):
        """TODO(2): Implement TCP's three-way-handshake protocol for establishing a connection. Here are some
           pointers on what you need to do:
           1. Handle SYN -> SYNACK -> ACK packets.
           2. Make sure to update the `sequence` and `acknowledgement` numbers correctly, along with the 
              TCP `flags`.
        """
        # Create SYN Packet
        syn_packet = self.ip / TCP(sport=self.sport, dport=self.dport, flags="S", seq=self.next_seq)
        self.next_seq += 1
        synack_packet = None
        # Retry sending SYN packet indefinitley until SYN ACK is recieved
        while True:
            synack_packet = sr1(syn_packet,timeout = self.timeout)
            if (synack_packet != None) and (TCP in synack_packet) and (synack_packet[TCP].flags.S and synack_packet[TCP].flags.A) and synack_packet[TCP].ack == self.next_seq:
                # synack packet received
                self.next_ack = synack_packet[TCP].seq + 1
                ack_packet = self.ip / TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.next_seq, ack=self.next_ack)
                send(ack_packet)
                break
            else:
                # Not the correct packet, continue
                continue
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
        # Send just the fin packet, sniffer thread will recieve finack and respond to it
        fin_packet = self.ip / TCP(sport=self.sport, dport=self.dport, flags="FA", seq=self.next_seq, ack= self.next_ack)
        self.next_seq += 1
        with self.finack_cv:
            self.fin_sent = True
            while not self.finack_recieved:
                send(fin_packet)
                self.finack_cv.wait(timeout= self.timeout)
                
        # If we reached here, sniffer thread recieved the finack and sent the ack, connection is closed
        # Resetting ack_recieved is now pointless
        
        self.connected = False
        print('Connection Closed')

    def send(self, payload):
        """TODO(4): Create and send TCP's data packets for sharing the given message (or file):
           1. Make sure to update the `sequence` and `acknowledgement` numbers correctly, along with the 
              TCP `flags`.
        """
        # Create packet
        data_packet = self.ip / TCP(sport=self.sport, dport=self.dport, flags="PA", seq=self.next_seq, ack=self.next_ack) / payload
        # This is the number we expect for the ack packet from the server
        self.next_seq += len(payload)
        with self.ack_cv:
            while not self.ack_recieved:
                send(data_packet)
                self.ack_cv.wait(timeout= self.timeout)
                # Wait till timeout seconds and if the ack is still not recieved send it again
            self.ack_recieved = False 
        
        


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
