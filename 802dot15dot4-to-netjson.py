# -*- coding: utf-8 -*-
"""
=====================================================
Read a 802.15.4 protocol and turn into a netJSON file
=====================================================
802.15.4 protocols are native 802.15.4, 6LoWPAN, Zigbee, Thread, etc.

Scapy is used to read the PCAP.

netJSON format is described in `netJSON website <https://netjson.org/>`_.
"""

import argparse
import json
import logging
import sys
import webbrowser
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from scapy.all import rdpcap
from scapy.config import conf
from scapy.layers.dot15d4 import Dot15d4Data

logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)


@dataclass
class Node:
    """
    Node as described in netJSON specification.
    """
    id: int
    pan_id: int

    def __repr__(self):
        """
        Representation is a JSON to smoothly create a netJSON.
        """
        return {
            'id': self.graph_id,
            'label': 'Node {}, PAN {}'.format(
                hex(self.id), hex(self.pan_id)
            )
        }

    @property
    def graph_id(self):
        """
        Graph ID is considered as unique when it is the combination of a node ID
        and a PAN ID.
        """
        return abs(hash("%d%d" % (self.id, self.pan_id)))

    def __hash__(self):
        """
        Hash to be added to a set, equal to the graph ID as this one also define
        uniqueness of a device i.e. a node ID on a  PAN ID.
        """
        return self.graph_id


@dataclass
class Link:
    """
    Link as described in netJSON specification.
    """
    src_graph_id: int
    dst_graph_id: int

    def __repr__(self):
        """
        Representation is a JSON to smoothly create a netJSON.
        """
        return {
            'source': self.src_graph_id,
            'target': self.dst_graph_id,
            'cost': 1.0
        }

    def __hash__(self):
        """
        Hash to be added to a set.
        """
        return hash("%d%d" % (self.src_graph_id, self.dst_graph_id))


def parse_pcap(pcap: str, zigbee: bool, min_packet=0, max_packet=None):
    """
    Main function parsing the input pcap path. It parses the PCAP in between an
    interval of a defined number or the whole file.
    Use scapy to read this pcap.

       :parameter pcap: File object of the PCAP to parse, not the path.
       :parameter zigbee: Zigbee broadcast communication skip for a clearer
          view.
       :parameter min_packet: First packet of the PCAP to parse, default is 0.
       :parameter max_packet: Last packet of the PCAP file to parse, default is
          None, which mean no limit.

    It exclude all types of broadcast communication are exclude if the zigbee
    boolean is True for a clearer view. See the note containing an extract of
    the Zigbee specification 3.6.5 paragraph listing the different address.

    .. note::

       3.6.5 Broadcast Communication

          - 0xffff: All devices in PAN
          - 0xfffe: Reserved
          - 0xfffd: macRxOnWhenIdle = TRUE
          - 0xfffc: All routers and coordinator
          - 0xfffb: Low power routers only
          - 0xfff8 - 0xfffa: Reserved
    """
    # Links and nodes are sets has they are supposed to be unique
    nodes = set()
    links = set()
    # Configure scapy for Zigbee
    if zigbee is True:
        conf.dot15d4_protocol = "zigbee"
    # Iterate over the PCAP
    for packet_number, packet in enumerate(rdpcap(pcap)):
        try:
            # Only analyse the packets in between the desired interval
            if (
                    min_packet <= packet_number and max_packet is None) or (
                    min_packet <= packet_number <= max_packet
            ):
                if zigbee is True and packet[Dot15d4Data].dest_addr > 0xfff8:
                    # Skip Zigbee broadcast communication for a clearer view
                    continue
                else:
                    logging.debug(
                        'Frame %d from %#x to %#x on PAN %#x' % (
                            packet_number,
                            packet[Dot15d4Data].src_addr,
                            packet[Dot15d4Data].dest_addr,
                            packet[Dot15d4Data].dest_panid
                        )
                    )
                    # Add source node to the set
                    src_node = Node(
                        packet[Dot15d4Data].src_addr,
                        packet[Dot15d4Data].dest_panid
                    )
                    nodes.add(src_node)
                    # Add destination node to the set
                    dest_node = Node(
                        packet[Dot15d4Data].dest_addr,
                        packet[Dot15d4Data].dest_panid
                    )
                    nodes.add(dest_node)
                    # Add link between source and destination
                    links.add(
                        Link(src_node.graph_id,
                             dest_node.graph_id)
                    )
            # After the last packet to parse, leave the loop.
            elif max_packet is not None and packet_number >= max_packet:
                break
        except IndexError as error:
            logging.debug(
                """Could not parse 802.15.4 frame %d containing %s
                \tThe following error wa raised %s""" % (
                    packet_number, packet, error
                )
            )
    return nodes, links


if __name__ == "__main__":
    # Parse the arguments passed to the script
    parser = argparse.ArgumentParser(
        description='Turn a PCAP into the corresponding network.json'
    )
    parser.add_argument('infile',
                        type=str,
                        default=sys.stdin,
                        help='Input PCAP file')
    parser.add_argument('--min',
                        type=int,
                        default=0,
                        help='First packet of the PCAP to parse')
    parser.add_argument('--max',
                        type=int,
                        default=None,
                        help='Last packet of the PCAP file to parse')
    parser.add_argument('--zigbee',
                        action='store_true',
                        default=False,
                        help='Skip Zigbee broadcast communication')
    parser.add_argument('--serve',
                        action='store_true',
                        default=False,
                        help='Serve the web page using netJSONgraph and open it'
                        )
    args = parser.parse_args()
    nodes, links = parse_pcap(args.infile, args.zigbee, args.min, args.max)
    # Write the output JSON file using a hardcoded filename to be used by other
    # modules
    with open('netjson.json', 'w') as netjson_file:
        netjson_file.write(
            json.dumps({
                'type': 'NetworkGraph',
                'label': '802.15.4 Communication',
                'protocol': '802.15.4',
                'version': None,
                'metric': 'hop',
                'nodes': tuple(node.__repr__() for node in nodes),
                'links': tuple(link.__repr__() for link in links)
            })
        )
    # Serve and open a browser tab if the serve is True
    if args.serve is True:
        server_address = ("localhost", 8005)
        webbrowser.open("http://%s:%d" % server_address, new=2)
        SimpleHTTPRequestHandler.protocol_version = "HTTP/1.0"
        ServerClass = ThreadingHTTPServer
        with ServerClass(server_address, SimpleHTTPRequestHandler) as httpd:
            httpd.serve_forever()
