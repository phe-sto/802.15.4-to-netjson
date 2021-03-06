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
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from scapy.all import rdpcap
from scapy.config import conf
from scapy.layers.dot15d4 import Dot15d4Data, Dot15d4Cmd

logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)

MIN_BROADCAST_ADDRESS = 0xfff8


@dataclass
class Node:
    """
    Node as described in netJSON specification.
    """
    id: int
    pan_id: int

    @property
    def __dict__(self):
        """
        A Python object to smoothly create a netJSON using vars or __dict__ and
        json.dumps.
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

    @property
    def __dict__(self):
        """
        A Python object to smoothly create a netJSON using vars or __dict__ and
        json.dumps.
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


def parse_packet_and_log(packet, packet_number, layer, nodes, links, zigbee):
    """
    Parse the packet using scapy and a defined layer.
    Only extract source and destination, short address and pan ID.
    Verify tha packet is in the interval pass as argument.
    It excludes all types of broadcast communication are excluded if the zigbee
    boolean is True for a clearer view. See the note containing an extract of
    the Zigbee specification 3.6.5 paragraph listing the different address.

       :parameter packet: Packet scapy object to parse.
       :parameter packet_number: Number of the packet in the capture.
       :parameter layer: Layer to parse.
       :parameter nodes: Set of nodes.
       :parameter links: Set of links.
       :parameter zigbee: Boolean to treat the packet as part of Zigbee network.

    .. note::

       3.6.5 Broadcast Communication

          - 0xffff: All devices in PAN
          - 0xfffe: Reserved
          - 0xfffd: macRxOnWhenIdle = TRUE
          - 0xfffc: All routers and coordinator
          - 0xfffb: Low power routers only
          - 0xfff8 - 0xfffa: Reserved
    """
    try:
        if zigbee is True and packet[layer].dest_addr > MIN_BROADCAST_ADDRESS:
            # Skip Zigbee broadcast communication for a clearer view
            pass
        else:
            logging.debug(
                'Frame %d from %#x to %#x on PAN %#x' % (
                    packet_number,
                    packet[layer].src_addr,
                    packet[layer].dest_addr,
                    packet[layer].dest_panid
                )
            )
            # Add source node to the set
            src_node = Node(
                packet[layer].src_addr,
                packet[layer].dest_panid
            )
            nodes.add(src_node)
            # Add destination node to the set
            dest_node = Node(
                packet[layer].dest_addr,
                packet[layer].dest_panid
            )
            nodes.add(dest_node)
            # Add link between source and destination
            links.add(
                Link(src_node.graph_id,
                     dest_node.graph_id)
            )
    except IndexError as error:
        logging.debug(
            """Could not parse 802.15.4 frame %d containing %s
            \tThe following error wa raised %s""" % (
                packet_number, packet, error
            )
        )


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
    """
    # Links and nodes are sets has they are supposed to be unique
    nodes = set()
    links = set()
    # Configure scapy for Zigbee
    if zigbee is True:
        conf.dot15d4_protocol = "zigbee"
    short_parse_packet_and_log = partial(parse_packet_and_log, zigbee=zigbee)
    # Iterate over the PCAP
    for packet_number, packet in enumerate(rdpcap(pcap)):
        # Only analyse the packets in between the desired interval
        if (
                min_packet <= packet_number and max_packet is None) or (
                min_packet <= packet_number <= max_packet
        ):
            # 802.15.4 data layer, meaning all the Zigbee and more
            short_parse_packet_and_log(
                packet=packet,
                packet_number=packet_number,
                layer=Dot15d4Data,
                nodes=nodes,
                links=links
            )
            # 802.15.4 command layer
            short_parse_packet_and_log(
                packet=packet,
                packet_number=packet_number,
                layer=Dot15d4Cmd,
                nodes=nodes,
                links=links
            )

        # After the last packet to parse, leave the loop.
        elif max_packet is not None and packet_number >= max_packet:
            break
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
    # Fill two sets of nodes and links to formerly fill the netJSON
    nodes, links = parse_pcap(args.infile, args.zigbee, args.min, args.max)
    # Write the output netJSON file using a hardcoded filename to be used by
    # other modules
    with open('netjson.json', 'w') as netjson_file:
        netjson_file.write(
            json.dumps({
                'type': 'NetworkGraph',
                'label': '802.15.4 Communication',
                'protocol': '802.15.4',
                'version': None,
                'metric': 'hop',
                # Cast both sets below as tuple to be serialized in JSON
                'nodes': tuple(vars(node) for node in nodes),
                'links': tuple(vars(link) for link in links)
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
