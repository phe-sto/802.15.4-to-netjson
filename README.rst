
802.15.4 to netJSON
===================

A tool to visualize 802.15.4 PCAP file turning it to netJSON, can be useful for
Zigbee, Thread. It uses the two layers including a destination and source short
address, Command and Data layers.
Visualization thank to netJSONgraph.
This Python script runs into Python 3.7 or newer as it uses `dataclass`.

.. image:: doc/network-example.png

netJSON
-------

NetJSON is a data interchange format based on JSON designed to ease the
development of software tools for computer networks.

NetJSON defines several types of JSON objects and the manner in which
they are combined to represent a network: configuration of devices,
monitoring data, network topology and routing information.

Described in their website https://netjson.org/

This format comes with many tools to visualize the data. Here is used
netJSONgraph https://github.com/openwisp/netjsongraph.js for the html
visualization.

Scapy
-----

Scapy is the library used to parse the input PCAP.

Scapy is a powerful interactive packet manipulation program. It is able
to forge or decode packets of a wide number of protocols, send them on
the wire, capture them, match requests and replies, and much more. It
can easily handle most classical tasks like scanning, tracerouting,
probing, unit tests, attacks or network discovery (it can replace hping,
85% of nmap, arpspoof, arp-sk, arping, tcpdump, tshark, p0f, etc.).

It is the unique dependency of this library.

install the dependency
----------------------

In your shell or console:

    ``python -m pip install -r requirements.txt``

Usage
-----

Just need the PCAP filepath as input, can be piped. A ``--zigbee`` token
can be added to get read of the broadcast communication for a clearer
view. As per the specification all the nodes above 0xfff7 are reserved for
broadcast communication and will be removed. The ``--serve`` token serve the
netJSONgraph view of the netJSON opened in the browser at http://localhost:8005/:

    ``python 802dot15dot4-to-netjson.py <PCAP filepath> --zigbee --serve``

To just create the netJSON file remove the --serve token:

    ``python 802dot15dot4-to-netjson.py <PCAP filepath>``

Optional argument ``--min`` and ``--max`` specify the first and last packet to
analyze.

Start analysis frame 1000:

    ``python 802dot15dot4-to-netjson.py <PCAP filepath> --min=1000``

From beginning till frame 1000:

    ``python 802dot15dot4-to-netjson.py <PCAP filepath> --max=1000``

From frame 1000 to 2000:

    ``python 802dot15dot4-to-netjson.py <PCAP filepath> --min=1000 --max=2000``
