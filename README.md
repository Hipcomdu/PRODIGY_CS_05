# PRODIGY_CS_05

A packet sniffer is an important educational tool to learn about network traffic and protocols. But it is important that these types of tools are used responsibly and ethically (only run them on devices you own or have explicit permission to capture/analyze network traffic). Note: Unsancionted packet sniffing can be illegal, and is disallowed by the terms of service for just about any ISP or destination website.

Here is a basic packet sniffer in Python using the `scapy` library. This script will take care of packet capture and extract some information the source IP address, destination IP addresses protocols usedFor example; it payload data.

### Prerequisites

1— Install the scapy library You can install it using pip:

```bash

pip install scapy

```

### Packet Sniffer Code

A Simple Packet Sniffer Script with `scapy`

```python

from scapy. Import all the sniffing stuff, IP,TCP,UDP,Raw.

def packet_callback(packet):

if IP in packet:

ip_src = packet[IP]. src

ip_dst = packet[IP]. dst

protocol = packet[IP]. proto

# Determine the protocol

if protocol == 6:

protocol_name = "TCP"

if TCP in packet:

payload = packet[TCP]. payload

elif protocol == 17:

protocol_name = "UDP"

if UDP in packet:

payload = packet[UDP]. payload

else:

protocol_name = "Other"

payload = None

# Display packet details

print(f"Source IP: {ip_src}")

print(f"Destination IP: {ip_dst}")

# print the protocol nameprint(f"Protocol: {protocol_name}")

if payload:

payload_data = payload. load. decode(errors='ignore')

print("Payload Data :", payload_data[:100], "...") #Fist 100 byte of pay load data as the only required assignment is to print Length, IP etc

print("-" * 50)

# Start sniffing

print ("Starting packet sniffer…...")

sniff(prn=packet_callback, store=False)

```

### Explanation

1. Import Libraries:

- `scapy. * all`: Offers the ability to capture and spoof packets, as well.
- 2. Packet Callback Function:

packet_callback(packet): This method deals with capturing every packet by using scapy.

IP Check: Checks whether the packet has an IP layer.

Notable Features :– IP Addresses: Captures source and destination ip addresses.

- Protocol: IP header field, which determines the protocol (TCP or UDP) used.

Payload — If there is payload data, it autosniffs the contents and shows with Payload. The Payload Data, which is the first 100 bytes of payload data;

3. Sniffing:

`sniff(prn=lambda x: packet_callback(x), store=0)`: Start the capture process and call a `callback_function` for each captured packet.

Ethical and Legal factors

- Permission — Make sure you have explicit permission before recording network traffic in any network. Illicit packet sniffing is very illegal and unethical.

– Educational use: An alternative to a script kiddy workstation on the same network— Legitimate reasons for monitoring your own traffic or analyzing packets from your own machine. No collecting sensitive or personal data without consent

Privacy: Analyze network traffic in a way that respects the privacy of individuals and their data.

### Conclusion

This packet sniffer example is just a simple demonstration of how to do network data capturing and parsing. It is a nice utility to get an understanding of the network protocols and doing traffic analysis but should be used responsibly, with appropriate legal permission. When experimenting with network traffic, always beware of the ethical and legal requirements.
