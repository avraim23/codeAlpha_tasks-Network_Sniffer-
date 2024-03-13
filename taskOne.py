from scapy.all import sniff, wrpcap, TCP, IP, getmacbyip

def analyze_packet(packet):
  """Analyzes a captured packet and prints relevant information."""
  if packet.haslayer(IP):
    # Extract source and destination IP addresses
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Resolve MAC addresses (if possible)
    try:
      src_mac = getmacbyip(src_ip)
    except Exception:
      src_mac = "Unknown"
    try:
      dst_mac = getmacbyip(dst_ip)
    except Exception:
      dst_mac = "Unknown"

    # Analyze protocol layer (focusing on TCP for now)
    if packet.haslayer(TCP):
      protocol = "TCP"
      src_port = packet[TCP].sport
      dst_port = packet[TCP].dport
      flags = packet[TCP].flags
    else:
      protocol = packet.name  # Use the layer name if not TCP

    # Print captured information
    print(f"Source MAC: {src_mac}  Destination MAC: {dst_mac}")
    print(f"Source IP: {src_ip}  Destination IP: {dst_ip}")
    print(f"Protocol: {protocol}  Ports: {src_port} -> {dst_port}")
    print(f"Flags: {flags}")
    print("-" * 40)  # Separator for readability

def capture_packets(iface, filename):
  """Captures packets from the specified interface and saves them to a PCAP file."""
  sniff(iface=iface, prn=analyze_packet, store=wrpcap(filename))

if __name__ == "__main__":
  # Replace "eth0" with your network interface name
  # Replace "mycapture.pcap" with your desired filename
  iface = "eth0"
  filename = "mycapture.pcap"

  capture_packets(iface, filename)

  print("Packet capture completed. Check", filename, "for captured data.")