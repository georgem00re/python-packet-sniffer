
from scapy.all import sniff, get_if_list
import sys

INTERFACE = "en0"

def log_packet(packet):
    print(packet.summary())

def get_all_network_interfaces():
    get_if_list()

def main():
    if INTERFACE not in get_if_list(): sys.exit(1)
    sniff(iface=INTERFACE, prn=log_packet, store=False)

if __name__ == "__main__":
    main()
