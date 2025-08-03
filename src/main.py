#!/usr/bin/env python3

from scapy.all import sniff, get_if_list
import click
import sys

@click.command()
@click.option("--iface", prompt=True, help="The network interface to sniff on (e.g., eth0, tun0, utun3)")
def main(iface):
    # Get a list of all available network interfaces.
    interfaces = get_if_list()

    # Throw an exception if the provided interface is invalid.
    if iface not in interfaces:
        raise click.ClickException(f"Interface '{iface}' not found.\nAvailable interfaces: {', '.join(interfaces)}")

    click.echo(f"[*] Sniffing on {iface}. Press Ctrl+C to stop.")

    # Starts packet capture on the specific network interface.
    # Each captured packet will be logged to the console. Packets will not be stored in memory.
    sniff(iface=iface, prn=lambda packet: print(packet.summary()), store=False)

if __name__ == "__main__":
    main()
