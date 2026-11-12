#!/usr/bin/env python3
"""
Personal Firewall - Python + Linux iptables
Educational defensive project implementation.

Features:
- Adds a dedicated set of firewall chains (does not flush existing system rules).
- Blocks selected incoming TCP/UDP destination ports.
- Blocks selected outgoing TCP/UDP destination ports.
- Logs blocked packets to the kernel log.
- Supports removing only the chains/jumps created by this program.

Run with sudo. Test in a local VM first.
"""

import argparse
import shutil
import subprocess
import sys

CHAIN_IN = "YUSUF_FW_IN"
CHAIN_OUT = "YUSUF_FW_OUT"


class FirewallError(Exception):
    pass


def run_iptables(args, check=True):
    """Run iptables and return stdout. Raises a readable error on failure."""
    command = ["iptables"] + args
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if check and result.returncode != 0:
        raise FirewallError(result.stderr.strip() or "iptables command failed")
    return result


def chain_exists(chain):
    return run_iptables(["-n", "-L", chain], check=False).returncode == 0


def jump_exists(parent, child):
    result = run_iptables(["-C", parent, "-j", child], check=False)
    return result.returncode == 0


def ensure_chain(chain):
    if not chain_exists(chain):
        run_iptables(["-N", chain])
    run_iptables(["-F", chain])


def ensure_jump(parent, child):
    if not jump_exists(parent, child):
        run_iptables(["-I", parent, "1", "-j", child])


def valid_ports(values):
    ports = []
    for value in values:
        try:
            port = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid port: {value}")
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"Port must be 1-65535: {value}")
        if port not in ports:
            ports.append(port)
    return ports


def add_port_block_rule(chain, port, direction):
    # Match both TCP and UDP, log a short prefix, then drop the packet.
    run_iptables([
        "-A", chain, "-p", "tcp", "--dport", str(port),
        "-m", "limit", "--limit", "5/min", "-j", "LOG",
        "--log-prefix", f"YUSUF_FW_{direction}_TCP "
    ])
    run_iptables([
        "-A", chain, "-p", "tcp", "--dport", str(port), "-j", "DROP"
    ])
    run_iptables([
        "-A", chain, "-p", "udp", "--dport", str(port),
        "-m", "limit", "--limit", "5/min", "-j", "LOG",
        "--log-prefix", f"YUSUF_FW_{direction}_UDP "
    ])
    run_iptables([
        "-A", chain, "-p", "udp", "--dport", str(port), "-j", "DROP"
    ])


def apply_firewall(in_ports, out_ports, allow_ssh):
    if shutil.which("iptables") is None:
        raise FirewallError("iptables is not installed. This program is for Linux.")

    ensure_chain(CHAIN_IN)
    ensure_chain(CHAIN_OUT)

    # Put our own chains at the start of INPUT and OUTPUT. Existing rules remain.
    ensure_jump("INPUT", CHAIN_IN)
    ensure_jump("OUTPUT", CHAIN_OUT)

    # Do not block established sessions or local loopback traffic.
    run_iptables(["-A", CHAIN_IN, "-i", "lo", "-j", "RETURN"])
    run_iptables([
        "-A", CHAIN_IN, "-m", "conntrack",
        "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"
    ])
    run_iptables(["-A", CHAIN_OUT, "-o", "lo", "-j", "RETURN"])
    run_iptables([
        "-A", CHAIN_OUT, "-m", "conntrack",
        "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"
    ])

    # Optional SSH allowance for new inbound connections.
    # Enable only if SSH is required and the machine is trusted.
    if allow_ssh:
        run_iptables([
            "-A", CHAIN_IN, "-p", "tcp", "--dport", "22", "-j", "RETURN"
        ])

    for port in in_ports:
        add_port_block_rule(CHAIN_IN, port, "IN")
    for port in out_ports:
        add_port_block_rule(CHAIN_OUT, port, "OUT")

    # Continue through the system's pre-existing firewall rules.
    run_iptables(["-A", CHAIN_IN, "-j", "RETURN"])
    run_iptables(["-A", CHAIN_OUT, "-j", "RETURN"])


def remove_firewall():
    # Remove only our jumps and chains. Other firewall rules are untouched.
    for parent, child in (("INPUT", CHAIN_IN), ("OUTPUT", CHAIN_OUT)):
        while jump_exists(parent, child):
            run_iptables(["-D", parent, "-j", child], check=False)
        if chain_exists(child):
            run_iptables(["-F", child])
            run_iptables(["-X", child])


def show_status():
    for chain in (CHAIN_IN, CHAIN_OUT):
        print(f"\n--- {chain} ---")
        result = run_iptables(["-n", "-v", "-L", chain], check=False)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("Not installed.")


def main():
    parser = argparse.ArgumentParser(
        description="Personal Firewall using Python and Linux iptables"
    )
    parser.add_argument(
        "--block-in", nargs="*", default=[],
        help="Incoming TCP/UDP destination ports to block, e.g. --block-in 23 445"
    )
    parser.add_argument(
        "--block-out", nargs="*", default=[],
        help="Outgoing TCP/UDP destination ports to block, e.g. --block-out 23 25"
    )
    parser.add_argument(
        "--allow-ssh", action="store_true",
        help="Explicitly allow new inbound SSH connections on TCP port 22"
    )
    parser.add_argument("--remove", action="store_true",
                        help="Remove this program's firewall chains and rules")
    parser.add_argument("--status", action="store_true",
                        help="Display this program's firewall chains")
    args = parser.parse_args()

    if sys.platform != "linux":
        print("This implementation requires Linux and iptables.")
        sys.exit(1)
    if hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() != 0:
        print("Please run with sudo/root privileges.")
        sys.exit(1)

    try:
        if args.remove:
            remove_firewall()
            print("Personal firewall rules removed.")
        elif args.status:
            show_status()
        else:
            incoming = valid_ports(args.block_in)
            outgoing = valid_ports(args.block_out)
            apply_firewall(incoming, outgoing, args.allow_ssh)
            print("Personal firewall rules applied successfully.")
            print("Incoming ports blocked:", incoming or "None")
            print("Outgoing ports blocked:", outgoing or "None")
            print("Use --status to view rules or --remove to uninstall them.")
    except FirewallError as error:
        print(f"Firewall error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
