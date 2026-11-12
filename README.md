# Personal Firewall - Python + Linux iptables

## Project objective
Create a custom personal firewall application that manages selected incoming and outgoing network traffic rules.

## Technology used
- Python 3
- Linux `iptables`
- TCP/UDP packet filtering
- Linux kernel firewall logging

## Files
- `personal_firewall.py` - complete Python implementation.

## Requirements
- Linux (Ubuntu/Kali/Debian recommended)
- Python 3
- `iptables`
- Administrator/root access (`sudo`)

Install iptables if required:
```bash
sudo apt update
sudo apt install iptables
```

## Run the implementation

Make the file executable:
```bash
chmod +x personal_firewall.py
```

Block incoming TCP/UDP traffic to ports 23 and 445:
```bash
sudo python3 personal_firewall.py --block-in 23 445
```

Block outgoing TCP/UDP traffic to port 25:
```bash
sudo python3 personal_firewall.py --block-out 25
```

Apply both incoming and outgoing rules:
```bash
sudo python3 personal_firewall.py --block-in 23 445 --block-out 25
```

View the rules:
```bash
sudo python3 personal_firewall.py --status
```

Remove only the rules/chains created by this project:
```bash
sudo python3 personal_firewall.py --remove
```

## How it works
1. The program creates two dedicated iptables chains: `YUSUF_FW_IN` and `YUSUF_FW_OUT`.
2. It attaches these chains to the Linux INPUT and OUTPUT chains.
3. It preserves loopback and established/related traffic.
4. It adds TCP and UDP destination-port rules for the ports selected by the user.
5. Matching packets are logged (rate-limited) and dropped.
6. Other packets return to the existing firewall rules.
7. The `--remove` option detaches and deletes only the chains created by this program.

## Example test plan

| Test | Command / action | Expected result |
|---|---|---|
| View current project rules | `sudo python3 personal_firewall.py --status` | Shows project chains or says not installed |
| Block incoming port 23 | Run with `--block-in 23` | New incoming TCP/UDP packets to port 23 are dropped |
| Block outgoing port 25 | Run with `--block-out 25` | Outgoing TCP/UDP packets to port 25 are dropped |
| Remove project rules | Run with `--remove` | Project chains and jumps are removed |

## Important safety notes
- Test in a virtual machine or lab system first.
- This project changes the host firewall and requires root privileges.
- Do not run on a remote server unless you have console access; firewall mistakes can interrupt connectivity.
- The script does not flush the system's existing firewall rules.
- This is an IPv4 `iptables` demonstration. IPv6 traffic needs separate `ip6tables` rules.
- Rules are runtime rules and may not persist after reboot unless configured separately.
- This is an educational project implementation, not a replacement for a professionally managed firewall.

## Project conclusion
The implementation demonstrates network security concepts, packet filtering, protocol selection (TCP/UDP), rule management and firewall logging using Python and Linux iptables.
