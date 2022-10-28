# Description
An ICMP-based shell written in C, nothing fancy, made it just for fun and to poke at some C/*nix programming concepts.

# Optional Requirement
- UPX

# Usage  
You can build the binaries by running `make` which needs sudo permissions to set the `cap_net_raw` capability:
- `bin/icmp-c2` is the C2 that sends commands to the implant (attacker)
- `bin/icmp-implant` is the implant which executes commands and sends them back to the C2 (victim)

Don't forget to run `sysctl -w net.ipv4.icmp_echo_ignore_all=1` on both machines (as root) so no interference may occur between the C2 and the implant.

# Todo
- Add some stealthness (e.g encrypted communication, default packet size with fragementation, obfuscated process name, random ICMP id numbers, delays...).
