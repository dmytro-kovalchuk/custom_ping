# Custom Ping

## Build
To build, use:
```bash
gcc ping.c
```

## Usage
To run, use:
```bash
sudo ./a.out [-s size] [-c count] [-t ttl] <IPv4/IPv6 address or hostname>
```
Examples:
```bash
user@pc:/$ sudo ./a.out -h
Usage: sudo ./a.out [-s size] [-c count] [-t ttl] destination
	-h, --help		Show this help message
	-s, --size		Set number of bytes in ICMP packet(min 64 bytes, max 1024 bytes)
	-c, --count		Set number of packets
	-t, --ttl		Set time to live
    


user@pc:/$ sudo ./a.out 8.8.8.8
PING: sent 64 bytes to 8.8.8.8
PONG: received 8 bytes from 8.8.8.8, ttl=118, round-trip time 18.04 ms

PING: sent 64 bytes to 8.8.8.8
PONG: received 8 bytes from 8.8.8.8, ttl=118, round-trip time 399.95 ms

PING: sent 64 bytes to 8.8.8.8
PONG: received 8 bytes from 8.8.8.8, ttl=118, round-trip time 10.83 ms

PING: sent 64 bytes to 8.8.8.8
PONG: received 8 bytes from 8.8.8.8, ttl=118, round-trip time 9.69 ms



user@pc:/$ sudo ./a.out google.com
PING: sent 64 bytes to google.com
PONG: received 8 bytes from 216.58.208.206, ttl=117, round-trip time 9.81 ms

PING: sent 64 bytes to google.com
PONG: received 8 bytes from 216.58.208.206, ttl=117, round-trip time 141.68 ms

PING: sent 64 bytes to google.com
PONG: received 8 bytes from 216.58.208.206, ttl=117, round-trip time 10.30 ms

PING: sent 64 bytes to google.com
PONG: received 8 bytes from 216.58.208.206, ttl=117, round-trip time 33.12 ms
```