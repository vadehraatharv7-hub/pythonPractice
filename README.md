# Port Scanner

A simple multithreaded TCP port scanner that grabs service banners from open ports.

## Usage

```
python3 port_scanner.py -t target.com -p startport-endport/port/port1,port2,port3...
```

## Arguments

| Flag | Long form | Default | Description |
|------|-----------|---------|--------------|
| `-t` | `--target` | *required* | Target IP address or hostname |
| `-p` | `--port` | `1-1024` | Port range (e.g. `20-80`), single port (e.g. `22`), or comma-separated list/mix (e.g. `22,80,1000-1010`) |
| `-w` | `--workers` | `10` | Number of threads to use |
| `-To` | `--timeout` | `1.0` | Socket timeout in seconds |

## Example

```
python3 port_scanner.py -t scanme.nmap.org -p 1-100

PORT    STATE     BANNER
----------------------------------------------------------
22      open      SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80      open      HTTP/1.1 200 OK

Scan completed in 0:00:03.475768
Open: 2  Closed: 98  Filtered: 0  Unknown: 0
```

## Requirements

Python 3, standard library only (no external dependencies).
