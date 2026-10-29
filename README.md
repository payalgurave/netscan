# netscan

A small command-line network scanner written in Python. It finds devices on your network with a parallel ping sweep and shows their IP address, hostname, and response time.

## Features

- Auto-detects your local subnet (uses `psutil` if installed, otherwise assumes `/24`)
- Parallel scanning with adjustable thread count and timeout
- Reverse-DNS hostname lookup and response time for each host
- Live progress counter
- Export results to JSON or CSV
- Safety check that refuses very large scans (bigger than a `/16`) unless `--force` is given
- Works on Windows, Linux, and macOS

## Usage

```bash
python netscan.py                        # scan your local network
python netscan.py 192.168.1              # scan 192.168.1.0/24
python netscan.py 10.0.0.0/22 -t 200 -w 500
python netscan.py --no-resolve           # skip hostname lookups (faster)
python netscan.py -o results.json        # save as JSON
python netscan.py -o results.csv         # save as CSV
```

| Option | Meaning |
|---|---|
| `-w, --timeout MS` | per-host timeout in milliseconds (default 1000) |
| `-t, --threads N` | parallel workers (default 100) |
| `-o, --output FILE` | save results as `.json` or `.csv` |
| `--no-resolve` | skip reverse-DNS lookups |
| `--force` | allow scans of more than 65,536 addresses |
| `--no-banner` | hide the ASCII banner |

Optional: `pip install psutil` for accurate subnet-mask detection.

## Acknowledgements

This project started as a follow-along from a YouTube tutorial: (https://youtu.be/wCS59Jpc1iQ?si=wojup2jdkcRrFP5t). After finishing it, I rewrote and extended the code myself.

What I added on my own:

- Command-line options with `argparse` (threads, timeout, output file, and more)
- Hostname lookup, response times, and a live progress counter
- JSON and CSV export of results
- More reliable detection of the local network
- A ping check that works on non-English systems, plus a macOS timeout fix
- A limit on very large scans and clean Ctrl+C handling

## Responsible use

netscan is made for learning and for checking networks you own or have permission to test. Scanning networks without permission may be illegal where you live.
