# OffSecXWeapons External Network

Safe external network assessment helper for authorized unauthenticated testing.

## Kali installation
```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap curl traceroute nikto whatweb sslscan
# optional
sudo apt install -y golang-go
# nuclei (optional)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# testssl.sh (optional)
git clone https://github.com/drwetter/testssl.sh.git
```

## Required dependencies
- Python 3
- nmap

## Optional dependencies
- nuclei
- testssl.sh
- sslscan
- nikto
- whatweb
- traceroute

## How to run
```bash
python3 offsecx.py
```

## How to resume
- Choose `yes` at `Resume previous run?`
- Provide the run directory path (for example `offsecx_v3_20260501_120000`)

## Output files
Each run creates a directory containing:
- `state.json` (checkpoint / resume state)
- `results.json` (full normalized output)
- `findings.csv` (flat findings export)
- `report.html` (consolidated report)

## Example command
```bash
python3 offsecx.py
```
