# requirements.md

## Runtime
- Python 3.10+

## Required tool
- nmap

## Optional tools
- nuclei
- testssl.sh
- sslscan
- nikto
- whatweb
- traceroute

## Notes
- Script uses timezone-aware UTC via `datetime.now(UTC)`.
- Optional tools are skipped gracefully if not installed.
- Required `nmap` must be available in PATH.
