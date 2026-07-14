# Python Deep Packet Inspection Engine

A small Python PCAP filtering engine. It parses Ethernet, IPv4, TCP, and UDP traffic, extracts TLS SNI, HTTP Host, and DNS names, then applies blocking rules by IP, app, or domain substring.

## Files

- `main.py` CLI entry point
- `generate_test_pcap.py` synthetic PCAP generator
- `src/` engine, parser, extractor, and rule modules
- `tests/test_dpi.py` unit and integration tests

## Run

```bash
python main.py test_dpi.pcap output.pcap --block-app YouTube
```

## Test

```bash
python -m unittest discover -s tests -v
```
