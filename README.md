# CLI Risk Assessment Tool
_By: Abdullah Q._

## Usage:

python3 main.py --target TARGET --profile PROFILE --output OUTPUT --timeout --threads THREADS

1. TARGET (Mandatory) is the target computer that you want to scan. A good, legal example would be scanning scanme.nmap.org.
  - Alternatively, you could use IPs instead, i.e 45.33.32.156.

2. PROFILE (standard by default) determines which ports to scan. I was inspired by various Nmap flags, like -T and -F.
  - standard, medium time, doesn't scan all ports.
  - quick, fastest, scans only a few common ports.
  - full, most extensive and time consuming, scans all ports within my PortRisks.py.

3. OUTPUT (Terminal by default) determines how the results are returned.
  - Terminal is the default, it prints the results to the CLI.
  - JSON is another option, which exports the results in a JSON format. This is useful for passing the results through piplines like
    Splunk, Elasticsearch, etc.
  - csv is the final option, which exports the results in csv format.

4. TIMEOUT is simply how long the the program waits for a connection. by default it's 1.5, but you can replace it with any other number (not negative)

5. THREADS - how many PORTS are being scanned at a time. by default, we scan 50 ports at the same time.
