Continue # SQLiDorker
# Advanced Asynchronous SQL Injection Scanner

An advanced SQL injection scanner implemented in Python. This tool tests web applications for SQL injection vulnerabilities using multiple injection techniques (error-based, time-based, boolean-based, union-based, and advanced payloads). It also detects Web Application Firewalls (WAFs) and fingerprints backend Database Management Systems (DBMS) by analyzing error messages. Additionally, it features Google dorking capabilities to automatically search for and test potential vulnerable targets—allowing you to scan URLs found through dorking

## Features

- **Asynchronous Scanning:** Utilizes `asyncio` and `aiohttp` for concurrent and efficient HTTP requests.
- **Multiple Injection Techniques:** Supports error-based, time-based, boolean-based, union-based, and advanced injection methods.
- **WAF and DBMS Detection:** Automatically detects common WAF signatures and DBMS error messages.
- **Command-Line & Interactive Modes:**  
  - Scan a single URL using the `--url` option.
  - Search for vulnerable targets using Google dorks with the `--dork` option.
- **Detailed Logging:** Generates detailed logs with timestamps and error messages to aid in debugging and reporting.
- **Customizable:** Easily extend payloads and detection methods to suit your needs.

## Requirements

- Python 3.7+
- Required Python packages (install via `pip`):
  - `aiohttp`
  - `aiohttp_socks`
  - `beautifulsoup4`
  - `tldextract`
  - `googlesearch-python`
  - *(Other standard libraries are part of the Python standard library.)*

## Installation

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/vnbvr/SQLiDorker.git
    cd SQLiDorker
    ```

2. **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3. **Usage Examples:**

   - **Scan a Single URL:**
     ```bash
     python SQLiDorker.py --url "http://example.com/page.php?id=1"
     ```

   - **Search Using a Google Dork:**
     ```bash
     python SQLiDorker.py --dork "inurl:page.php?id="
     ```

   - **Verbose Output and Custom Timeout:**
     ```bash
     python SQLiDorker.py --url "http://example.com/page.php?id=1" --verbose --timeout 45
     ```

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Unauthorized scanning or exploitation of websites is illegal and unethical. Use responsibly and with explicit permission.

## Author

VnbVr
