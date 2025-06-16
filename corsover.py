#!/usr/bin/env python3
"""
CORSOVER - Advanced CORS Vulnerability Scanner
A production-grade tool for bug bounty hunters to detect CORS misconfigurations
with zero false positives through intelligent request/response analysis.
"""

import asyncio
import aiohttp
import json
import re
import sys
import time
import subprocess
import tempfile
import os
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional, Tuple
import argparse
from pathlib import Path
import logging
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint
import warnings
warnings.filterwarnings("ignore")

@dataclass
class CORSVulnerability:
    """Data class for CORS vulnerability findings"""
    url: str
    vulnerability_type: str
    severity: str
    origin_sent: str
    access_control_allow_origin: str
    access_control_allow_credentials: str
    access_control_allow_methods: str
    access_control_allow_headers: str
    description: str
    poc: str
    response_headers: Dict[str, str]
    timestamp: str

class CORSScanner:
    def __init__(self, target_domain: str, max_concurrent: int = 50):
        self.target_domain = target_domain
        self.max_concurrent = max_concurrent
        self.console = Console()
        self.vulnerabilities: List[CORSVulnerability] = []
        self.tested_urls: Set[str] = set()
        self.live_urls: Set[str] = set()
        
        # Advanced CORS test payloads
        self.cors_payloads = [
            "https://evil.com",
            "http://evil.com", 
            f"https://evil.{target_domain}",
            f"http://evil.{target_domain}",
            "null",
            "file://",
            "data:",
            f"https://{target_domain}.evil.com",
            f"http://{target_domain}.evil.com",
            "https://localhost",
            "http://localhost",
            "https://127.0.0.1",
            "http://127.0.0.1",
            f"https://www.{target_domain}",
            f"http://www.{target_domain}",
            "https://attacker.com",
            "javascript://",
            "vbscript:",
            f"https://{target_domain}",
            f"http://{target_domain}",
            "",  # Empty origin
            "https://.",
            "http://.",
            "https://evil.com.target.com",
            f"https://sub.{target_domain}",
            "https://evil%00.com",
            "https://evil\x00.com",
            "Origin: https://evil.com\r\nInjected: header",
        ]
        
        # Headers to check for in responses
        self.cors_headers = [
            'access-control-allow-origin',
            'access-control-allow-credentials',
            'access-control-allow-methods',
            'access-control-allow-headers',
            'access-control-expose-headers',
            'access-control-max-age',
            'vary'
        ]
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    async def enumerate_subdomains(self) -> Set[str]:
        """Enumerate subdomains using crt.sh and subfinder"""
        subdomains = set()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Enumerating subdomains..."),
            transient=True,
        ) as progress:
            task = progress.add_task("Subdomain enumeration", total=None)
            
            # crt.sh enumeration
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                    url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = await response.json()
                            for entry in data:
                                name = entry.get('name_value', '')
                                if name:
                                    # Handle wildcard and multiple domains
                                    domains = name.split('\n')
                                    for domain in domains:
                                        domain = domain.strip().lower()
                                        if domain.startswith('*.'):
                                            domain = domain[2:]
                                        if domain.endswith(f'.{self.target_domain}') or domain == self.target_domain:
                                            subdomains.add(domain)
            except Exception as e:
                self.logger.warning(f"crt.sh enumeration failed: {e}")
            
            # Subfinder enumeration (if available)
            try:
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                    temp_file = f.name
                
                result = subprocess.run(['subfinder', '-d', self.target_domain, '-o', temp_file], 
                                      capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0 and os.path.exists(temp_file):
                    with open(temp_file, 'r') as f:
                        for line in f:
                            subdomain = line.strip().lower()
                            if subdomain:
                                subdomains.add(subdomain)
                
                os.unlink(temp_file)
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
                self.logger.warning(f"Subfinder enumeration failed: {e}")
        
        # Add common subdomains
        common_subs = ['www', 'api', 'admin', 'app', 'dev', 'test', 'staging', 'mobile', 'cdn', 'static']
        for sub in common_subs:
            subdomains.add(f"{sub}.{self.target_domain}")
        
        subdomains.add(self.target_domain)
        
        return subdomains

    async def filter_live_domains(self, subdomains: Set[str]) -> Set[str]:
        """Filter out live domains from the subdomain list"""
        live_domains = set()
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_domain(session, domain):
            async with semaphore:
                for scheme in ['https', 'http']:
                    url = f"{scheme}://{domain}"
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            if response.status != 404:
                                live_domains.add(url)
                                return
                    except:
                        continue
        
        async with aiohttp.ClientSession() as session:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold green]Filtering live domains..."),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task("Checking domains", total=len(subdomains))
                
                tasks = []
                for domain in subdomains:
                    tasks.append(check_domain(session, domain))
                
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task)
        
        return live_domains

    async def crawl_urls(self, domains: Set[str]) -> Set[str]:
        """Crawl domains to find additional endpoints"""
        all_urls = set(domains)
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Common endpoints to check
        common_endpoints = [
            '/api', '/api/v1', '/api/v2', '/admin', '/login', '/dashboard',
            '/user', '/profile', '/settings', '/config', '/upload', '/download',
            '/search', '/data', '/info', '/status', '/health', '/debug',
            '/test', '/dev', '/staging', '/mobile', '/app', '/service',
            '/rest', '/graphql', '/soap', '/xml', '/json', '/oauth',
            '/auth', '/token', '/session', '/cookie', '/cors', '/cross-origin'
        ]
        
        async def crawl_domain(session, base_url):
            async with semaphore:
                found_urls = set()
                
                # Check common endpoints
                for endpoint in common_endpoints:
                    url = urljoin(base_url, endpoint)
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            if response.status not in [404, 403, 500]:
                                found_urls.add(url)
                    except:
                        continue
                
                # Try to find links in the main page
                try:
                    async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 200:
                            content = await response.text()
                            # Extract URLs from href and src attributes
                            urls = re.findall(r'(?:href|src)=["\']([^"\']*)["\']', content, re.IGNORECASE)
                            for url in urls:
                                if url.startswith('/'):
                                    full_url = urljoin(base_url, url)
                                    if urlparse(full_url).netloc == urlparse(base_url).netloc:
                                        found_urls.add(full_url)
                except:
                    pass
                
                return found_urls
        
        async with aiohttp.ClientSession() as session:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold yellow]Crawling for endpoints..."),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task("Crawling URLs", total=len(domains))
                
                tasks = []
                for domain in domains:
                    tasks.append(crawl_domain(session, domain))
                
                for coro in asyncio.as_completed(tasks):
                    found_urls = await coro
                    all_urls.update(found_urls)
                    progress.advance(task)
        
        return all_urls

    def analyze_cors_response(self, origin: str, response_headers: Dict[str, str], status_code: int) -> Optional[Dict]:
        """Analyze CORS response for vulnerabilities with zero false positives"""
        
        # Extract CORS headers (case-insensitive)
        headers_lower = {k.lower(): v for k, v in response_headers.items()}
        
        acao = headers_lower.get('access-control-allow-origin', '').strip()
        acac = headers_lower.get('access-control-allow-credentials', '').strip().lower()
        acam = headers_lower.get('access-control-allow-methods', '').strip()
        acah = headers_lower.get('access-control-allow-headers', '').strip()
        
        # No CORS headers = not vulnerable
        if not acao:
            return None
        
        vulnerability = None
        
        # 1. Wildcard with credentials (High severity)
        if acao == '*' and acac == 'true':
            vulnerability = {
                'type': 'Wildcard Origin with Credentials',
                'severity': 'High',
                'description': 'Server allows any origin (*) with credentials, enabling complete CORS bypass',
                'poc': f'fetch("{origin}", {{credentials: "include", mode: "cors"}})'
            }
        
        # 2. Null origin reflection with credentials (High severity)
        elif acao == 'null' and acac == 'true' and origin == 'null':
            vulnerability = {
                'type': 'Null Origin Reflection with Credentials',
                'severity': 'High', 
                'description': 'Server reflects null origin with credentials, exploitable via data: URLs or sandboxed iframes',
                'poc': f'<iframe src="data:text/html,<script>fetch(\\"{origin}\\", {{credentials: \\"include\\", mode: \\"cors\\"}}).then(r=>r.text()).then(console.log)</script>"></iframe>'
            }
        
        # 3. Dangerous origin reflection with credentials (High/Medium severity)
        elif acao == origin and acac == 'true' and origin not in ['', 'null']:
            parsed_origin = urlparse(origin)
            target_parsed = urlparse(f"https://{self.target_domain}")
            
            # Check if it's a completely different domain
            if parsed_origin.netloc != target_parsed.netloc and not parsed_origin.netloc.endswith(f".{self.target_domain}"):
                severity = 'High'
                if 'localhost' in origin or '127.0.0.1' in origin:
                    severity = 'Medium'
                
                vulnerability = {
                    'type': 'Arbitrary Origin Reflection with Credentials',
                    'severity': severity,
                    'description': f'Server reflects arbitrary origin ({origin}) with credentials enabled',
                    'poc': f'fetch("{origin}", {{credentials: "include", mode: "cors", headers: {{"Origin": "{origin}"}}}}).then(r=>r.text()).then(console.log)'
                }
        
        # 4. Subdomain wildcard issues (Medium severity)
        elif acao != '*' and acao != origin and '.' in acao:
            if acao.startswith('*.') and acac == 'true':
                vulnerability = {
                    'type': 'Subdomain Wildcard with Credentials',
                    'severity': 'Medium',
                    'description': f'Server allows subdomain wildcard ({acao}) with credentials',
                    'poc': f'// Register subdomain like evil.{acao[2:]} and exploit'
                }
        
        # 5. Protocol issues (Medium severity)
        elif acao == origin and acac == 'true':
            if origin.startswith('http://') and self.target_domain in origin:
                vulnerability = {
                    'type': 'HTTP Origin Accepted',
                    'severity': 'Medium',
                    'description': 'Server accepts HTTP origin with credentials, vulnerable to MITM attacks',
                    'poc': f'fetch("{origin}", {{credentials: "include", mode: "cors"}})'
                }
        
        # 6. Pre-flight bypass potential (Low severity)
        elif acao != '*' and acao != '' and acam and 'GET' in acam.upper():
            if not acac or acac != 'true':
                vulnerability = {
                    'type': 'Weak CORS Configuration',
                    'severity': 'Low',
                    'description': 'CORS enabled without credentials, potential information disclosure',
                    'poc': f'fetch("{origin}", {{mode: "cors"}})'
                }
        
        if vulnerability:
            return {
                'vulnerability_type': vulnerability['type'],
                'severity': vulnerability['severity'],
                'description': vulnerability['description'],
                'poc': vulnerability['poc'],
                'origin_sent': origin,
                'access_control_allow_origin': acao,
                'access_control_allow_credentials': acac,
                'access_control_allow_methods': acam,
                'access_control_allow_headers': acah
            }
        
        return None

    async def test_cors_vulnerability(self, session: aiohttp.ClientSession, url: str) -> List[CORSVulnerability]:
        """Test a single URL for CORS vulnerabilities"""
        vulnerabilities = []
        
        for origin in self.cors_payloads:
            try:
                headers = {
                    'Origin': origin,
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 404:
                        continue
                    
                    response_headers = dict(response.headers)
                    
                    # Analyze the response
                    analysis = self.analyze_cors_response(origin, response_headers, response.status)
                    
                    if analysis:
                        vuln = CORSVulnerability(
                            url=url,
                            vulnerability_type=analysis['vulnerability_type'],
                            severity=analysis['severity'],
                            origin_sent=analysis['origin_sent'],
                            access_control_allow_origin=analysis['access_control_allow_origin'],
                            access_control_allow_credentials=analysis['access_control_allow_credentials'],
                            access_control_allow_methods=analysis['access_control_allow_methods'],
                            access_control_allow_headers=analysis['access_control_allow_headers'],
                            description=analysis['description'],
                            poc=analysis['poc'],
                            response_headers=response_headers,
                            timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
                        )
                        vulnerabilities.append(vuln)
                        
                        # Only test one payload per URL if vulnerability found to avoid duplicates
                        break
                        
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                continue
        
        return vulnerabilities

    async def scan_urls(self, urls: Set[str]):
        """Scan all URLs for CORS vulnerabilities"""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        found_vulnerabilities = 0
        
        async def scan_url(session, url):
            nonlocal found_vulnerabilities
            async with semaphore:
                self.tested_urls.add(url)
                vulns = await self.test_cors_vulnerability(session, url)
                if vulns:
                    self.vulnerabilities.extend(vulns)
                    found_vulnerabilities += len(vulns)
                    
                    # Display vulnerability immediately
                    for vuln in vulns:
                        self.display_vulnerability(vuln)
                
                return len(vulns)
        
        connector = aiohttp.TCPConnector(limit=self.max_concurrent, limit_per_host=20)
        async with aiohttp.ClientSession(connector=connector) as session:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold red]🔍 Scanning for CORS vulnerabilities..."),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("• Found: {task.fields[found]} vulns"),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task("CORS Scanning", total=len(urls), found=0)
                
                tasks = []
                for url in urls:
                    tasks.append(scan_url(session, url))
                
                for coro in asyncio.as_completed(tasks):
                    vuln_count = await coro
                    progress.update(task, advance=1, found=found_vulnerabilities)

    def display_vulnerability(self, vuln: CORSVulnerability):
        """Display a vulnerability with futuristic styling"""
        
        # Color mapping for severity
        severity_colors = {
            'High': 'red',
            'Medium': 'yellow', 
            'Low': 'blue'
        }
        
        color = severity_colors.get(vuln.severity, 'white')
        
        # Create vulnerability panel
        content = f"""
[bold]URL:[/bold] {vuln.url}
[bold]Vulnerability:[/bold] {vuln.vulnerability_type}
[bold]Severity:[/bold] [{color}]{vuln.severity}[/{color}]

[bold]Details:[/bold]
• Origin Sent: {vuln.origin_sent}
• ACAO Response: {vuln.access_control_allow_origin}
• Credentials: {vuln.access_control_allow_credentials}

[bold]Description:[/bold]
{vuln.description}

[bold]Proof of Concept:[/bold]
[code]{vuln.poc}[/code]

[bold]Timestamp:[/bold] {vuln.timestamp}
        """.strip()
        
        panel = Panel(
            content,
            title=f"🚨 CORS Vulnerability Found",
            title_align="left",
            border_style=color,
            padding=(1, 2)
        )
        
        self.console.print(panel)
        self.console.print()

    def generate_report(self):
        """Generate a comprehensive report"""
        if not self.vulnerabilities:
            self.console.print("[green]✅ No CORS vulnerabilities found![/green]")
            return
        
        # Summary statistics
        total_vulns = len(self.vulnerabilities)
        high_severity = len([v for v in self.vulnerabilities if v.severity == 'High'])
        medium_severity = len([v for v in self.vulnerabilities if v.severity == 'Medium'])
        low_severity = len([v for v in self.vulnerabilities if v.severity == 'Low'])
        
        # Create summary table
        table = Table(title="🔍 CORS Vulnerability Scan Results", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="bold")
        
        table.add_row("Total URLs Tested", str(len(self.tested_urls)))
        table.add_row("Vulnerabilities Found", str(total_vulns))
        table.add_row("High Severity", f"[red]{high_severity}[/red]")
        table.add_row("Medium Severity", f"[yellow]{medium_severity}[/yellow]")
        table.add_row("Low Severity", f"[blue]{low_severity}[/blue]")
        
        self.console.print(table)
        
        # Save detailed report to JSON
        report_data = {
            'scan_info': {
                'target_domain': self.target_domain,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_urls_tested': len(self.tested_urls),
                'total_vulnerabilities': total_vulns
            },
            'summary': {
                'high_severity': high_severity,
                'medium_severity': medium_severity,
                'low_severity': low_severity
            },
            'vulnerabilities': [asdict(vuln) for vuln in self.vulnerabilities]
        }
        
        filename = f"corsover_report_{self.target_domain}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.console.print(f"\n[green]📄 Detailed report saved to: {filename}[/green]")

    async def run_scan(self):
        """Main scanning orchestrator"""
        start_time = time.time()
        
        # ASCII Art Banner
        banner = """
╔═════════════════════════════════════════════════════════════════════╗
║                                                                     ║
║  ██████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██╗   ██╗███████╗██████╗  ║
║ ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗ ║
║ ██║     ██║   ██║██████╔╝███████╗██║   ██║██║   ██║█████╗  ██████╔╝ ║
║ ██║     ██║   ██║██╔══██╗╚════██║██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗ ║
║ ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝ ╚████╔╝ ███████╗██║  ██║ ║
║  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ║
║                                                                     ║
║                 Advanced CORS Vulnerability Scanner                 ║
║                    Professional Security Tool                       ║
║                      AUTHOR: MUHAMMED FARHAN                        ║
╚═════════════════════════════════════════════════════════════════════╝
        """
        
        self.console.print(f"[bold cyan]{banner}[/bold cyan]")
        self.console.print(f"[bold]🎯 Target Domain:[/bold] {self.target_domain}")
        self.console.print(f"[bold]🚀 Max Concurrent:[/bold] {self.max_concurrent}")
        self.console.print()
        
        try:
            # Step 1: Enumerate subdomains
            self.console.print("[bold blue]Phase 1: Subdomain Enumeration[/bold blue]")
            subdomains = await self.enumerate_subdomains()
            self.console.print(f"✅ Found {len(subdomains)} subdomains")
            
            # Step 2: Filter live domains
            self.console.print("\n[bold green]Phase 2: Live Domain Filtering[/bold green]")
            live_domains = await self.filter_live_domains(subdomains)
            self.console.print(f"✅ Found {len(live_domains)} live domains")
            
            # Step 3: Crawl for endpoints
            self.console.print("\n[bold yellow]Phase 3: Endpoint Discovery[/bold yellow]")
            all_urls = await self.crawl_urls(live_domains)
            self.console.print(f"✅ Discovered {len(all_urls)} URLs to test")
            
            # Step 4: CORS vulnerability scanning
            self.console.print("\n[bold red]Phase 4: CORS Vulnerability Scanning[/bold red]")
            await self.scan_urls(all_urls)
            
            # Step 5: Generate report
            self.console.print("\n[bold magenta]Phase 5: Report Generation[/bold magenta]")
            self.generate_report()
            
            # Final statistics
            end_time = time.time()
            duration = end_time - start_time
            
            self.console.print(f"\n[bold green]🎉 Scan completed in {duration:.2f} seconds[/bold green]")
            
        except KeyboardInterrupt:
            self.console.print("\n[bold red]❌ Scan interrupted by user[/bold red]")
            sys.exit(1)
        except Exception as e:
            self.console.print(f"\n[bold red]❌ Scan failed: {str(e)}[/bold red]")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="CORSOVER - Advanced CORS Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python corsover.py -d example.com
  python corsover.py -d example.com -c 100
  python corsover.py -d example.com --max-concurrent 75
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-c', '--max-concurrent', type=int, default=50, 
                       help='Maximum concurrent requests (default: 50)')
    
    args = parser.parse_args()
    
    # Validate domain
    if not args.domain or '.' not in args.domain:
        print("❌ Please provide a valid domain name")
        sys.exit(1)
    
    # Remove protocol if present
    domain = args.domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    # Initialize and run scanner
    scanner = CORSScanner(domain, args.max_concurrent)
    
    try:
        asyncio.run(scanner.run_scan())
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted")
        sys.exit(1)

if __name__ == "__main__":
    main()
