#!/usr/bin/env python3

import argparse
import ssl
import socket
import datetime
import json
import csv
import sys
import threading
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess

class SSLChecker:
    def __init__(self):
        self.timeout = 10
        self.results = []
        
    def check_ssl_certificate(self, hostname, port=443):
        #Check SSL certificate for a single host
        result = {
            'hostname': hostname,
            'port': port,
            'timestamp': datetime.datetime.now().isoformat(),
            'status': 'unknown',
            'error': None,
            'certificate': {}
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to the host
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        result['status'] = 'success'
                        result['certificate'] = self.parse_certificate(cert)
                        result['certificate']['cipher'] = ssock.cipher()
                        result['certificate']['version'] = ssock.version()
                    else:
                        result['status'] = 'no_certificate'
                        result['error'] = 'No certificate found'
                        
        except socket.timeout:
            result['status'] = 'timeout'
            result['error'] = f'Connection timeout after {self.timeout} seconds'
        except socket.gaierror as e:
            result['status'] = 'dns_error'
            result['error'] = f'DNS resolution failed: {str(e)}'
        except ssl.SSLError as e:
            result['status'] = 'ssl_error'
            result['error'] = f'SSL error: {str(e)}'
        except ConnectionRefusedError:
            result['status'] = 'connection_refused'
            result['error'] = 'Connection refused'
        except Exception as e:
            result['status'] = 'error'
            result['error'] = f'Unexpected error: {str(e)}'
            
        return result
    
    def parse_certificate(self, cert):
        #Parse certificate information
        parsed = {}
        
        # Basic certificate info
        parsed['subject'] = dict(x[0] for x in cert.get('subject', []))
        parsed['issuer'] = dict(x[0] for x in cert.get('issuer', []))
        parsed['version'] = cert.get('version', 'Unknown')
        parsed['serial_number'] = cert.get('serialNumber', 'Unknown')
        
        # Validity dates
        not_before = cert.get('notBefore')
        not_after = cert.get('notAfter')
        
        if not_before:
            parsed['not_before'] = datetime.datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
            parsed['not_before_str'] = parsed['not_before'].strftime('%Y-%m-%d %H:%M:%S UTC')
        
        if not_after:
            parsed['not_after'] = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            parsed['not_after_str'] = parsed['not_after'].strftime('%Y-%m-%d %H:%M:%S UTC')
            
            # Calculate days until expiration
            now = datetime.datetime.utcnow()
            days_until_expiry = (parsed['not_after'] - now).days
            parsed['days_until_expiry'] = days_until_expiry
            
            # Certificate status
            if days_until_expiry < 0:
                parsed['status'] = 'expired'
            elif days_until_expiry <= 30:
                parsed['status'] = 'expiring_soon'
            elif days_until_expiry <= 90:
                parsed['status'] = 'expiring_warning'
            else:
                parsed['status'] = 'valid'
        
        # Subject Alternative Names
        san_list = []
        for ext in cert.get('subjectAltName', []):
            if ext[0] == 'DNS':
                san_list.append(ext[1])
        parsed['san'] = san_list
        
        # OCSP and CRL
        parsed['ocsp'] = []
        parsed['crl'] = []
        
        for ext_oid, ext_value in cert.get('extensions', []):
            if 'authorityInfoAccess' in ext_oid:
                if 'OCSP' in ext_value:
                    parsed['ocsp'].append(ext_value)
            elif 'crlDistributionPoints' in ext_oid:
                parsed['crl'].append(ext_value)
        
        return parsed
    
    def check_multiple_hosts(self, hosts, max_workers=10):
        #Check SSL certificates for multiple hosts
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all jobs
            future_to_host = {}
            for host_info in hosts:
                if isinstance(host_info, str):
                    hostname = host_info
                    port = 443
                else:
                    hostname = host_info.get('hostname')
                    port = host_info.get('port', 443)
                
                future = executor.submit(self.check_ssl_certificate, hostname, port)
                future_to_host[future] = (hostname, port)
            
            # Collect results
            for future in as_completed(future_to_host):
                hostname, port = future_to_host[future]
                try:
                    result = future.result()
                    results.append(result)
                    print(f"Checked {hostname}:{port} - {result['status']}")
                except Exception as e:
                    print(f"Error checking {hostname}:{port}: {e}")
        
        return results
    
    def check_url_list(self, url_list):
        #Check SSL certificates for a list of URLs
        hosts = []
        
        for url in url_list:
            try:
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                
                parsed_url = urlparse(url)
                hostname = parsed_url.hostname
                port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
                
                if hostname:
                    hosts.append({'hostname': hostname, 'port': port})
                    
            except Exception as e:
                print(f"Error parsing URL {url}: {e}")
        
        return self.check_multiple_hosts(hosts)
    
    def load_hosts_from_file(self, filename):
        #Load hosts from a file (one per line)
        hosts = []
        
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ':' in line:
                            hostname, port = line.split(':', 1)
                            hosts.append({'hostname': hostname.strip(), 'port': int(port.strip())})
                        else:
                            hosts.append({'hostname': line, 'port': 443})
        except FileNotFoundError:
            print(f"Error: File not found: {filename}")
            return []
        except Exception as e:
            print(f"Error reading file {filename}: {e}")
            return []
        
        return hosts
    
    def print_result(self, result):
        #Print a single result in human-readable format
        hostname = result['hostname']
        port = result['port']
        status = result['status']
        
        print(f"\n{'='*60}")
        print(f"Host: {hostname}:{port}")
        print(f"Status: {status}")
        print(f"Checked: {result['timestamp']}")
        
        if result['error']:
            print(f"Error: {result['error']}")
            return
        
        if status != 'success':
            return
        
        cert = result['certificate']
        
        # Subject information
        subject = cert.get('subject', {})
        print(f"Subject: {subject.get('commonName', 'N/A')}")
        if subject.get('organizationName'):
            print(f"Organization: {subject['organizationName']}")
        
        # Issuer
        issuer = cert.get('issuer', {})
        print(f"Issuer: {issuer.get('commonName', 'N/A')}")
        
        # Validity
        print(f"Valid From: {cert.get('not_before_str', 'N/A')}")
        print(f"Valid Until: {cert.get('not_after_str', 'N/A')}")
        
        days_until_expiry = cert.get('days_until_expiry')
        if days_until_expiry is not None:
            if days_until_expiry < 0:
                print(f"[X] Certificate EXPIRED {abs(days_until_expiry)} days ago!")
            elif days_until_expiry <= 30:
                print(f"[!] Certificate expires in {days_until_expiry} days!")
            elif days_until_expiry <= 90:
                print(f"[#] Certificate expires in {days_until_expiry} days")
            else:
                print(f"[#] Certificate expires in {days_until_expiry} days")
        
        # SSL/TLS info
        if cert.get('version'):
            print(f"TLS Version: {cert['version']}")
        
        if cert.get('cipher'):
            cipher_info = cert['cipher']
            if isinstance(cipher_info, tuple) and len(cipher_info) >= 2:
                print(f"Cipher Suite: {cipher_info[0]}")
                print(f"Encryption: {cipher_info[2]} bits" if len(cipher_info) > 2 else "")
        
        # Subject Alternative Names
        san_list = cert.get('san', [])
        if san_list:
            print(f"SAN: {', '.join(san_list[:5])}")  # Show first 5 SANs
            if len(san_list) > 5:
                print(f"     ... and {len(san_list) - 5} more")
        
        # Serial number
        print(f"Serial: {cert.get('serial_number', 'N/A')}")
    
    def generate_summary_report(self, results):
        #Generate a summary report
        if not results:
            print("No results to summarize")
            return
        
        total = len(results)
        successful = sum(1 for r in results if r['status'] == 'success')
        failed = total - successful
        
        # Certificate status counts
        expired = 0
        expiring_soon = 0
        expiring_warning = 0
        valid = 0
        
        for result in results:
            if result['status'] == 'success':
                cert_status = result['certificate'].get('status', 'unknown')
                if cert_status == 'expired':
                    expired += 1
                elif cert_status == 'expiring_soon':
                    expiring_soon += 1
                elif cert_status == 'expiring_warning':
                    expiring_warning += 1
                elif cert_status == 'valid':
                    valid += 1
        
        print(f"\n{'='*60}")
        print("SUMMARY REPORT")
        print(f"{'='*60}")
        print(f"Total Hosts Checked: {total}")
        print(f"Successful Checks: {successful}")
        print(f"Failed Checks: {failed}")
        print(f"\nCertificate Status:")
        print(f"  [#] Valid: {valid}")
        print(f"  [!] Expiring (30-90 days): {expiring_warning}")
        print(f"  [!] Expiring Soon (≤30 days): {expiring_soon}")
        print(f"  [X] Expired: {expired}")
        
        # Show expired certificates
        if expired > 0:
            print(f"\n[X] EXPIRED CERTIFICATES:")
            for result in results:
                if (result['status'] == 'success' and 
                    result['certificate'].get('status') == 'expired'):
                    hostname = result['hostname']
                    port = result['port']
                    days = abs(result['certificate'].get('days_until_expiry', 0))
                    print(f"  {hostname}:{port} - Expired {days} days ago")
        
        # Show expiring soon certificates
        if expiring_soon > 0:
            print(f"\n⚠️  CERTIFICATES EXPIRING SOON (≤30 days):")
            for result in results:
                if (result['status'] == 'success' and 
                    result['certificate'].get('status') == 'expiring_soon'):
                    hostname = result['hostname']
                    port = result['port']
                    days = result['certificate'].get('days_until_expiry', 0)
                    not_after = result['certificate'].get('not_after_str', 'Unknown')
                    print(f"  {hostname}:{port} - {days} days ({not_after})")
        
        # Show failed checks
        if failed > 0:
            print(f"\n[X] FAILED CHECKS:")
            for result in results:
                if result['status'] != 'success':
                    hostname = result['hostname']
                    port = result['port']
                    error = result['error'] or 'Unknown error'
                    print(f"  {hostname}:{port} - {error}")
    
    def save_results_json(self, results, filename):
        #Save results to JSON file
        try:
            # Convert datetime objects to strings for JSON serialization
            json_results = []
            for result in results:
                json_result = result.copy()
                if 'certificate' in json_result:
                    cert = json_result['certificate'].copy()
                    # Convert datetime objects to ISO format strings
                    for key in ['not_before', 'not_after']:
                        if key in cert and isinstance(cert[key], datetime.datetime):
                            cert[key] = cert[key].isoformat()
                    json_result['certificate'] = cert
                json_results.append(json_result)
            
            with open(filename, 'w') as f:
                json.dump(json_results, f, indent=2, default=str)
            
            print(f"\nResults saved to JSON: {filename}")
            
        except Exception as e:
            print(f"Error saving JSON file: {e}")
    
    def save_results_csv(self, results, filename):
        #Save results to CSV file
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Header
                writer.writerow([
                    'Hostname', 'Port', 'Status', 'Error', 'Subject_CN', 'Issuer_CN',
                    'Valid_From', 'Valid_Until', 'Days_Until_Expiry', 'Certificate_Status',
                    'TLS_Version', 'Cipher_Suite', 'SAN_Count', 'Serial_Number'
                ])
                
                # Data rows
                for result in results:
                    cert = result.get('certificate', {})
                    subject = cert.get('subject', {})
                    issuer = cert.get('issuer', {})
                    cipher = cert.get('cipher', [])
                    
                    writer.writerow([
                        result['hostname'],
                        result['port'],
                        result['status'],
                        result.get('error', ''),
                        subject.get('commonName', ''),
                        issuer.get('commonName', ''),
                        cert.get('not_before_str', ''),
                        cert.get('not_after_str', ''),
                        cert.get('days_until_expiry', ''),
                        cert.get('status', ''),
                        cert.get('version', ''),
                        cipher[0] if cipher and len(cipher) > 0 else '',
                        len(cert.get('san', [])),
                        cert.get('serial_number', '')
                    ])
            
            print(f"Results saved to CSV: {filename}")
            
        except Exception as e:
            print(f"Error saving CSV file: {e}")
    
    def monitor_certificates(self, hosts, check_interval=3600):
        #Continuously monitor certificates
        print(f"Starting certificate monitoring (check every {check_interval} seconds)")
        print("Press Ctrl+C to stop...")
        
        try:
            while True:
                print(f"\n[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Checking certificates...")
                
                results = self.check_multiple_hosts(hosts)
                
                # Check for alerts
                for result in results:
                    if result['status'] == 'success':
                        cert = result['certificate']
                        days_until_expiry = cert.get('days_until_expiry', 999)
                        hostname = result['hostname']
                        port = result['port']
                        
                        if days_until_expiry < 0:
                            print(f"[X] ALERT: {hostname}:{port} certificate EXPIRED!")
                        elif days_until_expiry <= 7:
                            print(f"[!] WARNING: {hostname}:{port} certificate expires in {days_until_expiry} days!")
                        elif days_until_expiry <= 30:
                            print(f"[#] INFO: {hostname}:{port} certificate expires in {days_until_expiry} days")
                
                print(f"Next check in {check_interval} seconds...")
                time.sleep(check_interval)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")

def main():
    parser = argparse.ArgumentParser(description="SSL Certificate Checker")
    parser.add_argument('hosts', nargs='*', help='Hostnames or URLs to check')
    parser.add_argument('-f', '--file', help='File containing list of hosts')
    parser.add_argument('-p', '--port', type=int, default=443, help='Port number (default: 443)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Connection timeout in seconds')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of worker threads')
    parser.add_argument('--json', help='Save results to JSON file')
    parser.add_argument('--csv', help='Save results to CSV file')
    parser.add_argument('--summary', action='store_true', help='Show summary report')
    parser.add_argument('--monitor', type=int, help='Monitor mode with check interval in seconds')
    parser.add_argument('--expiring', type=int, help='Show certificates expiring within N days')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not args.hosts and not args.file:
        parser.print_help()
        return
    
    checker = SSLChecker()
    checker.timeout = args.timeout
    
    # Determine hosts to check
    hosts_to_check = []
    
    if args.file:
        hosts_to_check.extend(checker.load_hosts_from_file(args.file))
    
    if args.hosts:
        for host in args.hosts:
            if ':' in host and not host.startswith('http'):
                hostname, port = host.split(':', 1)
                hosts_to_check.append({'hostname': hostname, 'port': int(port)})
            else:
                hosts_to_check.append({'hostname': host, 'port': args.port})
    
    if not hosts_to_check:
        print("No valid hosts to check")
        return
    
    # Monitor mode
    if args.monitor:
        checker.monitor_certificates(hosts_to_check, args.monitor)
        return
    
    # Check certificates
    print(f"Checking SSL certificates for {len(hosts_to_check)} hosts...")
    results = checker.check_multiple_hosts(hosts_to_check, args.workers)
    
    # Filter results if expiring filter is specified
    if args.expiring is not None:
        filtered_results = []
        for result in results:
            if result['status'] == 'success':
                days_until_expiry = result['certificate'].get('days_until_expiry', 999)
                if days_until_expiry <= args.expiring:
                    filtered_results.append(result)
        results = filtered_results
        print(f"\nShowing certificates expiring within {args.expiring} days:")
    
    # Output results
    if args.verbose:
        for result in results:
            checker.print_result(result)
    
    if args.summary or not args.verbose:
        checker.generate_summary_report(results)
    
    # Save results
    if args.json:
        checker.save_results_json(results, args.json)
    
    if args.csv:
        checker.save_results_csv(results, args.csv)

if __name__ == "__main__":
    main()