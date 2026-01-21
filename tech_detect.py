#!/usr/bin/env python3
import requests
import json
import re
from bs4 import BeautifulSoup
from datetime import datetime
from colorama import Fore, Style, init
import argparse
import sys
import warnings
warnings.filterwarnings('ignore')

init(autoreset=True)

class TechDetector:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url if target_url.startswith('http') else f'http://{target_url}'
        self.verbose = verbose
        self.last_headers = {}
        self.last_html = ""
        self.technologies = {
            'server': [],
            'cms': [],
            'frameworks': [],
            'languages': [],
            'analytics': [],
            'cdn': [],
            'os': [],
            'versions': {},
            'misc': []
        }
        
    def log(self, message, level='info'):
        """Logging with verbosity control"""
        if self.verbose or level == 'error':
            timestamp = datetime.now().strftime('%H:%M:%S')
            colors = {'info': Fore.CYAN, 'success': Fore.GREEN, 'error': Fore.RED, 'warning': Fore.YELLOW}
            print(f"[{timestamp}] {colors.get(level, '')}{message}{Style.RESET_ALL}")
    
    def detect_os_from_headers(self):
        """Detect Operating System from HTTP headers"""
        self.log("Detecting Operating System...")
        
        if not self.last_headers:
            return
        
        server = self.last_headers.get('Server', '').lower()
        powered_by = self.last_headers.get('X-Powered-By', '').lower()
        
        # Linux distribution detection
        if 'ubuntu' in server or 'ubuntu' in powered_by:
            # Extract version if available
            match = re.search(r'ubuntu[\s/]*([\d.]+)?', server + ' ' + powered_by, re.I)
            if match and match.group(1):
                self.technologies['os'].append(f'Linux (Ubuntu {match.group(1)})')
            else:
                self.technologies['os'].append('Linux (Ubuntu)')
            self.log("OS: Ubuntu Linux detected", 'success')
        
        elif 'debian' in server or 'debian' in powered_by:
            self.technologies['os'].append('Linux (Debian)')
            self.log("OS: Debian Linux detected", 'success')
        
        elif 'centos' in server or 'centos' in powered_by:
            self.technologies['os'].append('Linux (CentOS)')
            self.log("OS: CentOS Linux detected", 'success')
        
        elif 'red hat' in server or 'rhel' in server:
            self.technologies['os'].append('Linux (Red Hat)')
            self.log("OS: Red Hat Linux detected", 'success')
        
        elif 'fedora' in server:
            self.technologies['os'].append('Linux (Fedora)')
            self.log("OS: Fedora Linux detected", 'success')
        
        # Windows detection
        elif 'microsoft' in server or 'iis' in server or 'aspnet' in powered_by:
            if 'iis' in server:
                # Extract IIS version
                match = re.search(r'iis/([\d.]+)', server, re.I)
                if match:
                    self.technologies['os'].append(f'Windows Server (IIS {match.group(1)})')
                else:
                    self.technologies['os'].append('Windows Server')
            else:
                self.technologies['os'].append('Windows Server')
            self.log("OS: Windows Server detected", 'success')
        
        # Unix/BSD detection
        elif 'unix' in server or 'bsd' in server:
            self.technologies['os'].append('Unix/BSD')
            self.log("OS: Unix/BSD detected", 'success')
        
        # Generic Linux if nginx/apache without specific distro
        elif any(x in server for x in ['nginx', 'apache']) and not self.technologies['os']:
            self.technologies['os'].append('Linux (Generic)')
            self.log("OS: Linux detected", 'success')
    
    def extract_versions(self):
        """Extract version numbers from headers and HTML"""
        self.log("Extracting version information...")
        
        # Server version from headers
        if 'Server' in self.last_headers:
            server = self.last_headers['Server']
            
            # nginx version
            match = re.search(r'nginx/([\d.]+)', server, re.I)
            if match:
                self.technologies['versions']['nginx'] = match.group(1)
                self.log(f"Version: nginx {match.group(1)}", 'success')
            
            # Apache version
            match = re.search(r'apache/([\d.]+)', server, re.I)
            if match:
                self.technologies['versions']['Apache'] = match.group(1)
                self.log(f"Version: Apache {match.group(1)}", 'success')
            
            # IIS version
            match = re.search(r'iis/([\d.]+)', server, re.I)
            if match:
                self.technologies['versions']['IIS'] = match.group(1)
                self.log(f"Version: IIS {match.group(1)}", 'success')
        
        # PHP version from headers
        if 'X-Powered-By' in self.last_headers:
            powered = self.last_headers['X-Powered-By']
            match = re.search(r'php/([\d.]+)', powered, re.I)
            if match:
                self.technologies['versions']['PHP'] = match.group(1)
                self.log(f"Version: PHP {match.group(1)}", 'success')
            
            # ASP.NET version
            match = re.search(r'asp\.net/([\d.]+)', powered, re.I)
            if match:
                self.technologies['versions']['ASP.NET'] = match.group(1)
                self.log(f"Version: ASP.NET {match.group(1)}", 'success')
        
        # Versions from HTML content
        if self.last_html:
            # WordPress version
            wp_match = re.search(r'wp-(?:content|includes).*?ver=([\d.]+)', self.last_html)
            if wp_match:
                self.technologies['versions']['WordPress'] = wp_match.group(1)
                self.log(f"Version: WordPress {wp_match.group(1)}", 'success')
            
            # jQuery version
            jquery_match = re.search(r'jquery[.-]?([\d.]+)(?:\.min)?\.js', self.last_html, re.I)
            if jquery_match:
                self.technologies['versions']['jQuery'] = jquery_match.group(1)
                self.log(f"Version: jQuery {jquery_match.group(1)}", 'success')
            
            # Bootstrap version
            bootstrap_match = re.search(r'bootstrap[/-]?([\d.]+)', self.last_html, re.I)
            if bootstrap_match:
                self.technologies['versions']['Bootstrap'] = bootstrap_match.group(1)
                self.log(f"Version: Bootstrap {bootstrap_match.group(1)}", 'success')
            
            # React version
            react_match = re.search(r'react[.-]?([\d.]+)', self.last_html, re.I)
            if react_match:
                self.technologies['versions']['React'] = react_match.group(1)
                self.log(f"Version: React {react_match.group(1)}", 'success')
            
            # Vue.js version
            vue_match = re.search(r'vue[.-]?([\d.]+)', self.last_html, re.I)
            if vue_match:
                self.technologies['versions']['Vue.js'] = vue_match.group(1)
                self.log(f"Version: Vue.js {vue_match.group(1)}", 'success')
            
            # Angular version
            angular_match = re.search(r'angular[.-]?([\d.]+)', self.last_html, re.I)
            if angular_match:
                self.technologies['versions']['Angular'] = angular_match.group(1)
                self.log(f"Version: Angular {angular_match.group(1)}", 'success')
    
    def detect_from_headers(self):
        """Detect technologies from HTTP headers"""
        self.log("Analyzing HTTP headers...")
        try:
            response = requests.get(self.target_url, timeout=10, allow_redirects=True, verify=False)
            self.last_headers = response.headers
            headers = response.headers
            
            # Server detection
            if 'Server' in headers:
                server_full = headers['Server']
                # Extract just the server name without version
                server_name = re.split(r'[/\s]', server_full)[0]
                self.technologies['server'].append(server_name)
                self.log(f"Server: {server_full}", 'success')
            
            # X-Powered-By detection
            if 'X-Powered-By' in headers:
                powered = headers['X-Powered-By']
                # Extract language name
                lang_name = re.split(r'[/\s]', powered)[0]
                self.technologies['languages'].append(lang_name)
                self.log(f"Powered by: {powered}", 'success')
            
            # CDN detection
            cdn_headers = ['CF-RAY', 'X-CDN', 'X-Akamai-Transformed']
            for header in cdn_headers:
                if header in headers:
                    if 'CF-RAY' in header:
                        self.technologies['cdn'].append('Cloudflare')
                    elif 'Akamai' in header:
                        self.technologies['cdn'].append('Akamai')
                    self.log(f"CDN detected: {header}", 'success')
            
            return response.text
            
        except requests.exceptions.RequestException as e:
            self.log(f"Error fetching headers: {e}", 'error')
            return None
    
    def detect_from_html(self, html_content):
        """Detect technologies from HTML content"""
        if not html_content:
            return
        
        self.log("Analyzing HTML content...")
        self.last_html = html_content
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # WordPress detection
        if soup.find('meta', {'name': 'generator', 'content': re.compile('WordPress', re.I)}):
            self.technologies['cms'].append('WordPress')
            self.log("CMS: WordPress detected", 'success')
        
        # Check for wp-content in links
        if soup.find('link', href=re.compile('/wp-content/')):
            if 'WordPress' not in self.technologies['cms']:
                self.technologies['cms'].append('WordPress')
        
        # Joomla detection
        if soup.find('meta', {'name': 'generator', 'content': re.compile('Joomla', re.I)}):
            self.technologies['cms'].append('Joomla')
            self.log("CMS: Joomla detected", 'success')
        
        # Drupal detection
        if soup.find('meta', {'name': 'Generator', 'content': re.compile('Drupal', re.I)}):
            self.technologies['cms'].append('Drupal')
            self.log("CMS: Drupal detected", 'success')
        
        # Framework detection - React
        if 'react' in html_content.lower() or soup.find('div', id='root'):
            self.technologies['frameworks'].append('React')
            self.log("Framework: React detected", 'success')
        
        # Vue.js
        if soup.find(attrs={'v-app': True}) or 'vue' in html_content.lower():
            self.technologies['frameworks'].append('Vue.js')
            self.log("Framework: Vue.js detected", 'success')
        
        # Angular
        if soup.find(attrs={'ng-app': True}) or 'ng-version' in html_content:
            self.technologies['frameworks'].append('Angular')
            self.log("Framework: Angular detected", 'success')
        
        # Bootstrap
        if 'bootstrap' in html_content.lower():
            self.technologies['frameworks'].append('Bootstrap')
        
        # Analytics detection
        if 'google-analytics.com' in html_content or 'gtag' in html_content:
            self.technologies['analytics'].append('Google Analytics')
            self.log("Analytics: Google Analytics detected", 'success')
        
        if 'facebook.com' in html_content and 'fbq' in html_content:
            self.technologies['analytics'].append('Facebook Pixel')
        
        # jQuery
        if 'jquery' in html_content.lower():
            self.technologies['frameworks'].append('jQuery')
    
    def detect_from_cookies(self):
        """Detect technologies from cookies"""
        self.log("Analyzing cookies...")
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            cookies = response.cookies
            
            for cookie in cookies:
                # PHP session
                if 'PHPSESSID' in cookie.name:
                    if 'PHP' not in self.technologies['languages']:
                        self.technologies['languages'].append('PHP')
                        self.log("Language: PHP detected (via cookie)", 'success')
                
                # ASP.NET
                if 'ASP.NET' in cookie.name:
                    self.technologies['languages'].append('ASP.NET')
                    self.log("Language: ASP.NET detected (via cookie)", 'success')
                
                # Laravel
                if 'laravel_session' in cookie.name:
                    self.technologies['frameworks'].append('Laravel')
                    self.log("Framework: Laravel detected (via cookie)", 'success')
        
        except Exception as e:
            self.log(f"Error analyzing cookies: {e}", 'error')
    
    def use_wappalyzer(self):
        """Use Wappalyzer library for comprehensive detection"""
        self.log("Running Wappalyzer analysis...")
        try:
            from Wappalyzer import Wappalyzer, WebPage
            
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(self.target_url)
            detected = wappalyzer.analyze(webpage)
            
            for tech in detected:
                self.technologies['misc'].append(tech)
                self.log(f"Wappalyzer detected: {tech}", 'success')
        
        except Exception as e:
            self.log(f"Wappalyzer analysis failed: {e}", 'warning')
    
    def run_detection(self):
        """Main detection orchestrator"""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"{Fore.YELLOW}Technology Detection for: {self.target_url}")
        print(f"{Fore.YELLOW}{'='*60}\n")
        
        # Run all detection methods
        html_content = self.detect_from_headers()
        self.detect_from_html(html_content)
        self.detect_from_cookies()
        
        # NEW: OS and Version detection
        self.detect_os_from_headers()
        self.extract_versions()
        
        self.use_wappalyzer()
        
        return self.get_results()
    
    def get_results(self):
        """Format and return results"""
        # Remove duplicates
        for category in self.technologies:
            if isinstance(self.technologies[category], list):
                self.technologies[category] = list(set(self.technologies[category]))
        
        return self.technologies
    
    def print_results(self):
        """Pretty print results"""
        results = self.get_results()
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}DETECTED TECHNOLOGIES")
        print(f"{Fore.GREEN}{'='*60}\n")
        
        categories = {
            'os': 'Operating System',
            'server': 'Web Server',
            'cms': 'Content Management System',
            'frameworks': 'Frameworks & Libraries',
            'languages': 'Programming Languages',
            'analytics': 'Analytics & Tracking',
            'cdn': 'CDN & Hosting',
            'versions': 'Version Information',
            'misc': 'Other Technologies'
        }
        
        for key, label in categories.items():
            if results[key]:
                print(f"{Fore.CYAN}{label}:")
                if isinstance(results[key], dict):
                    # For versions dictionary
                    for tech, version in results[key].items():
                        print(f"  • {tech}: {version}")
                else:
                    # For lists
                    for tech in results[key]:
                        print(f"  • {tech}")
                print()
        
        if not any(results.values()):
            print(f"{Fore.YELLOW}No technologies detected.")
    
    def generate_report(self, output_file='tech_report.txt'):
        """Generate text report"""
        results = self.get_results()
        
        with open(output_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write(f"Technology Detection Report\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")
            
            categories = {
                'os': 'Operating System',
                'server': 'Web Server',
                'cms': 'Content Management System',
                'frameworks': 'Frameworks & Libraries',
                'languages': 'Programming Languages',
                'analytics': 'Analytics & Tracking',
                'cdn': 'CDN & Hosting',
                'versions': 'Version Information',
                'misc': 'Other Technologies'
            }
            
            for key, label in categories.items():
                if results[key]:
                    f.write(f"{label}:\n")
                    if isinstance(results[key], dict):
                        for tech, version in results[key].items():
                            f.write(f"  - {tech}: {version}\n")
                    else:
                        for tech in results[key]:
                            f.write(f"  - {tech}\n")
                    f.write("\n")
        
        self.log(f"Report saved to: {output_file}", 'success')

def main():
    parser = argparse.ArgumentParser(description='Technology Detection Module with OS & Version Detection')
    parser.add_argument('target', help='Target URL or domain')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output report file', default='reports/tech_report.txt')
    
    args = parser.parse_args()
    
    detector = TechDetector(args.target, verbose=args.verbose)
    detector.run_detection()
    detector.print_results()
    detector.generate_report(args.output)

if __name__ == '__main__':
    main()