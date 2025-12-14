"""
Visitor Traffic Quality Analyzer
Flask-based web application to analyze visitor authenticity and detect bots, proxies, VPNs
"""

from flask import Flask, render_template, request, jsonify
import hashlib
import json
import time
from datetime import datetime
from user_agents import parse
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'visitor-analyzer-secret-key-2024'


class VisitorAnalyzer:
    """Comprehensive visitor analysis engine"""

    def __init__(self, request_data):
        self.request = request_data
        self.ip = self.get_client_ip()
        self.headers = dict(request_data.headers)
        self.user_agent = request_data.headers.get('User-Agent', '')
        self.fingerprint = {}
        self.results = {}

    def get_client_ip(self):
        """Get real client IP address"""
        if self.request.headers.get('X-Forwarded-For'):
            return self.request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif self.request.headers.get('X-Real-IP'):
            return self.request.headers.get('X-Real-IP')
        else:
            return self.request.remote_addr

    def analyze(self, client_fingerprint=None):
        """Run complete visitor analysis"""
        self.fingerprint = client_fingerprint or {}

        self.results = {
            'timestamp': datetime.now().isoformat(),
            'ip_address': self.ip,
            'basic_info': self.analyze_basic_info(),
            'header_analysis': self.analyze_headers(),
            'user_agent_analysis': self.analyze_user_agent(),
            'browser_fingerprint': self.analyze_browser_fingerprint(),
            'proxy_vpn_detection': self.detect_proxy_vpn(),
            'automation_detection': self.detect_automation(),
            'consistency_checks': self.check_consistency(),
            'threat_indicators': self.detect_threats(),
            'tls_analysis': self.analyze_tls(),
            'behavioral_signals': self.analyze_behavioral_signals(),
            'advanced_behavioral': self.analyze_advanced_behavioral(),
            'vm_detection': self.analyze_vm_detection(),
            'browser_extensions': self.analyze_extensions(),
            'timing_analysis': self.analyze_timing(),
            'css_media_queries': self.analyze_css_media(),
            'speech_synthesis': self.analyze_speech(),
            'client_hints': self.analyze_client_hints(),
        }

        # Calculate overall risk score
        self.results['risk_assessment'] = self.calculate_risk_score()

        return self.results

    def analyze_basic_info(self):
        """Analyze basic visitor information"""
        return {
            'ip_address': self.ip,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'method': self.request.method,
            'path': self.request.path,
            'protocol': self.request.environ.get('SERVER_PROTOCOL', 'Unknown'),
            'port': self.request.environ.get('SERVER_PORT', 'Unknown'),
            'is_secure': self.request.is_secure,
        }

    def analyze_headers(self):
        """Analyze HTTP headers for anomalies"""
        header_analysis = {
            'total_headers': len(self.headers),
            'suspicious_patterns': [],
            'missing_standard_headers': [],
            'proxy_headers': {},
            'header_quality': 'unknown'
        }

        # Standard browser headers
        standard_headers = [
            'User-Agent', 'Accept', 'Accept-Language',
            'Accept-Encoding', 'Connection', 'Upgrade-Insecure-Requests'
        ]

        for header in standard_headers:
            if header not in self.headers:
                header_analysis['missing_standard_headers'].append(header)

        # Check for proxy/VPN headers
        proxy_indicators = {
            'X-Forwarded-For': self.headers.get('X-Forwarded-For'),
            'X-Real-IP': self.headers.get('X-Real-IP'),
            'Via': self.headers.get('Via'),
            'X-Proxy-ID': self.headers.get('X-Proxy-ID'),
            'Forwarded': self.headers.get('Forwarded'),
            'CF-Connecting-IP': self.headers.get('CF-Connecting-IP'),
            'X-Forwarded-Proto': self.headers.get('X-Forwarded-Proto'),
        }

        header_analysis['proxy_headers'] = {k: v for k, v in proxy_indicators.items() if v}

        # Check header order and quality
        if len(self.headers) < 5:
            header_analysis['suspicious_patterns'].append('Too few headers (possible bot)')

        # Check Accept header
        accept = self.headers.get('Accept', '')
        if accept == '*/*':
            header_analysis['suspicious_patterns'].append('Generic Accept header (typical of bots)')
        elif not accept:
            header_analysis['suspicious_patterns'].append('Missing Accept header')

        # Check Accept-Language
        if 'Accept-Language' not in self.headers:
            header_analysis['suspicious_patterns'].append('Missing Accept-Language header')

        # Check for automation headers
        automation_headers = ['Selenium', 'PhantomJS', 'Headless', 'Python', 'curl', 'wget']
        for auto_header in automation_headers:
            for header_name, header_value in self.headers.items():
                if auto_header.lower() in str(header_value).lower():
                    header_analysis['suspicious_patterns'].append(f'Automation signature: {auto_header}')

        # Determine header quality
        missing_count = len(header_analysis['missing_standard_headers'])
        suspicious_count = len(header_analysis['suspicious_patterns'])

        if suspicious_count > 2 or missing_count > 3:
            header_analysis['header_quality'] = 'bad'
        elif suspicious_count > 0 or missing_count > 1:
            header_analysis['header_quality'] = 'suspicious'
        else:
            header_analysis['header_quality'] = 'good'

        return header_analysis

    def analyze_user_agent(self):
        """Detailed User-Agent analysis"""
        ua_analysis = {
            'raw_user_agent': self.user_agent,
            'parsed': {},
            'suspicious_patterns': [],
            'quality': 'unknown'
        }

        if not self.user_agent:
            ua_analysis['suspicious_patterns'].append('Missing User-Agent')
            ua_analysis['quality'] = 'bad'
            return ua_analysis

        # Parse User-Agent
        user_agent = parse(self.user_agent)
        ua_analysis['parsed'] = {
            'browser': user_agent.browser.family,
            'browser_version': user_agent.browser.version_string,
            'os': user_agent.os.family,
            'os_version': user_agent.os.version_string,
            'device': user_agent.device.family,
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_pc': user_agent.is_pc,
            'is_bot': user_agent.is_bot,
        }

        # Check for bot signatures
        bot_keywords = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python',
                        'java', 'php', 'ruby', 'go-http', 'postman', 'insomnia']

        ua_lower = self.user_agent.lower()
        for keyword in bot_keywords:
            if keyword in ua_lower:
                ua_analysis['suspicious_patterns'].append(f'Bot keyword detected: {keyword}')

        # Check User-Agent length
        if len(self.user_agent) < 50:
            ua_analysis['suspicious_patterns'].append('User-Agent too short')
        elif len(self.user_agent) > 500:
            ua_analysis['suspicious_patterns'].append('User-Agent abnormally long')

        # Check for common browser signatures
        if not any(browser in ua_lower for browser in ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera']):
            ua_analysis['suspicious_patterns'].append('Missing common browser identifiers')

        # Check version string count
        version_count = self.user_agent.count('/')
        if version_count > 10:
            ua_analysis['suspicious_patterns'].append('Excessive version strings')

        # Determine quality
        if user_agent.is_bot or len(ua_analysis['suspicious_patterns']) > 2:
            ua_analysis['quality'] = 'bad'
        elif len(ua_analysis['suspicious_patterns']) > 0:
            ua_analysis['quality'] = 'suspicious'
        else:
            ua_analysis['quality'] = 'good'

        return ua_analysis

    def analyze_browser_fingerprint(self):
        """Analyze browser fingerprint for manipulation"""
        fp_analysis = {
            'fingerprint_data': self.fingerprint,
            'inconsistencies': [],
            'manipulation_indicators': [],
            'quality': 'unknown'
        }

        if not self.fingerprint:
            fp_analysis['inconsistencies'].append({
                'message': 'No fingerprint data received',
                'value': 'null'
            })
            fp_analysis['quality'] = 'bad'
            return fp_analysis

        # Check for WebDriver
        if self.fingerprint.get('webdriver'):
            fp_analysis['manipulation_indicators'].append({
                'message': 'WebDriver detected (Selenium/Automation)',
                'property': 'navigator.webdriver',
                'value': str(self.fingerprint.get('webdriver'))
            })

        # Check for headless browser
        if self.fingerprint.get('headless'):
            fp_analysis['manipulation_indicators'].append({
                'message': 'Headless browser detected',
                'property': 'headless',
                'value': 'true'
            })

        # Check plugins consistency
        plugins = self.fingerprint.get('plugins', 0)
        if plugins == 0:
            fp_analysis['inconsistencies'].append({
                'message': 'No browser plugins (unusual for real browsers)',
                'property': 'navigator.plugins.length',
                'value': str(plugins)
            })

        # Check language consistency
        languages = self.fingerprint.get('languages', [])
        if not languages or len(languages) == 0:
            fp_analysis['inconsistencies'].append({
                'message': 'No languages detected',
                'property': 'navigator.languages',
                'value': str(languages)
            })

        # Check canvas fingerprint
        canvas_value = self.fingerprint.get('canvas')
        if canvas_value == 'blocked' or not canvas_value:
            fp_analysis['manipulation_indicators'].append({
                'message': 'Canvas fingerprinting blocked or unavailable',
                'property': 'canvas',
                'value': str(canvas_value) if canvas_value else 'null'
            })

        # Check WebGL
        webgl_vendor = self.fingerprint.get('webgl_vendor')
        webgl_renderer = self.fingerprint.get('webgl_renderer')
        if not webgl_vendor or not webgl_renderer:
            fp_analysis['inconsistencies'].append({
                'message': 'WebGL information missing',
                'property': 'webgl_vendor/renderer',
                'value': f'{webgl_vendor or "null"} / {webgl_renderer or "null"}'
            })

        # Check screen resolution
        screen_width = self.fingerprint.get('screen_width', 0)
        screen_height = self.fingerprint.get('screen_height', 0)

        if screen_width == 0 or screen_height == 0:
            fp_analysis['inconsistencies'].append({
                'message': 'Invalid screen dimensions',
                'property': 'screen.width x screen.height',
                'value': f'{screen_width} x {screen_height}'
            })
        elif screen_width < 800 or screen_height < 600:
            fp_analysis['inconsistencies'].append({
                'message': f'Unusual screen resolution (too small)',
                'property': 'screen.width x screen.height',
                'value': f'{screen_width} x {screen_height}'
            })

        # Check timezone
        timezone = self.fingerprint.get('timezone')
        if not timezone:
            fp_analysis['inconsistencies'].append({
                'message': 'Timezone not detected',
                'property': 'timezone',
                'value': 'null'
            })

        # Check for automation artifacts
        automation_props = ['__nightmare', '__phantomas', 'callPhantom', '_phantom',
                           '__selenium', '__webdriver', '__driver']

        for prop in automation_props:
            if self.fingerprint.get(prop):
                fp_analysis['manipulation_indicators'].append({
                    'message': f'Automation artifact detected',
                    'property': f'window.{prop}',
                    'value': str(self.fingerprint.get(prop))
                })

        # Determine quality
        manipulation_count = len(fp_analysis['manipulation_indicators'])
        inconsistency_count = len(fp_analysis['inconsistencies'])

        if manipulation_count > 0:
            fp_analysis['quality'] = 'bad'
        elif inconsistency_count > 3:
            fp_analysis['quality'] = 'suspicious'
        elif inconsistency_count > 0:
            fp_analysis['quality'] = 'acceptable'
        else:
            fp_analysis['quality'] = 'good'

        return fp_analysis

    def detect_proxy_vpn(self):
        """Detect proxy and VPN usage"""
        detection = {
            'indicators': [],
            'proxy_headers_found': [],
            'risk_level': 'unknown',
            'is_proxy_likely': False
        }

        # Check for proxy headers
        proxy_headers = ['X-Forwarded-For', 'X-Real-IP', 'Via', 'Forwarded',
                        'X-Proxy-ID', 'CF-Connecting-IP', 'X-Forwarded-Proto']

        for header in proxy_headers:
            if header in self.headers:
                detection['proxy_headers_found'].append(header)
                detection['indicators'].append({
                    'message': f'Proxy header present',
                    'header': header,
                    'value': self.headers.get(header)
                })

        # Check for multiple IPs in X-Forwarded-For
        xff = self.headers.get('X-Forwarded-For', '')
        if ',' in xff:
            ip_list = xff.split(',')
            ip_count = len(ip_list)
            detection['indicators'].append({
                'message': f'Multiple IPs in proxy chain',
                'header': 'X-Forwarded-For',
                'value': f'{ip_count} IPs: {xff}'
            })
            detection['is_proxy_likely'] = True

        # Check for VIA header (explicit proxy)
        if 'Via' in self.headers:
            detection['indicators'].append({
                'message': 'Via header indicates explicit proxy',
                'header': 'Via',
                'value': self.headers.get('Via')
            })
            detection['is_proxy_likely'] = True

        # Check IP characteristics from fingerprint
        if self.fingerprint.get('ip_info'):
            ip_info = self.fingerprint['ip_info']
            if ip_info.get('is_datacenter'):
                detection['indicators'].append({
                    'message': 'IP from datacenter (hosting provider)',
                    'property': 'ip_info.is_datacenter',
                    'value': f'IP: {self.ip}'
                })
            if ip_info.get('is_vpn'):
                detection['indicators'].append({
                    'message': 'VPN detected',
                    'property': 'ip_info.is_vpn',
                    'value': f'IP: {self.ip}'
                })
            if ip_info.get('is_proxy'):
                detection['indicators'].append({
                    'message': 'Proxy detected',
                    'property': 'ip_info.is_proxy',
                    'value': f'IP: {self.ip}'
                })
            if ip_info.get('is_tor'):
                detection['indicators'].append({
                    'message': 'Tor exit node detected',
                    'property': 'ip_info.is_tor',
                    'value': f'IP: {self.ip}'
                })

        # Check WebRTC leaks
        webrtc_ips = self.fingerprint.get('webrtc_ips', [])
        if webrtc_ips and len(webrtc_ips) > 0:
            if self.ip not in webrtc_ips:
                detection['indicators'].append({
                    'message': 'WebRTC IP mismatch (possible VPN/proxy leak)',
                    'property': 'webrtc_ips',
                    'value': f'Request IP: {self.ip}, WebRTC IPs: {", ".join(webrtc_ips)}'
                })

        # Determine risk level
        indicator_count = len(detection['indicators'])
        if indicator_count > 3 or detection['is_proxy_likely']:
            detection['risk_level'] = 'high'
        elif indicator_count > 1:
            detection['risk_level'] = 'medium'
        elif indicator_count > 0:
            detection['risk_level'] = 'low'
        else:
            detection['risk_level'] = 'none'

        return detection

    def detect_automation(self):
        """Detect browser automation and bots"""
        detection = {
            'indicators': [],
            'automation_type': [],
            'confidence': 'unknown'
        }

        # Check for WebDriver
        if self.fingerprint.get('webdriver'):
            detection['indicators'].append({
                'message': 'Navigator.webdriver = true',
                'property': 'navigator.webdriver',
                'value': str(self.fingerprint.get('webdriver'))
            })
            detection['automation_type'].append('Selenium/WebDriver')

        # Check for common automation properties
        automation_checks = {
            '__webdriver': 'Selenium',
            '__driver': 'WebDriver',
            '__selenium': 'Selenium',
            '__nightmare': 'Nightmare.js',
            '__phantomas': 'PhantomJS',
            'callPhantom': 'PhantomJS',
            '_phantom': 'PhantomJS',
            'domAutomation': 'Chrome Extension',
            'domAutomationController': 'Chrome Automation'
        }

        for prop, tool in automation_checks.items():
            if self.fingerprint.get(prop):
                detection['indicators'].append({
                    'message': f'Automation property detected',
                    'property': f'window.{prop}',
                    'value': str(self.fingerprint.get(prop)),
                    'tool': tool
                })
                if tool not in detection['automation_type']:
                    detection['automation_type'].append(tool)

        # Check Chrome-specific automation
        if self.fingerprint.get('chrome'):
            if not self.fingerprint.get('chrome_runtime'):
                detection['indicators'].append({
                    'message': 'Chrome detected but chrome.runtime missing',
                    'property': 'window.chrome.runtime',
                    'value': 'undefined (suspicious)'
                })

        # Check for permissions inconsistency
        if self.fingerprint.get('permissions_query_unavailable'):
            detection['indicators'].append({
                'message': 'Permissions API blocked (common in automation)',
                'property': 'navigator.permissions.query',
                'value': 'unavailable'
            })

        # Check notification permissions
        if self.fingerprint.get('notification_permission') == 'denied':
            detection['indicators'].append({
                'message': 'Notifications denied (automation default)',
                'property': 'Notification.permission',
                'value': 'denied'
            })

        # Determine confidence
        indicator_count = len(detection['indicators'])
        if indicator_count > 3:
            detection['confidence'] = 'very_high'
        elif indicator_count > 1:
            detection['confidence'] = 'high'
        elif indicator_count > 0:
            detection['confidence'] = 'medium'
        else:
            detection['confidence'] = 'low'

        return detection

    def check_consistency(self):
        """Check for inconsistencies between different data points"""
        consistency = {
            'checks': [],
            'passed': 0,
            'failed': 0,
            'warnings': 0
        }

        # UA vs Fingerprint OS consistency
        if self.fingerprint.get('platform'):
            fp_platform = self.fingerprint['platform'].lower()
            user_agent = parse(self.user_agent)
            ua_os = user_agent.os.family.lower()

            if 'win' in fp_platform and 'windows' not in ua_os:
                consistency['checks'].append({
                    'check': 'OS Consistency',
                    'status': 'failed',
                    'details': f'Platform says {fp_platform} but UA says {ua_os}'
                })
                consistency['failed'] += 1
            elif 'mac' in fp_platform and 'mac' not in ua_os:
                consistency['checks'].append({
                    'check': 'OS Consistency',
                    'status': 'failed',
                    'details': f'Platform mismatch: {fp_platform} vs {ua_os}'
                })
                consistency['failed'] += 1
            else:
                consistency['checks'].append({
                    'check': 'OS Consistency',
                    'status': 'passed',
                    'details': 'OS matches between UA and fingerprint'
                })
                consistency['passed'] += 1

        # Language consistency
        fp_language = self.fingerprint.get('language', '')
        header_language = self.headers.get('Accept-Language', '')

        if fp_language and header_language:
            fp_lang_code = fp_language.split('-')[0].lower()
            if fp_lang_code not in header_language.lower():
                consistency['checks'].append({
                    'check': 'Language Consistency',
                    'status': 'warning',
                    'details': f'Language mismatch: FP={fp_language}, Header={header_language}'
                })
                consistency['warnings'] += 1
            else:
                consistency['checks'].append({
                    'check': 'Language Consistency',
                    'status': 'passed',
                    'details': 'Languages match'
                })
                consistency['passed'] += 1

        # Timezone consistency
        timezone_offset = self.fingerprint.get('timezone_offset')
        if timezone_offset is not None:
            # Basic timezone validation
            if timezone_offset < -720 or timezone_offset > 840:
                consistency['checks'].append({
                    'check': 'Timezone Validation',
                    'status': 'failed',
                    'details': f'Invalid timezone offset: {timezone_offset}'
                })
                consistency['failed'] += 1
            else:
                consistency['checks'].append({
                    'check': 'Timezone Validation',
                    'status': 'passed',
                    'details': 'Valid timezone offset'
                })
                consistency['passed'] += 1

        # Hardware concurrency check
        hardware_concurrency = self.fingerprint.get('hardware_concurrency', 0)
        if hardware_concurrency == 0:
            consistency['checks'].append({
                'check': 'Hardware Concurrency',
                'status': 'failed',
                'details': 'No CPU cores reported'
            })
            consistency['failed'] += 1
        elif hardware_concurrency > 32:
            consistency['checks'].append({
                'check': 'Hardware Concurrency',
                'status': 'warning',
                'details': f'Unusual core count: {hardware_concurrency}'
            })
            consistency['warnings'] += 1
        else:
            consistency['checks'].append({
                'check': 'Hardware Concurrency',
                'status': 'passed',
                'details': f'{hardware_concurrency} cores detected'
            })
            consistency['passed'] += 1

        return consistency

    def detect_threats(self):
        """Detect specific threat indicators"""
        threats = {
            'threat_level': 'none',
            'threats_detected': [],
            'risk_factors': []
        }

        # Known bad patterns
        if 'sqlmap' in self.user_agent.lower():
            threats['threats_detected'].append('SQL injection tool detected')

        if 'nikto' in self.user_agent.lower():
            threats['threats_detected'].append('Nikto scanner detected')

        # Check for suspicious paths
        suspicious_paths = ['admin', 'wp-admin', 'phpmyadmin', '.env', 'config', 'backup']
        if any(path in self.request.path.lower() for path in suspicious_paths):
            threats['risk_factors'].append(f'Accessing suspicious path: {self.request.path}')

        # Check request method
        if self.request.method not in ['GET', 'POST']:
            threats['risk_factors'].append(f'Unusual HTTP method: {self.request.method}')

        # Determine threat level
        if len(threats['threats_detected']) > 0:
            threats['threat_level'] = 'critical'
        elif len(threats['risk_factors']) > 2:
            threats['threat_level'] = 'high'
        elif len(threats['risk_factors']) > 0:
            threats['threat_level'] = 'medium'

        return threats

    def analyze_tls(self):
        """Analyze TLS/SSL characteristics"""
        tls_analysis = {
            'protocol': self.request.environ.get('SERVER_PROTOCOL', 'Unknown'),
            'is_secure': self.request.is_secure,
            'cipher_suite': self.request.environ.get('SSL_CIPHER', 'Unknown'),
            'tls_version': self.request.environ.get('SSL_PROTOCOL', 'Unknown'),
        }

        # Add TLS fingerprint from client if available
        if self.fingerprint.get('tls_fingerprint'):
            tls_analysis['client_fingerprint'] = self.fingerprint['tls_fingerprint']

        return tls_analysis

    def analyze_behavioral_signals(self):
        """Analyze behavioral signals"""
        signals = {
            'mouse_movement': self.fingerprint.get('has_mouse_movement', False),
            'keyboard_input': self.fingerprint.get('has_keyboard_input', False),
            'touch_support': self.fingerprint.get('touch_support', False),
            'page_focus': self.fingerprint.get('has_page_focus', True),
            'scroll_behavior': self.fingerprint.get('has_scroll', False),
            'behavioral_score': 'unknown'
        }

        # Calculate behavioral score
        positive_signals = sum([
            signals['mouse_movement'],
            signals['keyboard_input'],
            signals['page_focus'],
            signals['scroll_behavior']
        ])

        if positive_signals >= 3:
            signals['behavioral_score'] = 'human_likely'
        elif positive_signals >= 2:
            signals['behavioral_score'] = 'uncertain'
        else:
            signals['behavioral_score'] = 'bot_likely'

        return signals

    def analyze_advanced_behavioral(self):
        """Analyze advanced mouse, keyboard, and scroll behavior"""
        analysis = {
            'mouse_behavior': {},
            'click_behavior': {},
            'scroll_behavior': {},
            'keyboard_behavior': {},
            'human_likelihood': 'unknown'
        }

        # Mouse behavior analysis
        mouse_data = self.fingerprint.get('mouse_behavior', {})
        if mouse_data:
            analysis['mouse_behavior'] = {
                'total_movements': mouse_data.get('total_movements', 0),
                'average_velocity': float(mouse_data.get('average_velocity', 0)),
                'max_velocity': float(mouse_data.get('max_velocity', 0)),
                'average_acceleration': float(mouse_data.get('average_acceleration', 0)),
                'has_human_curves': mouse_data.get('has_human_curves', False),
                'quality': 'good' if mouse_data.get('has_human_curves') else 'suspicious'
            }

            # Bots typically have very high constant velocity
            if float(mouse_data.get('average_velocity', 0)) > 3000:
                analysis['mouse_behavior']['bot_indicator'] = 'Abnormally high velocity'
            elif float(mouse_data.get('average_velocity', 0)) == 0:
                analysis['mouse_behavior']['bot_indicator'] = 'No mouse movement'

        # Click behavior
        click_data = self.fingerprint.get('click_behavior', {})
        if click_data:
            analysis['click_behavior'] = {
                'total_clicks': click_data.get('total_clicks', 0),
                'average_interval': float(click_data.get('average_click_interval', 0)),
                'rhythm_variance': float(click_data.get('click_rhythm_variance', 0)),
                'quality': 'good' if float(click_data.get('click_rhythm_variance', 0)) > 100 else 'suspicious'
            }

            # Bots have very consistent click intervals (low variance)
            if float(click_data.get('click_rhythm_variance', 0)) < 50:
                analysis['click_behavior']['bot_indicator'] = 'Too consistent (bot-like)'

        # Scroll behavior
        scroll_data = self.fingerprint.get('scroll_behavior', {})
        if scroll_data:
            analysis['scroll_behavior'] = {
                'total_scrolls': scroll_data.get('total_scrolls', 0),
                'average_velocity': float(scroll_data.get('average_scroll_velocity', 0)),
                'has_scrolled': scroll_data.get('has_scrolled', False)
            }

        # Keyboard behavior
        keyboard_data = self.fingerprint.get('keyboard_behavior', {})
        if keyboard_data:
            analysis['keyboard_behavior'] = {
                'average_dwell_time': float(keyboard_data.get('average_dwell_time', 0)),
                'average_flight_time': float(keyboard_data.get('average_flight_time', 0)),
                'typing_rhythm': float(keyboard_data.get('typing_rhythm', 0)),
                'quality': 'good' if float(keyboard_data.get('typing_rhythm', 0)) > 0 else 'unknown'
            }

        # Calculate human likelihood
        human_indicators = 0
        bot_indicators = 0

        if analysis['mouse_behavior'].get('has_human_curves'):
            human_indicators += 2
        if analysis['mouse_behavior'].get('bot_indicator'):
            bot_indicators += 2

        if analysis['click_behavior'].get('rhythm_variance', 0) > 100:
            human_indicators += 1
        if analysis['click_behavior'].get('bot_indicator'):
            bot_indicators += 2

        if human_indicators > bot_indicators:
            analysis['human_likelihood'] = 'high'
        elif bot_indicators > human_indicators:
            analysis['human_likelihood'] = 'low'
        else:
            analysis['human_likelihood'] = 'medium'

        return analysis

    def analyze_vm_detection(self):
        """Analyze virtual machine detection results"""
        vm_data = self.fingerprint.get('vm_detection', {})

        return {
            'vm_likelihood': vm_data.get('vm_likelihood', 'unknown'),
            'indicators': vm_data,
            'total_indicators': sum(1 for v in vm_data.values() if v == True) if isinstance(vm_data, dict) else 0,
            'is_likely_vm': vm_data.get('vm_likelihood') in ['high', 'medium'] if vm_data else False
        }

    def analyze_extensions(self):
        """Analyze browser extensions detection"""
        ext_data = self.fingerprint.get('browser_extensions', {})

        return {
            'total_detected': ext_data.get('total_detected', 0),
            'adblock_detected': ext_data.get('adblock_detected', False),
            'devtools_detected': ext_data.get('react_devtools', False) or ext_data.get('vue_devtools', False),
            'extensions': ext_data,
            'privacy_concerned': ext_data.get('adblock_detected', False) or ext_data.get('privacy_badger', False)
        }

    def analyze_timing(self):
        """Analyze page interaction timing"""
        timing_data = self.fingerprint.get('advanced_timing', {})

        analysis = {
            'page_load_time': timing_data.get('page_load_time', 0),
            'time_to_first_interaction': timing_data.get('time_to_first_interaction'),
            'time_to_first_click': timing_data.get('time_to_first_click'),
            'time_to_first_scroll': timing_data.get('time_to_first_scroll'),
            'suspicion_level': 'none'
        }

        # Bots interact too quickly
        if timing_data.get('time_to_first_click') and timing_data['time_to_first_click'] < 100:
            analysis['suspicion_level'] = 'high'
            analysis['reason'] = 'Clicked too fast (< 100ms)'
        elif timing_data.get('time_to_first_interaction') and timing_data['time_to_first_interaction'] < 50:
            analysis['suspicion_level'] = 'high'
            analysis['reason'] = 'Interacted too fast'

        return analysis

    def analyze_css_media(self):
        """Analyze CSS media query results"""
        css_data = self.fingerprint.get('css_media_queries', {})

        return {
            'total_features': css_data.get('css_media_queries_count', 0) if 'css_media_queries_count' in self.fingerprint else 0,
            'pointer_type': 'fine' if css_data.get('pointer_fine') else ('coarse' if css_data.get('pointer_coarse') else 'none'),
            'hover_capable': css_data.get('hover_hover', False),
            'color_gamut': 'p3' if css_data.get('color_gamut_p3') else ('srgb' if css_data.get('color_gamut_srgb') else 'unknown'),
            'prefers_dark_mode': css_data.get('prefers_color_scheme_dark', False),
            'reduced_motion': css_data.get('prefers_reduced_motion', False),
            'features': css_data
        }

    def analyze_speech(self):
        """Analyze speech synthesis data"""
        speech_data = self.fingerprint.get('speech_synthesis_support', False)

        if not speech_data:
            return {'supported': False}

        return {
            'supported': True,
            'voices_count': self.fingerprint.get('speech_voices_count', 0),
            'voice_hash': self.fingerprint.get('speech_voice_hash', ''),
            'has_voices': self.fingerprint.get('speech_voices_count', 0) > 0,
            'uniqueness': 'high' if self.fingerprint.get('speech_voices_count', 0) > 10 else 'low'
        }

    def analyze_client_hints(self):
        """Analyze Client Hints (new UA standard)"""
        hints = self.fingerprint.get('client_hints', {})

        if not hints:
            return {'supported': False}

        return {
            'supported': True,
            'mobile': hints.get('mobile', False),
            'platform': hints.get('platform', 'unknown'),
            'brands': hints.get('brands', []),
            'high_entropy': self.fingerprint.get('client_hints_high_entropy', {}),
            'architecture': self.fingerprint.get('client_hints_high_entropy', {}).get('architecture'),
            'bitness': self.fingerprint.get('client_hints_high_entropy', {}).get('bitness'),
        }

    def calculate_risk_score(self):
        """Calculate overall risk assessment"""
        risk = {
            'total_score': 0,
            'max_score': 100,
            'risk_level': 'unknown',
            'visitor_quality': 'unknown',
            'is_genuine': True,
            'confidence': 0,
            'red_flags': [],
            'green_flags': []
        }

        # Header analysis scoring
        header_quality = self.results['header_analysis']['header_quality']
        if header_quality == 'bad':
            risk['total_score'] += 25
            risk['red_flags'].append('Poor header quality')
        elif header_quality == 'suspicious':
            risk['total_score'] += 15
            risk['red_flags'].append('Suspicious headers')
        else:
            risk['green_flags'].append('Good header quality')

        # User-Agent scoring
        ua_quality = self.results['user_agent_analysis']['quality']
        if ua_quality == 'bad':
            risk['total_score'] += 20
            risk['red_flags'].append('Bad User-Agent')
        elif ua_quality == 'suspicious':
            risk['total_score'] += 10
            risk['red_flags'].append('Suspicious User-Agent')
        else:
            risk['green_flags'].append('Valid User-Agent')

        # Fingerprint scoring
        fp_quality = self.results['browser_fingerprint']['quality']
        if fp_quality == 'bad':
            risk['total_score'] += 30
            risk['red_flags'].append('Manipulated fingerprint')
            risk['is_genuine'] = False
        elif fp_quality == 'suspicious':
            risk['total_score'] += 15
            risk['red_flags'].append('Suspicious fingerprint')
        else:
            risk['green_flags'].append('Natural fingerprint')

        # Proxy/VPN scoring
        proxy_risk = self.results['proxy_vpn_detection']['risk_level']
        if proxy_risk == 'high':
            risk['total_score'] += 20
            risk['red_flags'].append('Proxy/VPN detected')
        elif proxy_risk == 'medium':
            risk['total_score'] += 10
            risk['red_flags'].append('Possible proxy/VPN')

        # Automation detection
        automation_confidence = self.results['automation_detection']['confidence']
        if automation_confidence in ['very_high', 'high']:
            risk['total_score'] += 25
            risk['red_flags'].append('Automation detected')
            risk['is_genuine'] = False
        elif automation_confidence == 'medium':
            risk['total_score'] += 10
            risk['red_flags'].append('Possible automation')

        # Consistency checks
        consistency = self.results['consistency_checks']
        if consistency['failed'] > 2:
            risk['total_score'] += 15
            risk['red_flags'].append('Multiple consistency failures')
        elif consistency['failed'] > 0:
            risk['total_score'] += 5

        # Threat detection
        threat_level = self.results['threat_indicators']['threat_level']
        if threat_level == 'critical':
            risk['total_score'] += 50
            risk['red_flags'].append('Critical threat detected')
            risk['is_genuine'] = False
        elif threat_level == 'high':
            risk['total_score'] += 30
            risk['red_flags'].append('High threat level')

        # Advanced behavioral analysis
        advanced_behavior = self.results.get('advanced_behavioral', {})
        human_likelihood = advanced_behavior.get('human_likelihood', 'unknown')

        if human_likelihood == 'low':
            risk['total_score'] += 20
            risk['red_flags'].append('Bot-like behavior patterns')
        elif human_likelihood == 'high':
            risk['green_flags'].append('Human-like behavior patterns')

        # Mouse behavior specific
        mouse_behavior = advanced_behavior.get('mouse_behavior', {})
        if mouse_behavior.get('bot_indicator'):
            risk['total_score'] += 10
            risk['red_flags'].append(f'Mouse: {mouse_behavior["bot_indicator"]}')
        elif mouse_behavior.get('has_human_curves'):
            risk['green_flags'].append('Natural mouse movement curves')

        # Click behavior
        click_behavior = advanced_behavior.get('click_behavior', {})
        if click_behavior.get('bot_indicator'):
            risk['total_score'] += 10
            risk['red_flags'].append(f'Click: {click_behavior["bot_indicator"]}')

        # VM detection
        vm_detection = self.results.get('vm_detection', {})
        if vm_detection.get('is_likely_vm'):
            risk['total_score'] += 15
            risk['red_flags'].append('Running in virtual machine')

        # Timing analysis
        timing = self.results.get('timing_analysis', {})
        if timing.get('suspicion_level') == 'high':
            risk['total_score'] += 15
            risk['red_flags'].append(f'Timing: {timing.get("reason", "Too fast")}')

        # Browser extensions (ad blockers indicate privacy-aware user)
        extensions = self.results.get('browser_extensions', {})
        if extensions.get('privacy_concerned'):
            risk['green_flags'].append('Privacy-aware (ad blocker detected)')

        # Cap the score
        risk['total_score'] = min(risk['total_score'], 100)

        # Determine risk level
        if risk['total_score'] >= 70:
            risk['risk_level'] = 'critical'
            risk['visitor_quality'] = 'bad'
        elif risk['total_score'] >= 50:
            risk['risk_level'] = 'high'
            risk['visitor_quality'] = 'bad'
        elif risk['total_score'] >= 30:
            risk['risk_level'] = 'medium'
            risk['visitor_quality'] = 'suspicious'
        elif risk['total_score'] >= 15:
            risk['risk_level'] = 'low'
            risk['visitor_quality'] = 'acceptable'
        else:
            risk['risk_level'] = 'minimal'
            risk['visitor_quality'] = 'good'

        # Calculate confidence
        risk['confidence'] = min(100, risk['total_score'] + len(risk['red_flags']) * 5)

        return risk


@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_visitor():
    """Analyze visitor endpoint"""
    try:
        # Get fingerprint data from client
        data = request.get_json()
        client_fingerprint = data.get('fingerprint', {}) if data else {}

        # Create analyzer and run analysis
        analyzer = VisitorAnalyzer(request)
        results = analyzer.analyze(client_fingerprint)

        return jsonify({
            'success': True,
            'results': results
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    print("=" * 70)
    print("Visitor Traffic Quality Analyzer")
    print("=" * 70)
    print("Starting Flask server...")
    print("Open your browser and go to: http://localhost:5000")
    print("=" * 70)
    app.run(debug=True, host='0.0.0.0', port=5000)
