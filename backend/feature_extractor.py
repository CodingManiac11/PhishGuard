import requests
import json
import re
import math
import os
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import Dict, Any, Optional, List
import whois
import dns.resolver
from datetime import datetime, timedelta
import logging
from config import settings
from Levenshtein import distance as levenshtein_distance
import hashlib
import base64

logger = logging.getLogger(__name__)


class FeatureExtractor:
    def __init__(self):
        self.cse_domains = self._load_cse_domains()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': settings.ua})
        
        # Enhanced phishing indicators
        self.phishing_keywords = [
            # Account/Authentication
            'verify', 'update', 'suspend', 'secure', 'account', 'login', 'signin', 'sign-in',
            'password', 'credential', 'authenticate', 'authorization', 'unlock',
            # Brands (commonly impersonated)
            'bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'netflix', 'linkedin', 'instagram', 'twitter', 'ebay', 'chase', 'wellsfargo',
            'coinbase', 'binance', 'blockchain', 'wallet', 'crypto',
            # Urgency/Fear tactics
            'urgent', 'immediate', 'confirm', 'validate', 'activate', 'locked',
            'expired', 'limited', 'restricted', 'alert', 'warning', 'security',
            'suspended', 'disabled', 'unusual', 'unauthorized', 'compromised',
            # Action words
            'click', 'action', 'required', 'verify-now', 'act-now', 'expire',
            # Financial
            'payment', 'invoice', 'refund', 'billing', 'transaction', 'wire', 'transfer'
        ]
        
        self.legitimate_domains = [
            # Tech giants
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'meta.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'youtube.com', 'instagram.com', 'whatsapp.com', 'netflix.com', 'spotify.com',
            # Financial
            'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
            'capitalone.com', 'americanexpress.com', 'discover.com', 'visa.com', 'mastercard.com',
            'stripe.com', 'square.com',
            # Crypto
            'coinbase.com', 'binance.com', 'blockchain.com', 'kraken.com',
            # E-commerce
            'ebay.com', 'etsy.com', 'walmart.com', 'target.com', 'bestbuy.com',
            'alibaba.com', 'aliexpress.com', 'shopify.com',
            # Cloud/Enterprise
            'salesforce.com', 'oracle.com', 'ibm.com', 'adobe.com', 'dropbox.com',
            'slack.com', 'zoom.us', 'atlassian.com', 'hubspot.com',
            # Other
            'reddit.com', 'pinterest.com', 'tumblr.com', 'discord.com', 'twitch.tv',
            
            # IT Services (for typosquatting baselines)
            'tcs.com', 'infosys.com', 'wipro.com', 'hcl.com', 'capgemini.com', 'accenture.com'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.click', '.download',
            '.stream', '.science', '.racing', '.win', '.bid', '.loan', '.date',
            '.review', '.country', '.kim', '.cricket', '.work', '.party', '.gdn',
            '.xyz', '.online', '.site', '.club', '.icu', '.buzz', '.live', '.rest'
        ]
        
        # Hosted infrastructure patterns (ngrok, tunneling services, etc.)
        self.hosted_infrastructure_patterns = [
            # ngrok patterns
            r'.*\.ngrok\.io$',
            r'.*\.ngrok-free\.app$',
            r'.*\.ngrok\.dev$',
            # Cloudflare tunnel patterns
            r'.*\.trycloudflare\.com$',
            r'.*\.cfargotunnel\.com$',
            # Other tunneling services
            r'.*\.localtunnel\.me$',
            r'.*\.serveo\.net$',
            r'.*\.pagekite\.me$',
            r'.*\.herokuapp\.com$',
            r'.*\.repl\.co$',
            r'.*\.replit\.dev$',
            r'.*\.glitch\.me$',
            r'.*\.codepen\.io$',
            r'.*\.codesandbox\.io$',
            r'.*\.stackblitz\.io$',
            r'.*\.surge\.sh$',
            r'.*\.netlify\.app$',
            r'.*\.vercel\.app$',
            r'.*\.now\.sh$',
            # GitHub Pages and similar
            r'.*\.github\.io$',
            r'.*\.gitlab\.io$',
            r'.*\.bitbucket\.io$',
            # Firebase and Google hosting
            r'.*\.firebaseapp\.com$',
            r'.*\.web\.app$',
            r'.*\.appspot\.com$',
            # AWS and cloud hosting
            r'.*\.amazonaws\.com$',
            r'.*\.s3\..*\.amazonaws\.com$',
            r'.*\.cloudfront\.net$',
            r'.*\.azurewebsites\.net$',
            r'.*\.azureedge\.net$',
            # Dynamic DNS services
            r'.*\.dyndns\.org$',
            r'.*\.no-ip\.org$',
            r'.*\.ddns\.net$',
            r'.*\.hopto\.org$',
            r'.*\.myds\.me$',
            # Temporary/disposable hosting
            r'.*\.000webhost\.com$',
            r'.*\.freehostia\.com$',
            r'.*\.freewebhostingarea\.com$',
            r'.*\.atwebpages\.com$',
            # URL shorteners (expanded list)
            r'.*\.ly$',
            r'.*\.me$',
            r'bit\.ly',
            r'tinyurl\.com',
            r't\.co',
            r'short\.link',
            r'ow\.ly',
            r's2r\.co',
            r'clicky\.me'
        ]
    
    def _load_cse_domains(self) -> List[str]:
        """Load CSE domain list from sample data"""
        try:
            cse_path = os.path.join(os.path.dirname(__file__), 'sample_data', 'cse_list.json')
            if os.path.exists(cse_path):
                with open(cse_path, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logger.warning(f"Could not load CSE list: {e}")
            return []
    
    def extract_features(self, url: str, cse_hint: Optional[str] = None) -> Dict[str, Any]:
        """Extract comprehensive features from URL and page content"""
        features = {}
        
        # Include the original URL for trusted domain checking
        features['url'] = url
        
        # URL structure features
        features.update(self._extract_url_features(url))
        
        # Page content features
        try:
            html_content = self._fetch_page_content(url)
            features.update(self._extract_content_features(html_content))
            features['fetch_success'] = True
        except Exception as e:
            logger.warning(f"Failed to fetch content for {url}: {e}")
            features['fetch_success'] = False
            features.update(self._get_default_content_features())
        
        # CSE similarity features
        if cse_hint:
            features.update(self._extract_cse_similarity(url, cse_hint))
        
        # WHOIS features (if enabled)
        if settings.enable_whois:
            features.update(self._extract_whois_features(url))
        
        # DNS features (if enabled)
        if settings.enable_dns:
            features.update(self._extract_dns_features(url))
        
        return features
    
    def _extract_url_features(self, url: str) -> Dict[str, Any]:
        """Extract enhanced URL structure and entropy features"""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        
        features = {
            # Store hostname for brand detection
            'hostname': hostname,
            
            # Basic length features
            'url_length': len(url),
            'hostname_length': len(hostname),
            'path_length': len(path),
            'query_length': len(query),
            
            # Domain structure features
            'subdomain_count': len(hostname.split('.')) - 2 if '.' in hostname else 0,
            'domain_depth': len([p for p in path.split('/') if p]) if path else 0,
            'query_param_count': len(parse_qs(query)) if query else 0,
            
            # Suspicious patterns
            'has_ip_address': bool(re.match(r'^\d+\.\d+\.\d+\.\d+', hostname)),
            'has_suspicious_tld': any(hostname.endswith(tld) for tld in self.suspicious_tlds),
            'dash_count': hostname.count('-'),
            'underscore_count': hostname.count('_'),
            'digit_count': sum(c.isdigit() for c in hostname),
            'special_char_count': len(re.findall(r'[^a-zA-Z0-9.-]', hostname)),
            
            # NEW: Double extension detection (e.g., .com.tk, .org.ml)
            'has_double_extension': self._detect_double_extension(hostname),
            
            # NEW: Brand name in subdomain (suspicious pattern)
            'brand_in_subdomain': self._detect_brand_in_subdomain(hostname),
            
            # NEW: Consonant ratio (random strings have abnormal ratios)
            'consonant_ratio': self._calculate_consonant_ratio(hostname),
            
            # NEW: URL encoding detection
            'url_encoded_chars_count': len(re.findall(r'%[0-9A-Fa-f]{2}', url)),
            
            # NEW: Typosquatting pattern detection
            'typosquatting_score': self._detect_typosquatting(hostname),
            
            # NEW: Repeated character sequences
            'has_repeated_chars': bool(re.search(r'(.)\1{3,}', hostname)),
            
            # NEW: Suspicious file extension in path (malware detection)
            'has_suspicious_file_extension': self._detect_suspicious_file_extension(path),
            
            # NEW: HTTP only (no HTTPS) - higher risk for downloads
            'http_without_https': parsed.scheme == 'http',
            
            # NEW: Short random path (common in malware URLs like /aTu.lim)
            'has_short_random_path': self._detect_short_random_path(path),
            
            # NEW: Unknown/uncommon TLD
            'has_uncommon_tld': self._detect_uncommon_tld(hostname),
            
            # Advanced suspicious patterns
            'has_homograph_chars': self._detect_homograph_chars(hostname),
            'punycode_domain': hostname.startswith('xn--'),
            'suspicious_port': self._is_suspicious_port(parsed.port),
            'has_url_shortener': self._is_url_shortener(hostname),
            'is_hosted_infrastructure': self._detect_hosted_infrastructure(hostname),
            'hosted_service_type': self._identify_hosted_service(hostname),
            
            # Keyword analysis
            'phishing_keyword_count': self._count_phishing_keywords(url.lower()),
            'brand_impersonation_score': self._calculate_brand_impersonation(hostname),
            
            # NEW: Brand in path detection
            'brand_in_path': self._detect_brand_in_path(path),
            
            # Entropy and randomness
            'url_entropy': self._calculate_entropy(url),
            'hostname_entropy': self._calculate_entropy(hostname),
            'path_entropy': self._calculate_entropy(path),
            'randomness_score': self._calculate_randomness_score(hostname),
            
            # URL complexity
            'has_query_params': bool(query),
            'fragment_present': bool(parsed.fragment),
            'redirect_chains': 0,  # Will be updated during content fetch
            
            # Certificate and protocol features
            'uses_https': parsed.scheme == 'https',
            'non_standard_port': parsed.port is not None and parsed.port not in [80, 443],
        }
        
        return features
    
    def _detect_double_extension(self, hostname: str) -> bool:
        """Detect domains with double extensions like .com.tk"""
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.co']
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw']
        
        for common in common_tlds:
            for suspicious in suspicious_tlds:
                if common + suspicious in hostname:
                    return True
        return False
    
    def _detect_brand_in_subdomain(self, hostname: str) -> bool:
        """Detect brand names appearing in subdomains (not as main domain)"""
        parts = hostname.lower().split('.')
        if len(parts) < 3:
            return False
        
        # Check subdomains (all parts except the last two which are domain.tld)
        subdomains = parts[:-2]
        subdomain_text = '.'.join(subdomains)
        
        for domain in self.legitimate_domains:
            brand = domain.split('.')[0]
            if brand in subdomain_text:
                return True
        return False
    
    def _calculate_consonant_ratio(self, text: str) -> float:
        """Calculate consonant ratio - random strings often have abnormal ratios"""
        if not text or len(text) < 3:
            return 0.5
        
        text_lower = text.lower()
        consonants = set('bcdfghjklmnpqrstvwxyz')
        letters = [c for c in text_lower if c.isalpha()]
        
        if not letters:
            return 0.5
            
        consonant_count = sum(1 for c in letters if c in consonants)
        return consonant_count / len(letters)
    
    def _detect_typosquatting(self, hostname: str) -> float:
        """Detect advanced typosquatting patterns including visual homoglyphs"""
        hostname_lower = hostname.lower()
        max_score = 0.0
        
        # 1. Visual Homoglyphs (Combosquatting)
        # These are character combinations that look like other characters
        visual_replacements = {
            'rn': 'm',
            'cl': 'd',
            'vv': 'w',
            'nn': 'm',
            'ol': 'd',
            'lc': 'k',
        }
        
        # 2. Common character substitutions
        substitutions = {
            'o': ['0', 'ο'],  # o -> zero, Greek omicron
            'i': ['1', 'l', '!'],
            'l': ['1', 'i', '|'],
            'a': ['@', '4', 'а'], 
            'e': ['3', 'е'],
            's': ['5', '$'],
            'g': ['9', '6'],
            'm': ['rn', 'nn'], # m -> rn spoofing
            'w': ['vv'],       # w -> vv spoofing
            'd': ['cl'],       # d -> cl spoofing
        }
        
        for domain in self.legitimate_domains:
            brand = domain.split('.')[0].lower()
            if len(brand) < 4: continue # Skip very short brands to avoid FPs
            
            # Check for "rn" -> "m" style visual spoofing (e.g., tcs.corn -> tcs.com)
            # Create a "normalized" version of the hostname where visual tricks are resolved
            normalized_hostname = hostname_lower
            for visual, char in visual_replacements.items():
                normalized_hostname = normalized_hostname.replace(visual, char)
            
            if brand in normalized_hostname and brand not in hostname_lower:
                 # "brand" appearing in normalized but not original implies visual spoofing
                 max_score = max(max_score, 0.95)
            
            # Check for regular substitutions
            for char, subs in substitutions.items():
                for sub in subs:
                    # Check if 'brand' with replacement 'sub' exists in hostname
                    # E.g. brand="micro", sub="1" -> "m1cro"
                    try:
                        brand_with_sub = brand.replace(char, sub)
                        if brand_with_sub in hostname_lower and brand_with_sub != brand:
                            max_score = max(max_score, 0.9)
                    except Exception:
                        continue

            # 3. Levenshtein Distance Check (Insertions/Deletions)
            # e.g., rmicrosoft.com (INSERT 'r')
            # Extract the SLD (Second Level Domain) from hostname for comparison
            parts = hostname_lower.split('.')
            if len(parts) >= 2:
                sld = parts[-2] # assume tcs.com -> tcs, or tcs.co.uk -> co (simple heuristic)
                if len(parts) > 2 and len(parts[-1]) == 2: # heuristic for co.uk
                     sld = parts[-3]

                # Calculate distance between SLD and Brand
                dist = levenshtein_distance(sld, brand)
                
                # If distance is small (1 or 2) and string length is sufficient
                if dist == 1 and len(brand) > 4:
                    max_score = max(max_score, 0.85) # Very distinct typesquat
                elif dist == 2 and len(brand) > 6:
                    max_score = max(max_score, 0.7)

        return max_score
    
    def _detect_brand_in_path(self, path: str) -> bool:
        """Detect brand names in URL path (phishing often puts brand in path)"""
        path_lower = path.lower()
        
        for domain in self.legitimate_domains:
            brand = domain.split('.')[0]
            if brand in path_lower:
                return True
        return False
    
    def _detect_suspicious_file_extension(self, path: str) -> bool:
        """Detect suspicious/executable file extensions commonly used in malware"""
        suspicious_extensions = [
            # Executables
            '.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.pif',
            # Scripts
            '.vbs', '.vbe', '.js', '.jse', '.ws', '.wsf', '.wsc', '.wsh',
            '.ps1', '.psm1', '.psd1',
            # Documents with macros
            '.docm', '.xlsm', '.pptm', '.dotm',
            # Archives (often used to hide malware)
            '.zip', '.rar', '.7z', '.tar', '.gz',
            # Other suspicious
            '.dll', '.sys', '.drv', '.ocx',
            '.lim', '.bin', '.dat', '.tmp',  # Uncommon extensions like in the malware URL
            '.apk', '.ipa',  # Mobile apps
        ]
        
        path_lower = path.lower()
        for ext in suspicious_extensions:
            if path_lower.endswith(ext):
                return True
        return False
    
    def _detect_short_random_path(self, path: str) -> bool:
        """Detect short random-looking paths common in malware URLs like /aTu.lim"""
        if not path or path == '/':
            return False
        
        # Get the last segment of the path
        segments = [s for s in path.split('/') if s]
        if not segments:
            return False
        
        last_segment = segments[-1]
        
        # Check if it's a short segment with mixed case (suspicious pattern)
        if len(last_segment) <= 10 and len(last_segment) >= 3:
            # Check for mixed case which is unusual in normal URLs
            has_upper = any(c.isupper() for c in last_segment)
            has_lower = any(c.islower() for c in last_segment)
            
            if has_upper and has_lower:
                # Check if it doesn't look like a normal word
                # (has unusual character distribution)
                vowels = sum(1 for c in last_segment.lower() if c in 'aeiou')
                if vowels <= 1:  # Very few vowels = likely random
                    return True
        
        return False
    
    def _detect_uncommon_tld(self, hostname: str) -> bool:
        """Detect uncommon/suspicious TLDs often used in malware distribution"""
        uncommon_tlds = [
            # Very uncommon/cheap TLDs
            '.xyz', '.top', '.click', '.link', '.work', '.date',
            '.racing', '.download', '.stream', '.gdn', '.men',
            '.loan', '.win', '.bid', '.trade', '.webcam', '.party',
            '.science', '.review', '.cricket', '.accountant',
            # Free TLDs often abused
            '.tk', '.ml', '.ga', '.cf', '.gq',
            # Less trusted
            '.pw', '.cc', '.ws', '.su', '.biz',
        ]
        
        hostname_lower = hostname.lower()
        for tld in uncommon_tlds:
            if hostname_lower.endswith(tld):
                return True
        return False
        
    def _detect_homograph_chars(self, text: str) -> bool:
        """Detect Unicode homograph characters that could be used for spoofing"""
        # Common homograph characters used in phishing
        homograph_pairs = [
            ('а', 'a'), ('о', 'o'), ('р', 'p'), ('е', 'e'), ('с', 'c'),
            ('х', 'x'), ('у', 'y'), ('і', 'i'), ('ј', 'j'), ('ѕ', 's')
        ]
        
        for cyrillic, latin in homograph_pairs:
            if cyrillic in text:
                return True
        return False
        
    def _is_suspicious_port(self, port: Optional[int]) -> bool:
        """Check if port number is suspicious"""
        if port is None:
            return False
        # Common suspicious ports
        suspicious_ports = [8080, 8000, 3000, 4000, 5000, 8888, 9000, 8443]
        return port in suspicious_ports
        
    def _is_url_shortener(self, hostname: str) -> bool:
        """Check if hostname is a known URL shortener"""
        shorteners = [
            'bit.ly', 'tinyurl.com', 'short.link', 'ow.ly', 'is.gd',
            'buff.ly', 't.co', 'goo.gl', 'tiny.cc', 'cli.gs'
        ]
        return hostname in shorteners
        
    def _count_phishing_keywords(self, url: str) -> int:
        """Count phishing-related keywords in URL"""
        return sum(1 for keyword in self.phishing_keywords if keyword in url)
        
    def _calculate_brand_impersonation(self, hostname: str) -> float:
        """Calculate likelihood of brand impersonation"""
        max_score = 0.0
        
        for legitimate_domain in self.legitimate_domains:
            # Extract the main part (before .com, .org, etc.)
            legitimate_name = legitimate_domain.split('.')[0]
            
            # Check for exact substring match
            if legitimate_name in hostname and hostname != legitimate_domain:
                max_score = max(max_score, 0.9)
            
            # Check for character substitution
            distance = levenshtein_distance(hostname.split('.')[0], legitimate_name)
            if distance <= 2 and len(legitimate_name) > 4:
                similarity = 1.0 - (distance / len(legitimate_name))
                if similarity > 0.7:
                    max_score = max(max_score, similarity * 0.8)
        
        return max_score
        
    def _calculate_randomness_score(self, text: str) -> float:
        """Calculate randomness score based on character patterns"""
        if len(text) < 3:
            return 0.0
        
        # Count vowel-consonant patterns
        vowels = set('aeiou')
        consonants = set('bcdfghjklmnpqrstvwxyz')
        
        vowel_count = sum(1 for c in text.lower() if c in vowels)
        consonant_count = sum(1 for c in text.lower() if c in consonants)
        
        if len(text) == 0:
            return 0.0
            
        vowel_ratio = vowel_count / len(text)
        
        # Normal English has ~40% vowels, very random strings have different patterns
        normal_vowel_ratio = 0.4
        randomness = abs(vowel_ratio - normal_vowel_ratio) * 2
        
        # [MODIFIED] Check for repeated characters (another randomness indicator)
        char_counts = {}
        for char in text.lower():
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Penalize only if repetition is excessive relative to length
        max_repeat = max(char_counts.values()) if char_counts else 0
        repeat_penalty = 0
        if len(text) > 4 and max_repeat > len(text) * 0.5: # Only if >50% chars are same
             repeat_penalty = 0.4
        
        score = randomness + repeat_penalty
        
        # [MODIFIED] Relax score for short strings (acronyms often have no vowels)
        # e.g. "tcs" -> 0 vowels -> high randomness originally.
        if len(text) <= 4:
            score = score * 0.3 # Significantly reduce impact for acronyms
        elif len(text) <= 6:
            score = score * 0.6
            
        return min(score, 1.0)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _fetch_page_content(self, url: str) -> str:
        """Safely fetch page content with timeouts and redirect handling"""
        try:
            response = self.session.get(
                url, 
                timeout=10, 
                allow_redirects=True,
                verify=False  # For testing purposes
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            raise
    
    def _detect_hosted_infrastructure(self, hostname: str) -> bool:
        """Detect if hostname uses hosted infrastructure services"""
        if not hostname:
            return False
        
        hostname_lower = hostname.lower()
        
        for pattern in self.hosted_infrastructure_patterns:
            if re.match(pattern, hostname_lower):
                return True
        return False
    
    def _identify_hosted_service(self, hostname: str) -> str:
        """Identify the specific type of hosted service"""
        if not hostname:
            return "unknown"
        
        hostname_lower = hostname.lower()
        
        # ngrok services
        if re.match(r'.*\.ngrok\.(io|dev|app)$', hostname_lower):
            return "ngrok"
        
        # Cloudflare services
        if re.match(r'.*\.(trycloudflare\.com|cfargotunnel\.com)$', hostname_lower):
            return "cloudflare_tunnel"
        
        # Development platforms
        if re.match(r'.*\.(herokuapp\.com|repl\.co|replit\.dev|glitch\.me)$', hostname_lower):
            return "dev_platform"
        
        # Static hosting
        if re.match(r'.*\.(github\.io|gitlab\.io|netlify\.app|vercel\.app)$', hostname_lower):
            return "static_hosting"
        
        # Cloud hosting
        if re.match(r'.*\.(amazonaws\.com|azurewebsites\.net|appspot\.com)$', hostname_lower):
            return "cloud_hosting"
        
        # Tunneling services
        if re.match(r'.*\.(localtunnel\.me|serveo\.net|pagekite\.me)$', hostname_lower):
            return "tunnel_service"
        
        # URL shorteners
        if hostname_lower in ['bit.ly', 'tinyurl.com', 't.co', 'short.link']:
            return "url_shortener"
        
        # Dynamic DNS
        if re.match(r'.*\.(dyndns\.org|no-ip\.org|ddns\.net)$', hostname_lower):
            return "dynamic_dns"
        
        # Free hosting
        if re.match(r'.*\.(000webhost\.com|freehostia\.com)$', hostname_lower):
            return "free_hosting"
        
        return "standard_hosting"
    
    def _extract_content_features(self, html_content: str) -> Dict[str, Any]:
        """Extract enhanced features from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Get page text and title
        page_text = soup.get_text().lower()
        title = soup.title.string.lower() if soup.title else ""
        
        # Enhanced form analysis
        forms = soup.find_all('form')
        password_inputs = soup.find_all('input', {'type': 'password'})
        text_inputs = soup.find_all('input', {'type': ['text', 'email']})
        
        # Link analysis
        all_links = soup.find_all('a', href=True)
        external_links = [link for link in all_links if self._is_external_link(link['href'])]
        
        # Image analysis
        images = soup.find_all('img')
        external_images = [img for img in images if img.get('src') and self._is_external_link(img.get('src'))]
        
        # Script analysis
        scripts = soup.find_all('script')
        external_scripts = [script for script in scripts if script.get('src') and self._is_external_link(script.get('src'))]
        
        features = {
            # Enhanced form features
            'has_forms': bool(forms),
            'form_count': len(forms),
            'has_password_input': bool(password_inputs),
            'password_input_count': len(password_inputs),
            'text_input_count': len(text_inputs),
            'form_to_input_ratio': len(text_inputs) / max(len(forms), 1),
            'hidden_input_count': len(soup.find_all('input', {'type': 'hidden'})),
            
            # Enhanced keyword analysis
            'phishing_keyword_density': self._calculate_keyword_density(page_text),
            'urgent_keyword_count': len(re.findall(r'(urgent|immediately|expire|suspend|verify now|act now|limited time)', page_text)),
            'security_keyword_count': len(re.findall(r'(security|verify|update|confirm|validate|authenticate)', page_text)),
            'financial_keyword_count': len(re.findall(r'(bank|payment|credit card|paypal|account|billing)', page_text)),
            
            # Title analysis
            'suspicious_title': self._analyze_suspicious_title(title),
            'title_brand_mismatch': self._detect_title_brand_mismatch(title, soup),
            
            # Link analysis
            'total_links': len(all_links),
            'external_links_count': len(external_links),
            'external_link_ratio': len(external_links) / max(len(all_links), 1),
            'suspicious_link_count': self._count_suspicious_links(all_links),
            'broken_link_indicators': self._detect_broken_links(soup),
            
            # Media and resource analysis
            'iframe_count': len(soup.find_all('iframe')),
            'external_iframe_count': len([iframe for iframe in soup.find_all('iframe') 
                                        if iframe.get('src') and self._is_external_link(iframe.get('src'))]),
            'image_count': len(images),
            'external_image_count': len(external_images),
            'script_count': len(scripts),
            'external_script_count': len(external_scripts),
            
            # Page structure analysis
            'has_favicon': bool(soup.find('link', {'rel': 'icon'})),
            'meta_tags_count': len(soup.find_all('meta')),
            'has_ssl_indicators': self._detect_ssl_indicators(soup),
            'obfuscated_content': self._detect_obfuscation(html_content),
            
            # Content quality indicators
            'text_to_html_ratio': len(page_text) / max(len(html_content), 1),
            'html_complexity_score': self._calculate_html_complexity(soup),
            'spelling_error_indicators': self._detect_spelling_errors(page_text),
            
            # Social engineering indicators
            'countdown_timer_present': self._detect_countdown_timer(soup),
            'popup_indicators': self._detect_popup_indicators(soup),
            'certificate_warnings': self._detect_certificate_warnings(page_text),
        }
        
        return features
        
    def _calculate_keyword_density(self, text: str) -> float:
        """Calculate density of phishing keywords in text"""
        if not text:
            return 0.0
        
        words = text.split()
        phishing_count = sum(1 for word in words if any(keyword in word for keyword in self.phishing_keywords))
        return phishing_count / max(len(words), 1)
        
    def _analyze_suspicious_title(self, title: str) -> float:
        """Analyze title for suspicious patterns"""
        if not title:
            return 0.0
            
        suspicious_patterns = [
            r'(login|sign in)',
            r'(security|verify|update)',
            r'(suspended|locked|expired)',
            r'(urgent|immediate)',
            r'(confirm|validate)',
        ]
        
        score = 0.0
        for pattern in suspicious_patterns:
            if re.search(pattern, title):
                score += 0.2
                
        return min(score, 1.0)
        
    def _detect_title_brand_mismatch(self, title: str, soup: BeautifulSoup) -> float:
        """Detect mismatch between title branding and page content"""
        if not title:
            return 0.0
            
        # Extract potential brand names from title
        title_brands = []
        for domain in self.legitimate_domains:
            brand = domain.split('.')[0]
            if brand in title:
                title_brands.append(brand)
        
        # Check if page content matches title branding
        page_text = soup.get_text().lower()
        mismatch_score = 0.0
        
        for brand in title_brands:
            # If brand in title but not prominently in content, it's suspicious
            brand_count_in_content = len(re.findall(brand, page_text))
            if brand_count_in_content < 3:  # Threshold for "prominent"
                mismatch_score += 0.3
                
        return min(mismatch_score, 1.0)
        
    def _count_suspicious_links(self, links: List) -> int:
        """Count links with suspicious characteristics"""
        suspicious_count = 0
        
        for link in links:
            href = link.get('href', '').lower()
            text = link.get_text().lower()
            
            # Check for suspicious patterns
            if any(keyword in href or keyword in text for keyword in self.phishing_keywords):
                suspicious_count += 1
            elif re.search(r'https?://[^/]*\d+\.\d+\.\d+\.\d+', href):  # IP address links
                suspicious_count += 1
            elif len(href) > 100:  # Very long URLs
                suspicious_count += 1
                
        return suspicious_count
        
    def _detect_broken_links(self, soup: BeautifulSoup) -> int:
        """Detect indicators of broken or placeholder links"""
        broken_indicators = 0
        
        # Look for common broken link patterns
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href'].lower()
            if href in ['#', 'javascript:void(0)', 'javascript:', ''] or href.startswith('mailto:'):
                broken_indicators += 1
                
        return broken_indicators
        
    def _detect_ssl_indicators(self, soup: BeautifulSoup) -> bool:
        """Detect fake SSL/security indicators"""
        page_text = soup.get_text().lower()
        
        # Look for fake security badges or SSL claims
        fake_ssl_patterns = [
            'ssl protected', 'secure site', '100% secure', 'guaranteed secure',
            'bank level security', 'military grade encryption'
        ]
        
        return any(pattern in page_text for pattern in fake_ssl_patterns)
        
    def _detect_obfuscation(self, html_content: str) -> bool:
        """Detect content obfuscation techniques"""
        # Look for common obfuscation patterns
        obfuscation_indicators = [
            r'eval\(', r'unescape\(', r'fromCharCode\(',
            r'\\x[0-9a-f]{2}', r'&#x?[0-9a-f]+;',
            r'document\.write\(.*string', r'innerHTML.*fromCharCode'
        ]
        
        return any(re.search(pattern, html_content, re.IGNORECASE) for pattern in obfuscation_indicators)
        
    def _calculate_html_complexity(self, soup: BeautifulSoup) -> float:
        """Calculate HTML structure complexity score"""
        # Simple complexity based on tag diversity and nesting
        all_tags = soup.find_all()
        unique_tags = set(tag.name for tag in all_tags)
        
        # Calculate average nesting depth
        max_depth = 0
        for tag in soup.find_all():
            depth = len(list(tag.parents))
            max_depth = max(max_depth, depth)
            
        complexity = len(unique_tags) * 0.1 + min(max_depth * 0.05, 0.5)
        return min(complexity, 1.0)
        
    def _detect_spelling_errors(self, text: str) -> float:
        """Detect potential spelling errors (simple heuristic)"""
        if not text or len(text) < 50:
            return 0.0
            
        # Look for common misspellings in phishing attempts
        misspellings = [
            'recieve', 'seperate', 'occured', 'begining', 'writting',
            'sucessful', 'neccessary', 'occassion', 'definately'
        ]
        
        error_count = sum(text.lower().count(error) for error in misspellings)
        words = len(text.split())
        
        return min(error_count / max(words, 1) * 10, 1.0)  # Scale up the score
        
    def _detect_countdown_timer(self, soup: BeautifulSoup) -> bool:
        """Detect countdown timers (urgency tactic)"""
        page_text = soup.get_text().lower()
        
        # Look for time-related urgency
        timer_patterns = [
            r'\d+:\d+:\d+', r'\d+ (hours?|minutes?|seconds?) (left|remaining)',
            'countdown', 'expires in', 'time remaining', 'hurry'
        ]
        
        return any(re.search(pattern, page_text) for pattern in timer_patterns)
        
    def _detect_popup_indicators(self, soup: BeautifulSoup) -> bool:
        """Detect popup or overlay indicators"""
        # Look for common popup/modal patterns
        popup_indicators = soup.find_all(['div', 'span'], {
            'class': re.compile(r'(popup|modal|overlay|alert)', re.IGNORECASE)
        })
        
        return len(popup_indicators) > 0
        
    def _detect_certificate_warnings(self, text: str) -> bool:
        """Detect fake certificate warnings"""
        warning_patterns = [
            'certificate expired', 'security certificate', 'ssl certificate',
            'certificate error', 'certificate warning', 'certificate invalid'
        ]
        
        return any(pattern in text.lower() for pattern in warning_patterns)
    
    def _get_default_content_features(self) -> Dict[str, Any]:
        """Return default values for content features when fetch fails"""
        return {
            'has_forms': False,
            'form_count': 0,
            'has_password_input': False,
            'has_login_keywords': False,
            'has_urgent_language': False,
            'has_security_keywords': False,
            'suspicious_title': False,
            'external_links_count': 0,
            'iframe_count': 0,
            'script_count': 0,
            'has_favicon': False,
        }
    
    def _is_external_link(self, href: str) -> bool:
        """Check if link is external"""
        return href.startswith('http') and not href.startswith('#')
    
    def _extract_cse_similarity(self, url: str, cse_hint: str) -> Dict[str, Any]:
        """Extract CSE similarity features using Levenshtein distance"""
        try:
            from Levenshtein import distance
        except ImportError:
            logger.warning("Levenshtein not available, using basic similarity")
            return {'cse_similarity_score': 0.5}
        
        hostname = urlparse(url).hostname or ""
        cse_lower = cse_hint.lower()
        hostname_lower = hostname.lower()
        
        # Calculate Levenshtein similarity
        max_len = max(len(cse_lower), len(hostname_lower))
        if max_len == 0:
            similarity = 1.0
        else:
            similarity = 1.0 - (distance(cse_lower, hostname_lower) / max_len)
        
        features = {
            'cse_similarity_score': similarity,
            'cse_in_hostname': cse_lower in hostname_lower,
            'hostname_in_cse': hostname_lower in cse_lower,
        }
        
        return features
    
    def _extract_whois_features(self, url: str) -> Dict[str, Any]:
        """Extract WHOIS-based features"""
        hostname = urlparse(url).hostname
        if not hostname:
            return {'domain_age_days': -1, 'whois_available': False}
        
        try:
            domain_info = whois.whois(hostname)
            creation_date = domain_info.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                return {
                    'domain_age_days': age_days,
                    'whois_available': True,
                    'domain_young': age_days < 90,  # Less than 3 months
                }
            else:
                return {'domain_age_days': -1, 'whois_available': False}
                
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {hostname}: {e}")
            return {'domain_age_days': -1, 'whois_available': False}
    
    def _extract_dns_features(self, url: str) -> Dict[str, Any]:
        """Extract DNS-based features"""
        hostname = urlparse(url).hostname
        if not hostname:
            return {'has_mx_record': False, 'has_txt_record': False}
        
        features = {'has_mx_record': False, 'has_txt_record': False}
        
        try:
            # Check for MX records
            dns.resolver.resolve(hostname, 'MX')
            features['has_mx_record'] = True
        except:
            pass
        
        try:
            # Check for TXT records
            dns.resolver.resolve(hostname, 'TXT')
            features['has_txt_record'] = True
        except:
            pass
        
        return features
