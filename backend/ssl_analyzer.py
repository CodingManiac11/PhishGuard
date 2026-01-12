"""
SSL Certificate Analyzer for PhishGuard
Validates SSL certificates to detect security issues
"""

import ssl
import socket
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class SSLAnalyzer:
    """Analyze SSL certificates for security issues"""
    
    def __init__(self):
        self.timeout = 20  # Increased timeout for slow servers
        logger.info("✅ SSL Analyzer initialized")
    
    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze SSL certificate for a given URL
        Returns certificate details and security assessment
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            if not hostname:
                return {
                    "success": False,
                    "error": "Invalid URL - no hostname found",
                    "is_secure": False
                }
            
            # Check if HTTP (no SSL)
            if parsed.scheme == "http":
                return {
                    "success": True,
                    "is_secure": False,
                    "warning": "No SSL - HTTP connection (not encrypted)",
                    "risk_level": "HIGH",
                    "issues": ["No HTTPS encryption - data transmitted in plaintext"],
                    "hostname": hostname
                }
            
            # Get certificate
            cert_info = await self._get_certificate(hostname, port)
            
            if not cert_info.get("success"):
                return cert_info
            
            # Analyze certificate
            return self._analyze_certificate(cert_info, hostname)
            
        except Exception as e:
            logger.error(f"SSL analysis error: {e}")
            return {
                "success": False,
                "error": str(e),
                "is_secure": False
            }
    
    async def _get_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Fetch SSL certificate from server"""
        try:
            # Use default context with verification for proper cert parsing
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    
                    if cert:
                        return {
                            "success": True,
                            "certificate": cert,
                            "verified": True
                        }
                    else:
                        return {
                            "success": True,
                            "certificate": None,
                            "warning": "Certificate retrieved but empty"
                        }
                        
        except ssl.SSLCertVerificationError as e:
            # Certificate verification failed - try to get cert anyway for analysis
            try:
                context_no_verify = ssl.create_default_context()
                context_no_verify.check_hostname = False
                context_no_verify.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context_no_verify.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # Can't get parsed cert with CERT_NONE, so return the error info
                        return {
                            "success": True,
                            "certificate": None,
                            "verification_error": str(e),
                            "is_secure": False,
                            "issues": [f"Certificate verification failed: {str(e)}"]
                        }
            except:
                return {
                    "success": False,
                    "error": f"SSL Verification Error: {str(e)}",
                    "is_secure": False,
                    "issues": ["Certificate verification failed"]
                }
        except ssl.SSLError as e:
            return {
                "success": True,
                "certificate": None,
                "is_secure": False,
                "issues": [f"SSL Error: {str(e)}"]
            }
        except socket.timeout:
            return {
                "success": False,
                "error": "Connection timeout",
                "is_secure": False
            }
        except socket.gaierror:
            return {
                "success": False,
                "error": "Could not resolve hostname",
                "is_secure": False
            }
        except ConnectionRefusedError:
            return {
                "success": False,
                "error": "Connection refused - server may not support HTTPS",
                "is_secure": False
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "is_secure": False
            }
    
    def _analyze_certificate(self, cert_info: Dict[str, Any], hostname: str) -> Dict[str, Any]:
        """Analyze certificate for security issues"""
        issues = []
        warnings = []
        cert = cert_info.get("certificate")
        
        if not cert:
            return {
                "success": True,
                "is_secure": False,
                "hostname": hostname,
                "risk_level": "MEDIUM",
                "issues": ["Could not parse certificate details"],
                "warnings": ["Certificate exists but validation failed"]
            }
        
        # Extract certificate details
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        
        common_name = subject.get("commonName", "")
        issuer_org = issuer.get("organizationName", "")
        issuer_cn = issuer.get("commonName", "")
        
        # Parse dates
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        
        try:
            expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            valid_from = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
            days_until_expiry = (expiry_date - datetime.now()).days
        except:
            expiry_date = None
            valid_from = None
            days_until_expiry = None
        
        # Check for issues
        
        # 1. Expired certificate
        if days_until_expiry is not None:
            if days_until_expiry < 0:
                issues.append(f"Certificate EXPIRED {abs(days_until_expiry)} days ago")
            elif days_until_expiry < 30:
                warnings.append(f"Certificate expires in {days_until_expiry} days")
        
        # 2. Self-signed certificate
        if subject == issuer:
            issues.append("Self-signed certificate detected")
        
        # 3. Domain mismatch
        san = cert.get("subjectAltName", [])
        valid_domains = [x[1] for x in san if x[0] == "DNS"]
        valid_domains.append(common_name)
        
        domain_match = any(
            self._domain_matches(hostname, domain) 
            for domain in valid_domains
        )
        
        if not domain_match:
            issues.append(f"Certificate domain mismatch - expected {hostname}")
        
        # 4. Check issuer reputation
        trusted_issuers = [
            "DigiCert", "Let's Encrypt", "Comodo", "GlobalSign", 
            "Sectigo", "GeoTrust", "Thawte", "Symantec", "GoDaddy",
            "Amazon", "Microsoft", "Google Trust"
        ]
        
        is_trusted_issuer = any(
            trusted in issuer_org or trusted in issuer_cn 
            for trusted in trusted_issuers
        )
        
        if not is_trusted_issuer and subject != issuer:
            warnings.append(f"Unknown certificate issuer: {issuer_org or issuer_cn}")
        
        # Determine risk level
        if issues:
            risk_level = "HIGH"
            is_secure = False
        elif warnings:
            risk_level = "MEDIUM"
            is_secure = True
        else:
            risk_level = "LOW"
            is_secure = True
        
        return {
            "success": True,
            "is_secure": is_secure,
            "risk_level": risk_level,
            "hostname": hostname,
            "certificate": {
                "common_name": common_name,
                "issuer": issuer_org or issuer_cn,
                "valid_from": not_before,
                "valid_until": not_after,
                "days_until_expiry": days_until_expiry,
                "san_domains": valid_domains[:10]  # Limit to 10
            },
            "issues": issues,
            "warnings": warnings,
            "summary": self._generate_summary(is_secure, issues, warnings)
        }
    
    def _domain_matches(self, hostname: str, pattern: str) -> bool:
        """Check if hostname matches certificate domain pattern"""
        if pattern.startswith("*."):
            # Wildcard certificate
            pattern_base = pattern[2:]
            hostname_parts = hostname.split(".", 1)
            return len(hostname_parts) > 1 and hostname_parts[1] == pattern_base
        return hostname.lower() == pattern.lower()
    
    def _generate_summary(self, is_secure: bool, issues: list, warnings: list) -> str:
        """Generate human-readable summary"""
        if not is_secure:
            return f"🚨 INSECURE: {'; '.join(issues)}"
        elif warnings:
            return f"⚠️ Valid but has warnings: {'; '.join(warnings)}"
        else:
            return "✅ Valid and secure SSL certificate"


# Singleton instance
ssl_analyzer = SSLAnalyzer()
