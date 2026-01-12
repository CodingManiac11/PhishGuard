"""
Email Header Analyzer for PhishGuard
Parses and analyzes email headers to detect spoofing
"""

import re
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import email
from email.utils import parseaddr, parsedate_tz, mktime_tz

logger = logging.getLogger(__name__)


class EmailAnalyzer:
    """Analyze email headers for spoofing and security issues"""
    
    def __init__(self):
        logger.info("✅ Email Analyzer initialized")
        
        # Known disposable email domains
        self.disposable_domains = {
            "tempmail.com", "throwaway.email", "guerrillamail.com",
            "10minutemail.com", "mailinator.com", "trashmail.com",
            "fakeinbox.com", "sharklasers.com", "dispostable.com"
        }
        
        # Suspicious sender patterns
        self.suspicious_patterns = [
            r"noreply.*@.*",  # Generic no-reply
            r".*@.*\d{5,}.*",  # Domain with many numbers
            r".*@.*-{2,}.*",  # Multiple dashes
        ]
    
    async def analyze_headers(self, raw_headers: str) -> Dict[str, Any]:
        """
        Analyze raw email headers
        Returns security assessment and potential issues
        """
        try:
            # Parse headers
            msg = email.message_from_string(raw_headers)
            
            issues = []
            warnings = []
            
            # Extract key headers
            from_header = msg.get("From", "")
            reply_to = msg.get("Reply-To", "")
            return_path = msg.get("Return-Path", "")
            received_headers = msg.get_all("Received", [])
            message_id = msg.get("Message-ID", "")
            date_header = msg.get("Date", "")
            subject = msg.get("Subject", "")
            
            # Parse sender
            sender_name, sender_email = parseaddr(from_header)
            sender_domain = sender_email.split("@")[1] if "@" in sender_email else ""
            
            # 1. Check for spoofing indicators
            spoofing_result = self._check_spoofing(
                sender_email, reply_to, return_path, received_headers
            )
            issues.extend(spoofing_result.get("issues", []))
            warnings.extend(spoofing_result.get("warnings", []))
            
            # 2. Check authentication headers
            auth_result = self._check_authentication(msg)
            issues.extend(auth_result.get("issues", []))
            warnings.extend(auth_result.get("warnings", []))
            
            # 3. Check for suspicious patterns
            pattern_result = self._check_patterns(
                sender_email, sender_name, subject
            )
            issues.extend(pattern_result.get("issues", []))
            warnings.extend(pattern_result.get("warnings", []))
            
            # 4. Analyze routing
            routing_result = self._analyze_routing(received_headers)
            
            # Determine risk level
            if len(issues) >= 3:
                risk_level = "HIGH"
                is_suspicious = True
            elif len(issues) >= 1:
                risk_level = "MEDIUM"
                is_suspicious = True
            elif len(warnings) >= 2:
                risk_level = "MEDIUM"
                is_suspicious = False
            else:
                risk_level = "LOW"
                is_suspicious = False
            
            return {
                "success": True,
                "is_suspicious": is_suspicious,
                "risk_level": risk_level,
                "sender": {
                    "name": sender_name,
                    "email": sender_email,
                    "domain": sender_domain
                },
                "headers": {
                    "from": from_header,
                    "reply_to": reply_to,
                    "return_path": return_path,
                    "message_id": message_id,
                    "date": date_header,
                    "subject": subject
                },
                "authentication": auth_result,
                "routing": routing_result,
                "issues": issues,
                "warnings": warnings,
                "summary": self._generate_summary(is_suspicious, issues, warnings)
            }
            
        except Exception as e:
            logger.error(f"Email analysis error: {e}")
            return {
                "success": False,
                "error": str(e),
                "is_suspicious": True
            }
    
    def _check_spoofing(
        self, 
        sender: str, 
        reply_to: str, 
        return_path: str,
        received: List[str]
    ) -> Dict[str, Any]:
        """Check for email spoofing indicators"""
        issues = []
        warnings = []
        
        # Check From vs Reply-To mismatch
        if reply_to:
            _, reply_email = parseaddr(reply_to)
            if reply_email and reply_email != sender:
                sender_domain = sender.split("@")[1] if "@" in sender else ""
                reply_domain = reply_email.split("@")[1] if "@" in reply_email else ""
                
                if sender_domain != reply_domain:
                    issues.append(f"Suspicious: Reply-To domain ({reply_domain}) differs from sender ({sender_domain})")
        
        # Check Return-Path mismatch
        if return_path:
            _, return_email = parseaddr(return_path)
            if return_email and return_email != sender:
                warnings.append(f"Return-Path ({return_email}) differs from sender")
        
        # Check for disposable email
        sender_domain = sender.split("@")[1] if "@" in sender else ""
        if sender_domain.lower() in self.disposable_domains:
            issues.append("Sent from disposable/temporary email service")
        
        return {"issues": issues, "warnings": warnings}
    
    def _check_authentication(self, msg) -> Dict[str, Any]:
        """Check SPF, DKIM, and DMARC results"""
        issues = []
        warnings = []
        results = {}
        
        # Check Authentication-Results header
        auth_results = msg.get("Authentication-Results", "")
        
        # Parse SPF
        spf_match = re.search(r"spf=(\w+)", auth_results.lower())
        if spf_match:
            spf_result = spf_match.group(1)
            results["spf"] = spf_result
            if spf_result == "fail":
                issues.append("SPF authentication FAILED")
            elif spf_result == "softfail":
                warnings.append("SPF authentication soft-failed")
            elif spf_result != "pass":
                warnings.append(f"SPF result: {spf_result}")
        else:
            warnings.append("No SPF authentication found")
            results["spf"] = "none"
        
        # Parse DKIM
        dkim_match = re.search(r"dkim=(\w+)", auth_results.lower())
        if dkim_match:
            dkim_result = dkim_match.group(1)
            results["dkim"] = dkim_result
            if dkim_result == "fail":
                issues.append("DKIM signature FAILED")
            elif dkim_result != "pass":
                warnings.append(f"DKIM result: {dkim_result}")
        else:
            results["dkim"] = "none"
        
        # Parse DMARC
        dmarc_match = re.search(r"dmarc=(\w+)", auth_results.lower())
        if dmarc_match:
            dmarc_result = dmarc_match.group(1)
            results["dmarc"] = dmarc_result
            if dmarc_result == "fail":
                issues.append("DMARC policy check FAILED")
        else:
            results["dmarc"] = "none"
        
        results["issues"] = issues
        results["warnings"] = warnings
        
        return results
    
    def _check_patterns(
        self, 
        sender_email: str, 
        sender_name: str,
        subject: str
    ) -> Dict[str, Any]:
        """Check for suspicious patterns"""
        issues = []
        warnings = []
        
        # Check suspicious sender patterns
        for pattern in self.suspicious_patterns:
            if re.match(pattern, sender_email, re.IGNORECASE):
                warnings.append(f"Sender matches suspicious pattern")
                break
        
        # Check for display name spoofing (name contains email-like text)
        if "@" in sender_name or re.search(r"\.(com|org|net)", sender_name, re.I):
            issues.append("Potential display name spoofing detected")
        
        # Check for urgent/phishing subject keywords
        urgent_keywords = [
            "urgent", "immediate action", "account suspended",
            "verify your account", "confirm your identity",
            "unusual activity", "password expired", "final warning"
        ]
        
        subject_lower = subject.lower()
        for keyword in urgent_keywords:
            if keyword in subject_lower:
                warnings.append(f"Subject contains urgent/phishing keyword: '{keyword}'")
                break
        
        return {"issues": issues, "warnings": warnings}
    
    def _analyze_routing(self, received_headers: List[str]) -> Dict[str, Any]:
        """Analyze email routing path"""
        hops = []
        
        for header in received_headers[:10]:  # Limit to 10 hops
            # Extract server info
            from_match = re.search(r"from\s+([^\s]+)", header)
            by_match = re.search(r"by\s+([^\s]+)", header)
            
            hop = {
                "from": from_match.group(1) if from_match else "unknown",
                "by": by_match.group(1) if by_match else "unknown",
                "raw": header[:200]  # Truncate
            }
            hops.append(hop)
        
        return {
            "hop_count": len(received_headers),
            "hops": hops
        }
    
    def _generate_summary(
        self, 
        is_suspicious: bool, 
        issues: List[str], 
        warnings: List[str]
    ) -> str:
        """Generate human-readable summary"""
        if not is_suspicious and not issues and not warnings:
            return "✅ Email appears legitimate - no issues detected"
        elif issues:
            return f"🚨 SUSPICIOUS: {len(issues)} security issue(s) found"
        else:
            return f"⚠️ {len(warnings)} warning(s) - review recommended"


# Singleton instance
email_analyzer = EmailAnalyzer()
