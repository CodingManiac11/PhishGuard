import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from typing import Dict, Any, Tuple, List
import logging
import joblib
import os
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Trusted domains whitelist - major legitimate websites
TRUSTED_DOMAINS = {
    # Google services
    'google.com', 'www.google.com', 'gmail.com', 'youtube.com', 'www.youtube.com',
    'drive.google.com', 'docs.google.com', 'sheets.google.com', 'meet.google.com',
    'calendar.google.com', 'photos.google.com', 'play.google.com', 'maps.google.com',
    'accounts.google.com', 'mail.google.com', 'translate.google.com',
    # Regional Google
    'google.co.uk', 'google.de', 'google.fr', 'google.in', 'google.co.jp',
    
    # Microsoft services
    'microsoft.com', 'www.microsoft.com', 'office.com', 'outlook.com', 'live.com',
    'login.microsoftonline.com', 'azure.microsoft.com', 'portal.azure.com',
    'onedrive.live.com', 'teams.microsoft.com', 'sharepoint.com', 'bing.com',
    'linkedin.com', 'www.linkedin.com',
    
    # Amazon services
    'amazon.com', 'www.amazon.com', 'aws.amazon.com', 'console.aws.amazon.com',
    'amazon.co.uk', 'amazon.de', 'amazon.in', 'amazon.co.jp', 'amazon.ca',
    'primevideo.com', 'smile.amazon.com', 'alexa.amazon.com',
    
    # Apple services
    'apple.com', 'www.apple.com', 'icloud.com', 'appleid.apple.com',
    'support.apple.com', 'developer.apple.com', 'music.apple.com',
    
    # Meta/Facebook services
    'facebook.com', 'www.facebook.com', 'instagram.com', 'www.instagram.com',
    'messenger.com', 'whatsapp.com', 'web.whatsapp.com', 'meta.com',
    
    # Other major tech
    'twitter.com', 'x.com', 'github.com', 'www.github.com', 'gist.github.com',
    'stackoverflow.com', 'www.stackoverflow.com', 'stackexchange.com',
    'reddit.com', 'www.reddit.com', 'old.reddit.com',
    'wikipedia.org', 'www.wikipedia.org', 'en.wikipedia.org',
    'yahoo.com', 'www.yahoo.com', 'mail.yahoo.com',
    'netflix.com', 'www.netflix.com',
    'spotify.com', 'open.spotify.com',
    'dropbox.com', 'www.dropbox.com',
    'adobe.com', 'www.adobe.com', 'creativecloud.adobe.com',
    'zoom.us', 'zoom.com',
    'slack.com', 'app.slack.com',
    'discord.com', 'discord.gg',
    'twitch.tv', 'www.twitch.tv',
    
    # Financial services
    'paypal.com', 'www.paypal.com',
    'ebay.com', 'www.ebay.com',
    'stripe.com', 'dashboard.stripe.com',
    'chase.com', 'www.chase.com', 'secure.chase.com',
    'bankofamerica.com', 'www.bankofamerica.com',
    'wellsfargo.com', 'www.wellsfargo.com',
    'citibank.com', 'www.citibank.com',
    'capitalone.com', 'www.capitalone.com',
    'americanexpress.com', 'www.americanexpress.com',
    'discover.com', 'www.discover.com',
    'visa.com', 'www.visa.com',
    'mastercard.com', 'www.mastercard.com',
    
    # Enterprise/Business
    'salesforce.com', 'www.salesforce.com',
    'oracle.com', 'www.oracle.com',
    'ibm.com', 'www.ibm.com',
    'sap.com', 'www.sap.com',
    'atlassian.com', 'www.atlassian.com', 'jira.atlassian.com',
    'hubspot.com', 'www.hubspot.com',
    
    # Government & Education
    'gov.uk', 'irs.gov', 'usa.gov', 'ssa.gov',
    'edu', 'harvard.edu', 'mit.edu', 'stanford.edu',
    
    # Crypto & Finance
    'coinbase.com', 'www.coinbase.com',
    'binance.com', 'www.binance.com',
    'blockchain.com', 'www.blockchain.com',
    
    # Shopping
    'etsy.com', 'www.etsy.com',
    'walmart.com', 'www.walmart.com',
    'target.com', 'www.target.com',
    'bestbuy.com', 'www.bestbuy.com',
    'homedepot.com', 'www.homedepot.com',
    
    # Travel
    'booking.com', 'www.booking.com',
    'airbnb.com', 'www.airbnb.com',
    'expedia.com', 'www.expedia.com',
    'tripadvisor.com', 'www.tripadvisor.com',
    
    # Legitimate Hosting Platforms (user deployments)
    'vercel.app', 'netlify.app', 'github.io', 'gitlab.io',
    'pages.dev', 'fly.dev', 'render.com', 'railway.app',
    'herokuapp.com', 'glitch.me', 'replit.dev',
    
    # Video & Media
    'youtu.be', 'vimeo.com', 'dailymotion.com',
    'tiktok.com', 'www.tiktok.com',
}


class HybridClassifier:
    def __init__(self):
        # Use ensemble of models for better precision
        self.models = {
            'rf': RandomForestClassifier(
                n_estimators=100, 
                random_state=42, 
                class_weight='balanced',
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2
            ),
            'gb': GradientBoostingClassifier(
                n_estimators=50,
                random_state=42,
                learning_rate=0.1,
                max_depth=6
            ),
            'lr': LogisticRegression(
                random_state=42, 
                max_iter=1000, 
                class_weight='balanced',
                C=0.1
            )
        }
        
        self.scaler = StandardScaler()
        self.feature_names = []
        self.is_fitted = False
        self.feature_importance = {}
        
        # Enhanced classification thresholds
        self.thresholds = {
            'phishing': 0.7,      # Higher threshold for phishing (more precision)
            'suspicious': 0.4,    # Medium threshold for suspicious
        }
        
        self._initialize_with_synthetic_data()
    
    def _initialize_with_synthetic_data(self):
        """Bootstrap the models with enhanced synthetic training data"""
        synthetic_data = self._generate_enhanced_synthetic_data()
        
        if len(synthetic_data) > 0:
            X, y = self._prepare_training_data(synthetic_data)
            self._train_models(X, y)
            logger.info(f"Initialized models with {len(synthetic_data)} synthetic samples")
    
    def _generate_enhanced_synthetic_data(self) -> List[Dict[str, Any]]:
        """Generate more comprehensive synthetic training examples"""
        synthetic_samples = []
        
        # High-confidence phishing examples - diverse patterns
        phishing_samples = [
            # Pattern 1: Classic phishing with brand impersonation + urgency
            {
                'url_length': 95, 'hostname_length': 32, 'subdomain_count': 4,
                'has_ip_address': False, 'has_suspicious_tld': True, 'dash_count': 5,
                'digit_count': 8, 'phishing_keyword_count': 3, 'url_entropy': 4.5,
                'hostname_entropy': 4.2, 'randomness_score': 0.8, 'brand_impersonation_score': 0.9,
                'has_forms': True, 'form_count': 2, 'has_password_input': True,
                'password_input_count': 2, 'phishing_keyword_density': 0.15,
                'urgent_keyword_count': 3, 'security_keyword_count': 4,
                'suspicious_title': 0.8, 'external_links_count': 12,
                'external_link_ratio': 0.9, 'suspicious_link_count': 6,
                'has_homograph_chars': True, 'certificate_warnings': True,
                'countdown_timer_present': True, 'obfuscated_content': True,
                'spelling_error_indicators': 0.3, 'domain_age_days': 3,
                'label': 'phishing'
            },
            # Pattern 2: IP address phishing
            {
                'url_length': 120, 'hostname_length': 45, 'subdomain_count': 5,
                'has_ip_address': True, 'has_suspicious_tld': False, 'dash_count': 3,
                'digit_count': 12, 'phishing_keyword_count': 4, 'url_entropy': 4.8,
                'hostname_entropy': 4.5, 'randomness_score': 0.9, 'brand_impersonation_score': 0.85,
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.12,
                'urgent_keyword_count': 2, 'security_keyword_count': 5,
                'suspicious_title': 0.9, 'external_links_count': 8,
                'external_link_ratio': 0.8, 'suspicious_link_count': 4,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': True,
                'spelling_error_indicators': 0.2, 'domain_age_days': 1,
                'label': 'phishing'
            },
            # Pattern 3: Free hosting service abuse (000webhost, etc.)
            {
                'url_length': 85, 'hostname_length': 38, 'subdomain_count': 2,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 4,
                'digit_count': 6, 'phishing_keyword_count': 2, 'url_entropy': 4.2,
                'hostname_entropy': 4.0, 'randomness_score': 0.7, 'brand_impersonation_score': 0.8,
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.10,
                'urgent_keyword_count': 2, 'security_keyword_count': 3,
                'suspicious_title': 0.7, 'external_links_count': 5,
                'external_link_ratio': 0.6, 'suspicious_link_count': 3,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': True, 'obfuscated_content': False,
                'spelling_error_indicators': 0.25, 'domain_age_days': 7,
                'label': 'phishing'
            },
            # Pattern 4: Typosquatting attack (g00gle, amaz0n style)
            {
                'url_length': 45, 'hostname_length': 18, 'subdomain_count': 1,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 1,
                'digit_count': 2, 'phishing_keyword_count': 1, 'url_entropy': 3.5,
                'hostname_entropy': 3.2, 'randomness_score': 0.3, 'brand_impersonation_score': 0.95,
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.08,
                'urgent_keyword_count': 1, 'security_keyword_count': 2,
                'suspicious_title': 0.6, 'external_links_count': 3,
                'external_link_ratio': 0.4, 'suspicious_link_count': 2,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.1, 'domain_age_days': 14,
                'label': 'phishing'
            },
            # Pattern 5: ngrok/tunnel service abuse
            {
                'url_length': 75, 'hostname_length': 35, 'subdomain_count': 2,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 2,
                'digit_count': 10, 'phishing_keyword_count': 2, 'url_entropy': 4.6,
                'hostname_entropy': 4.3, 'randomness_score': 0.85, 'brand_impersonation_score': 0.7,
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.09,
                'urgent_keyword_count': 1, 'security_keyword_count': 2,
                'suspicious_title': 0.5, 'external_links_count': 4,
                'external_link_ratio': 0.5, 'suspicious_link_count': 2,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': True,
                'spelling_error_indicators': 0.15, 'domain_age_days': 0,
                'label': 'phishing'
            },
            # Pattern 6: Banking/PayPal impersonation
            {
                'url_length': 110, 'hostname_length': 42, 'subdomain_count': 4,
                'has_ip_address': False, 'has_suspicious_tld': True, 'dash_count': 6,
                'digit_count': 5, 'phishing_keyword_count': 5, 'url_entropy': 4.4,
                'hostname_entropy': 4.1, 'randomness_score': 0.6, 'brand_impersonation_score': 0.92,
                'has_forms': True, 'form_count': 2, 'has_password_input': True,
                'password_input_count': 2, 'phishing_keyword_density': 0.18,
                'urgent_keyword_count': 4, 'security_keyword_count': 6,
                'suspicious_title': 0.85, 'external_links_count': 6,
                'external_link_ratio': 0.7, 'suspicious_link_count': 4,
                'has_homograph_chars': False, 'certificate_warnings': True,
                'countdown_timer_present': True, 'obfuscated_content': False,
                'spelling_error_indicators': 0.2, 'domain_age_days': 5,
                'label': 'phishing'
            },
            # Pattern 7: Cryptocurrency scam pattern
            {
                'url_length': 88, 'hostname_length': 30, 'subdomain_count': 3,
                'has_ip_address': False, 'has_suspicious_tld': True, 'dash_count': 3,
                'digit_count': 7, 'phishing_keyword_count': 3, 'url_entropy': 4.3,
                'hostname_entropy': 4.0, 'randomness_score': 0.75, 'brand_impersonation_score': 0.85,
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.12,
                'urgent_keyword_count': 3, 'security_keyword_count': 3,
                'suspicious_title': 0.7, 'external_links_count': 8,
                'external_link_ratio': 0.75, 'suspicious_link_count': 5,
                'has_homograph_chars': True, 'certificate_warnings': False,
                'countdown_timer_present': True, 'obfuscated_content': True,
                'spelling_error_indicators': 0.18, 'domain_age_days': 2,
                'label': 'phishing'
            },
            # Pattern 8: Social media account phishing
            {
                'url_length': 72, 'hostname_length': 28, 'subdomain_count': 3,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 4,
                'digit_count': 4, 'phishing_keyword_count': 2, 'url_entropy': 4.0,
                'hostname_entropy': 3.8, 'randomness_score': 0.55, 'brand_impersonation_score': 0.88,
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.07,
                'urgent_keyword_count': 2, 'security_keyword_count': 2,
                'suspicious_title': 0.65, 'external_links_count': 4,
                'external_link_ratio': 0.5, 'suspicious_link_count': 2,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.12, 'domain_age_days': 10,
                'label': 'phishing'
            },
        ]
        
        # Suspicious examples (medium confidence) - more variety
        suspicious_samples = [
            # Pattern 1: Moderately suspicious URL
            {
                'url_length': 65, 'hostname_length': 25, 'subdomain_count': 2,
                'has_ip_address': False, 'has_suspicious_tld': True, 'dash_count': 2,
                'digit_count': 4, 'phishing_keyword_count': 1, 'url_entropy': 3.8,
                'hostname_entropy': 3.5, 'randomness_score': 0.4, 'brand_impersonation_score': 0.6,
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.05,
                'urgent_keyword_count': 1, 'security_keyword_count': 2,
                'suspicious_title': 0.4, 'external_links_count': 5,
                'external_link_ratio': 0.5, 'suspicious_link_count': 1,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.1, 'domain_age_days': 30,
                'label': 'suspicious'
            },
            # Pattern 2: New domain with some red flags
            {
                'url_length': 55, 'hostname_length': 20, 'subdomain_count': 1,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 2,
                'digit_count': 3, 'phishing_keyword_count': 1, 'url_entropy': 3.5,
                'hostname_entropy': 3.2, 'randomness_score': 0.35, 'brand_impersonation_score': 0.4,
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.04,
                'urgent_keyword_count': 1, 'security_keyword_count': 1,
                'suspicious_title': 0.3, 'external_links_count': 4,
                'external_link_ratio': 0.45, 'suspicious_link_count': 1,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.08, 'domain_age_days': 45,
                'label': 'suspicious'
            },
            # Pattern 3: Borderline case with urgency language
            {
                'url_length': 58, 'hostname_length': 22, 'subdomain_count': 1,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 1,
                'digit_count': 2, 'phishing_keyword_count': 2, 'url_entropy': 3.4,
                'hostname_entropy': 3.1, 'randomness_score': 0.25, 'brand_impersonation_score': 0.3,
                'has_forms': True, 'form_count': 1, 'has_password_input': False,
                'password_input_count': 0, 'phishing_keyword_density': 0.06,
                'urgent_keyword_count': 2, 'security_keyword_count': 1,
                'suspicious_title': 0.35, 'external_links_count': 6,
                'external_link_ratio': 0.55, 'suspicious_link_count': 2,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.05, 'domain_age_days': 60,
                'label': 'suspicious'
            },
        ]
        
        # Benign examples - more diversity for better precision
        benign_samples = [
            # Pattern 1: Standard corporate site
            {
                'url_length': 35, 'hostname_length': 15, 'subdomain_count': 1,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 0,
                'digit_count': 0, 'phishing_keyword_count': 0, 'url_entropy': 2.8,
                'hostname_entropy': 2.5, 'randomness_score': 0.1, 'brand_impersonation_score': 0.0,
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.01,
                'urgent_keyword_count': 0, 'security_keyword_count': 1,
                'suspicious_title': 0.0, 'external_links_count': 2,
                'external_link_ratio': 0.2, 'suspicious_link_count': 0,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.0, 'domain_age_days': 1095,
                'label': 'benign'
            },
            # Pattern 2: Simple blog/content site
            {
                'url_length': 28, 'hostname_length': 12, 'subdomain_count': 0,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 0,
                'digit_count': 0, 'phishing_keyword_count': 0, 'url_entropy': 2.5,
                'hostname_entropy': 2.2, 'randomness_score': 0.05, 'brand_impersonation_score': 0.0,
                'has_forms': False, 'form_count': 0, 'has_password_input': False,
                'password_input_count': 0, 'phishing_keyword_density': 0.0,
                'urgent_keyword_count': 0, 'security_keyword_count': 0,
                'suspicious_title': 0.0, 'external_links_count': 3,
                'external_link_ratio': 0.3, 'suspicious_link_count': 0,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.0, 'domain_age_days': 2190,
                'label': 'benign'
            },
            # Pattern 3: E-commerce legitimate site
            {
                'url_length': 50, 'hostname_length': 18, 'subdomain_count': 1,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 1,
                'digit_count': 0, 'phishing_keyword_count': 0, 'url_entropy': 3.0,
                'hostname_entropy': 2.7, 'randomness_score': 0.12, 'brand_impersonation_score': 0.0,
                'has_forms': True, 'form_count': 2, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.02,
                'urgent_keyword_count': 0, 'security_keyword_count': 2,
                'suspicious_title': 0.0, 'external_links_count': 5,
                'external_link_ratio': 0.25, 'suspicious_link_count': 0,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.0, 'domain_age_days': 1825,
                'label': 'benign'
            },
            # Pattern 4: Banking legitimate site with login
            {
                'url_length': 42, 'hostname_length': 16, 'subdomain_count': 1,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 0,
                'digit_count': 0, 'phishing_keyword_count': 1, 'url_entropy': 2.9,
                'hostname_entropy': 2.6, 'randomness_score': 0.08, 'brand_impersonation_score': 0.0,
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.03,
                'urgent_keyword_count': 0, 'security_keyword_count': 3,
                'suspicious_title': 0.1, 'external_links_count': 4,
                'external_link_ratio': 0.2, 'suspicious_link_count': 0,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.0, 'domain_age_days': 3650,
                'label': 'benign'
            },
            # Pattern 5: Tech company with subdomain
            {
                'url_length': 55, 'hostname_length': 22, 'subdomain_count': 2,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 1,
                'digit_count': 0, 'phishing_keyword_count': 0, 'url_entropy': 3.1,
                'hostname_entropy': 2.8, 'randomness_score': 0.1, 'brand_impersonation_score': 0.0,
                'has_forms': True, 'form_count': 1, 'has_password_input': True,
                'password_input_count': 1, 'phishing_keyword_density': 0.01,
                'urgent_keyword_count': 0, 'security_keyword_count': 1,
                'suspicious_title': 0.0, 'external_links_count': 8,
                'external_link_ratio': 0.35, 'suspicious_link_count': 0,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.0, 'domain_age_days': 2555,
                'label': 'benign'
            },
            # Pattern 6: Government/educational site
            {
                'url_length': 40, 'hostname_length': 14, 'subdomain_count': 1,
                'has_ip_address': False, 'has_suspicious_tld': False, 'dash_count': 0,
                'digit_count': 0, 'phishing_keyword_count': 0, 'url_entropy': 2.6,
                'hostname_entropy': 2.3, 'randomness_score': 0.05, 'brand_impersonation_score': 0.0,
                'has_forms': True, 'form_count': 1, 'has_password_input': False,
                'password_input_count': 0, 'phishing_keyword_density': 0.0,
                'urgent_keyword_count': 0, 'security_keyword_count': 0,
                'suspicious_title': 0.0, 'external_links_count': 10,
                'external_link_ratio': 0.4, 'suspicious_link_count': 0,
                'has_homograph_chars': False, 'certificate_warnings': False,
                'countdown_timer_present': False, 'obfuscated_content': False,
                'spelling_error_indicators': 0.0, 'domain_age_days': 5475,
                'label': 'benign'
            },
        ]
        
        # Create balanced training dataset with more samples
        synthetic_samples.extend(phishing_samples * 4)  # 32 phishing samples
        synthetic_samples.extend(suspicious_samples * 5)  # 15 suspicious samples
        synthetic_samples.extend(benign_samples * 6)  # 36 benign samples
        
        return synthetic_samples
    
    def _prepare_training_data(self, samples: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Convert samples to feature matrix and labels"""
        X_list = []
        y_list = []
        
        for sample in samples:
            label = sample.pop('label')
            
            # Convert features to numeric values
            feature_vector = []
            for key, value in sample.items():
                if isinstance(value, bool):
                    feature_vector.append(1.0 if value else 0.0)
                elif isinstance(value, (int, float)):
                    feature_vector.append(float(value))
                else:
                    feature_vector.append(0.0)
            
            X_list.append(feature_vector)
            
            # Convert labels to numeric
            if label == 'phishing':
                y_list.append(2)
            elif label == 'suspicious':
                y_list.append(1)
            else:  # benign
                y_list.append(0)
                
            # Re-add label for consistency
            sample['label'] = label
        
        # Store feature names from first sample
        if self.feature_names == [] and len(samples) > 0:
            sample_copy = samples[0].copy()
            sample_copy.pop('label', None)
            self.feature_names = list(sample_copy.keys())
        
        return np.array(X_list), np.array(y_list)
    
    def _train_models(self, X: np.ndarray, y: np.ndarray):
        """Train all models in the ensemble"""
        try:
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train each model
            for name, model in self.models.items():
                model.fit(X_scaled, y)
                logger.info(f"Trained {name} model with {len(X)} samples")
            
            # Calculate feature importance from Random Forest
            if 'rf' in self.models and self.feature_names:
                importance = self.models['rf'].feature_importances_
                self.feature_importance = dict(zip(self.feature_names, importance))
            
            self.is_fitted = True
            
        except Exception as e:
            logger.error(f"Error training models: {e}")
            raise
    
    def _ensemble_predict(self, X: np.ndarray) -> Tuple[np.ndarray, Dict[str, float]]:
        """Make predictions using ensemble of models"""
        if not self.is_fitted:
            raise ValueError("Models not fitted yet")
        
        X_scaled = self.scaler.transform(X)
        predictions = {}
        probabilities = {}
        
        # Get predictions from each model
        for name, model in self.models.items():
            pred = model.predict(X_scaled)
            pred_proba = model.predict_proba(X_scaled)
            predictions[name] = pred
            probabilities[name] = pred_proba
        
        # Ensemble voting with weighted average
        weights = {'rf': 0.4, 'gb': 0.4, 'lr': 0.2}  # RF and GB are more reliable
        
        final_probabilities = np.zeros((X.shape[0], 3))  # 3 classes: benign, suspicious, phishing
        
        for name, weight in weights.items():
            if name in probabilities:
                final_probabilities += weight * probabilities[name]
        
        # Get final predictions based on enhanced thresholds
        final_predictions = []
        confidence_scores = {}
        
        for i in range(X.shape[0]):
            proba = final_probabilities[i]
            phishing_prob = proba[2]  # Class 2 = phishing
            suspicious_prob = proba[1]  # Class 1 = suspicious
            benign_prob = proba[0]     # Class 0 = benign
            
            # Enhanced classification logic
            if phishing_prob >= self.thresholds['phishing']:
                final_predictions.append(2)
                risk_level = 'high'
            elif suspicious_prob >= self.thresholds['suspicious'] or phishing_prob >= 0.3:
                final_predictions.append(1)
                risk_level = 'medium'
            else:
                final_predictions.append(0)
                risk_level = 'low'
            
            confidence_scores[f'sample_{i}'] = {
                'phishing_probability': float(phishing_prob),
                'suspicious_probability': float(suspicious_prob),
                'benign_probability': float(benign_prob),
                'risk_level': risk_level,
                'confidence': float(max(proba))
            }
        
        return np.array(final_predictions), confidence_scores
    
    def _is_trusted_domain(self, url: str) -> bool:
        """Check if domain is in trusted whitelist or is a subdomain of trusted platform"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Check exact match first
            if domain in TRUSTED_DOMAINS:
                return True
            
            # Check if it's a subdomain of a trusted platform
            # This handles cases like myapp.vercel.app, user.github.io, etc.
            hosting_platforms = [
                'vercel.app', 'netlify.app', 'github.io', 'gitlab.io',
                'pages.dev', 'fly.dev', 'render.com', 'railway.app',
                'herokuapp.com', 'glitch.me', 'replit.dev', 'web.app',
                'firebaseapp.com', 'azurewebsites.net', 'cloudfront.net'
            ]
            
            for platform in hosting_platforms:
                if domain.endswith('.' + platform) or domain == platform:
                    return True
            
            # Check if subdomain of major trusted domains (e.g., docs.google.com)
            for trusted in TRUSTED_DOMAINS:
                if domain.endswith('.' + trusted):
                    return True
                    
            return False
        except Exception:
            return False

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Make prediction for a single URL"""
        try:
            # Check if domain is trusted first
            url = features.get('url', '')
            if url and self._is_trusted_domain(url):
                logger.info(f"Domain recognized as trusted: {url}")
                return {
                    'prediction': 'benign',
                    'confidence': 0.99,
                    'confidence_score': 0.99,
                    'threat_level': 'LOW',
                    'phishing_probability': 0.01,
                    'suspicious_probability': 0.01,
                    'benign_probability': 0.99,
                    'risk_factors': [],
                    'explanation': 'This domain is recognized as a trusted, legitimate website.',
                    'model_explanation': 'Domain whitelist: Recognized as trusted legitimate website'
                }
            
            if not self.is_fitted:
                # Try to load saved model or use default
                self._initialize_with_synthetic_data()
            
            # Convert features to array
            feature_vector = []
            for feature_name in self.feature_names:
                value = features.get(feature_name, 0)
                if isinstance(value, bool):
                    feature_vector.append(1.0 if value else 0.0)
                elif isinstance(value, (int, float)):
                    feature_vector.append(float(value))
                else:
                    feature_vector.append(0.0)
            
            X = np.array([feature_vector])
            predictions, confidence_scores = self._ensemble_predict(X)
            
            prediction = predictions[0]
            sample_confidence = confidence_scores.get('sample_0', {})
            
            # Map prediction to label
            if prediction == 2:
                prediction_label = 'phishing'
                threat_level = 'HIGH'
            elif prediction == 1:
                prediction_label = 'suspicious'
                threat_level = 'MEDIUM'
            else:
                prediction_label = 'benign'
                threat_level = 'LOW'
            
            # Get risk factors
            risk_factors = self._identify_risk_factors(features)
            
            # AGGRESSIVE PHISHING DETECTION - Check for obvious phishing patterns first
            obvious_phishing_indicators = []
            
            # Brand impersonation with suspicious subdomains (major red flag)
            if (features.get('subdomain_count', 0) >= 2 and 
                any(brand in features.get('hostname_length', 0) for brand in ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'twitter', 'instagram', 'allegro', 'ebay', 'netflix']) if isinstance(features.get('hostname_length'), str) else False):
                obvious_phishing_indicators.append('Brand impersonation with suspicious subdomains')
            
            # Multiple suspicious subdomains (often used in phishing)
            if features.get('subdomain_count', 0) >= 3:
                obvious_phishing_indicators.append('Multiple suspicious subdomains')
            
            # Very long domain names with numbers (common phishing pattern)
            if features.get('hostname_length', 0) > 30 and features.get('digit_count', 0) >= 8:
                obvious_phishing_indicators.append('Very long domain with many numbers')
            
            # Domain age less than 7 days (fresh phishing domains)
            if features.get('domain_age_days', 365) < 7 and features.get('domain_age_days', 365) != -1:
                obvious_phishing_indicators.append('Extremely new domain (less than 7 days)')
            
            # No HTTPS on suspicious domain
            if not features.get('uses_https', True) and features.get('subdomain_count', 0) >= 2:
                obvious_phishing_indicators.append('No HTTPS with suspicious subdomains')
            
            # If we have obvious phishing indicators, upgrade aggressively
            if len(obvious_phishing_indicators) >= 2:
                prediction_label = 'phishing'
                threat_level = 'HIGH'
                risk_factors.extend(obvious_phishing_indicators)
            elif len(obvious_phishing_indicators) >= 1:
                prediction_label = 'suspicious'
                threat_level = 'MEDIUM'
                risk_factors.extend(obvious_phishing_indicators)
            
            # Standard threat level upgrading based on risk factors
            elif threat_level == 'LOW' and len(risk_factors) >= 2:
                # Multiple risk factors should elevate to suspicious
                prediction_label = 'suspicious'
                threat_level = 'MEDIUM'
            elif threat_level == 'MEDIUM' and len(risk_factors) >= 3:
                # Many risk factors should elevate to high threat
                prediction_label = 'phishing'
                threat_level = 'HIGH'
            
            # Additional special cases for highly suspicious patterns
            suspicious_patterns = [
                features.get('has_ip_address', False),
                features.get('has_homograph_chars', False),
                features.get('brand_impersonation_score', 0) > 0.5,
                features.get('phishing_keyword_count', 0) > 2,
                features.get('url_length', 0) > 100,
                features.get('subdomain_count', 0) > 3,
                not features.get('uses_https', True),
                features.get('domain_age_days', 365) < 7,
                # Enhanced: Hosted infrastructure patterns
                features.get('is_hosted_infrastructure', False) and features.get('hosted_service_type') in ['ngrok', 'tunnel_service', 'free_hosting'],
                features.get('has_suspicious_tld', False),
                features.get('randomness_score', 0) > 0.8,
                # NEW: Malware detection patterns
                features.get('has_suspicious_file_extension', False),
                features.get('has_short_random_path', False),
                features.get('has_uncommon_tld', False),
                features.get('http_without_https', False) and features.get('has_suspicious_file_extension', False),  # HTTP + download = very suspicious
            ]
            
            # CRITICAL: Immediate phishing classification for dangerous combinations
            # HTTP + suspicious file extension = likely malware download
            if features.get('http_without_https', False) and features.get('has_suspicious_file_extension', False):
                prediction_label = 'phishing'
                threat_level = 'HIGH'
                risk_factors.append('HTTP download with suspicious file extension (likely malware)')
            # Short random path + suspicious extension = malware
            elif features.get('has_short_random_path', False) and features.get('has_suspicious_file_extension', False):
                prediction_label = 'phishing'
                threat_level = 'HIGH'
                risk_factors.append('Random URL path with executable file (likely malware distribution)')
            elif sum(suspicious_patterns) >= 2 and threat_level == 'LOW':
                prediction_label = 'suspicious' 
                threat_level = 'MEDIUM'
            elif sum(suspicious_patterns) >= 3:
                prediction_label = 'phishing'
                threat_level = 'HIGH'
            
            result = {
                'prediction': prediction_label,
                'threat_level': threat_level,
                'confidence_score': sample_confidence.get('confidence', 0.5),
                'phishing_probability': sample_confidence.get('phishing_probability', 0.0),
                'risk_factors': risk_factors,
                'model_explanation': self._explain_prediction(features, {
                    'risk_level': threat_level.lower(),
                    'confidence': sample_confidence.get('confidence', 0.5),
                    'prediction': prediction_label,
                    'threat_level': threat_level
                })
            }
            
            logger.info(f"Prediction: {prediction_label} (confidence: {result['confidence_score']:.3f})")
            return result
            
        except Exception as e:
            logger.error(f"Error making prediction: {e}")
            # Return conservative prediction
            return {
                'prediction': 'suspicious',
                'threat_level': 'MEDIUM',
                'confidence_score': 0.5,
                'phishing_probability': 0.5,
                'risk_factors': ['Error in prediction model'],
                'model_explanation': f'Model error: {str(e)}'
            }
    
    def _identify_risk_factors(self, features: Dict[str, Any]) -> List[str]:
        """Identify specific risk factors based on feature values"""
        risk_factors = []
        
        # AGGRESSIVE BRAND IMPERSONATION DETECTION
        hostname = features.get('hostname', '').lower()
        known_brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 
                       'twitter', 'instagram', 'allegro', 'ebay', 'netflix', 'linkedin',
                       'github', 'dropbox', 'wordpress', 'shopify', 'stripe', 'visa',
                       'mastercard', 'americanexpress', 'discover']
        
        # Check for brand impersonation patterns in hostname
        for brand in known_brands:
            if brand in hostname and not hostname.startswith(brand + '.'):
                # Brand name appears but not as the main domain (likely impersonation)
                if features.get('subdomain_count', 0) >= 1:
                    risk_factors.append(f'Potential {brand.title()} brand impersonation with subdomains')
        
        # URL-based risks
        if features.get('has_ip_address', False):
            risk_factors.append('URL contains IP address instead of domain name')
        
        if features.get('url_length', 0) > 80:
            risk_factors.append('Unusually long URL')
        
        if features.get('subdomain_count', 0) > 2:
            risk_factors.append('Multiple suspicious subdomains')
        
        # Aggressive detection of suspicious domain patterns
        if features.get('hostname_length', 0) > 30 and features.get('digit_count', 0) >= 5:
            risk_factors.append('Very long domain name with many numbers')
        
        if features.get('has_suspicious_tld', False):
            risk_factors.append('Suspicious top-level domain')
        
        if features.get('dash_count', 0) > 3:
            risk_factors.append('Excessive dashes in URL (typosquatting)')
        
        if features.get('brand_impersonation_score', 0) > 0.7:
            risk_factors.append('Potential brand impersonation detected')
        
        if features.get('has_homograph_chars', False):
            risk_factors.append('Homograph/Unicode spoofing characters detected')
        
        # Content-based risks
        if features.get('has_password_input', False) and features.get('certificate_warnings', False):
            risk_factors.append('Password input on insecure connection')
        
        if features.get('phishing_keyword_density', 0) > 0.1:
            risk_factors.append('High density of phishing-related keywords')
        
        if features.get('urgent_keyword_count', 0) > 2:
            risk_factors.append('Urgent language designed to create pressure')
        
        if features.get('countdown_timer_present', False):
            risk_factors.append('Countdown timer creating false urgency')
        
        if features.get('obfuscated_content', False):
            risk_factors.append('Content obfuscation detected')
        
        if features.get('spelling_error_indicators', 0) > 0.2:
            risk_factors.append('High number of spelling errors')
        
        # Domain-based risks  
        if features.get('domain_age_days', 365) < 30:
            risk_factors.append('Very new domain (less than 30 days old)')
        
        # Hosted infrastructure risks
        if features.get('is_hosted_infrastructure', False):
            service_type = features.get('hosted_service_type', 'unknown')
            if service_type == 'ngrok':
                risk_factors.append('Using ngrok tunneling service (high risk)')
            elif service_type == 'cloudflare_tunnel':
                risk_factors.append('Using Cloudflare tunnel (medium risk)')
            elif service_type == 'tunnel_service':
                risk_factors.append('Using tunneling service (suspicious)')
            elif service_type == 'dev_platform':
                risk_factors.append('Hosted on development platform')
            elif service_type == 'free_hosting':
                risk_factors.append('Using free hosting service (suspicious)')
            elif service_type == 'dynamic_dns':
                risk_factors.append('Using dynamic DNS service')
            else:
                risk_factors.append('Using hosted infrastructure service')
        
        return risk_factors
    
    def _explain_prediction(self, features: Dict[str, Any], confidence_info: Dict[str, Any]) -> str:
        """Generate human-readable explanation of the prediction"""
        threat_level = confidence_info.get('risk_level', 'unknown')
        confidence = confidence_info.get('confidence', 0.5)
        prediction = confidence_info.get('prediction', 'unknown')
        
        if threat_level == 'high' or prediction == 'phishing':
            explanation = f"🚨 PHISHING DETECTED: This URL shows strong indicators of phishing (confidence: {confidence:.1%}). "
        elif threat_level == 'medium' or prediction == 'suspicious':
            explanation = f"⚠️ SUSPICIOUS: This URL has concerning characteristics (confidence: {confidence:.1%}). "
        else:
            explanation = f"✅ SAFE: This URL appears legitimate (confidence: {confidence:.1%}). "
        
        # Add key contributing factors
        key_factors = []
        if features.get('brand_impersonation_score', 0) > 0.7:
            key_factors.append("brand impersonation")
        if features.get('has_homograph_chars', False):
            key_factors.append("character spoofing")
        if features.get('phishing_keyword_density', 0) > 0.1:
            key_factors.append("phishing keywords")
        if features.get('urgent_keyword_count', 0) > 2:
            key_factors.append("urgency tactics")
        if features.get('has_ip_address', False):
            key_factors.append("IP address in URL")
        if features.get('is_hosted_infrastructure', False):
            key_factors.append("hosted infrastructure")
        
        if key_factors:
            explanation += f"Key concerns: {', '.join(key_factors)}."
        
        return explanation
    
    def retrain(self, new_samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Retrain the model with new samples"""
        try:
            logger.info(f"Retraining with {len(new_samples)} new samples")
            
            if len(new_samples) == 0:
                return {'status': 'error', 'message': 'No samples provided for retraining'}
            
            X, y = self._prepare_training_data(new_samples)
            
            # If we have existing model, combine with new data
            if self.is_fitted:
                # For now, just retrain on new data
                # In production, you might want to combine old and new data
                pass
            
            self._train_models(X, y)
            
            return {
                'status': 'success',
                'message': f'Model retrained with {len(new_samples)} samples',
                'feature_count': len(self.feature_names),
                'model_types': list(self.models.keys())
            }
            
        except Exception as e:
            logger.error(f"Error retraining model: {e}")
            return {'status': 'error', 'message': f'Retraining failed: {str(e)}'}
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        return {
            'is_fitted': self.is_fitted,
            'feature_count': len(self.feature_names),
            'feature_names': self.feature_names,
            'model_types': list(self.models.keys()) if self.models else [],
            'thresholds': self.thresholds,
            'top_features': dict(sorted(
                self.feature_importance.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]) if self.feature_importance else {}
        }
