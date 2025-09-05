#
# This is the complete and fixed code for your feature.py file.
# Replace the entire content of your file with this code.
#
import ipaddress
import re
import socket
from datetime import datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from googlesearch import search
from whois import whois, parser as whois_parser

class FeatureExtraction:
    """
    Extracts 30 phishing website features from a given URL.
    The class is designed to be robust against network errors and invalid URLs.
    """
    def __init__(self, url):
        self.url = url
        self.features = []
        
        # Initialize all necessary components to None
        self.urlparse = None
        self.response = None
        self.whois_response = None
        self.soup = None
        self.domain = ""

        # --- Data Fetching ---
        # All network-dependent operations are wrapped in try-except blocks
        # to prevent the application from crashing.

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except Exception:
            pass  # Failsafe for malformed URLs

        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except requests.exceptions.RequestException:
            # This handles connection errors, timeouts, etc.
            pass

        try:
            self.whois_response = whois(self.domain)
        except (whois_parser.PywhoisError, socket.gaierror, ConnectionResetError):
            # Handles domains that don't have a WHOIS record or network issues
            pass
        
        # --- Feature Calculation ---
        # Append all 30 features to the list.
        self.features.append(self.using_ip())
        self.features.append(self.long_url())
        self.features.append(self.short_url())
        self.features.append(self.has_at_symbol())
        self.features.append(self.has_redirect())
        self.features.append(self.has_prefix_suffix())
        self.features.append(self.count_subdomains())
        self.features.append(self.is_https())
        self.features.append(self.domain_reg_len())
        self.features.append(self.favicon())
        self.features.append(self.non_std_port())
        self.features.append(self.https_in_domain())
        self.features.append(self.request_url())
        self.features.append(self.anchor_url())
        self.features.append(self.links_in_tags())
        self.features.append(self.sfh())
        self.features.append(self.submit_to_email())
        self.features.append(self.abnormal_url())
        self.features.append(self.website_forwarding())
        self.features.append(self.statusbar_cust())
        self.features.append(self.disable_right_click())
        self.features.append(self.popup_window())
        self.features.append(self.iframe())
        self.features.append(self.age_of_domain())
        self.features.append(self.dns_record())
        self.features.append(self.website_traffic())
        self.features.append(self.page_rank())
        self.features.append(self.google_index())
        self.features.append(self.links_pointing_to_page())
        self.features.append(self.stats_report())

    def get_features_list(self):
        return self.features

    # 1. Using IP Address
    def using_ip(self):
        try:
            ipaddress.ip_address(self.domain)
            return -1
        except ValueError:
            return 1

    # 2. Long URL
    def long_url(self):
        if len(self.url) < 54:
            return 1
        if 54 <= len(self.url) <= 75:
            return 0
        return -1

    # 3. URL Shortener
    def short_url(self):
        match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs', self.url)
        return -1 if match else 1

    # 4. @ Symbol
    def has_at_symbol(self):
        return -1 if "@" in self.url else 1

    # 5. Redirect //
    def has_redirect(self):
        return -1 if self.url.rfind('//') > 6 else 1

    # 6. Prefix/Suffix -
    def has_prefix_suffix(self):
        return -1 if "-" in self.domain else 1

    # 7. Subdomains
    def count_subdomains(self):
        dot_count = self.domain.count('.')
        if dot_count == 1:
            return 1  # e.g., example.com
        if dot_count == 2:
            return 0  # e.g., www.example.com
        return -1

    # 8. HTTPS
    def is_https(self):
        return 1 if self.urlparse.scheme == 'https' else -1

    # 9. Domain Registration Length
    def domain_reg_len(self):
        if not self.whois_response:
            return -1
        try:
            exp_date = self.whois_response.expiration_date
            cre_date = self.whois_response.creation_date
            exp_date = exp_date[0] if isinstance(exp_date, list) else exp_date
            cre_date = cre_date[0] if isinstance(cre_date, list) else cre_date
            
            if not all([exp_date, cre_date]): return -1

            age = (exp_date.year - cre_date.year) * 12 + (exp_date.month - cre_date.month)
            return 1 if age >= 12 else -1
        except Exception:
            return -1

    # 10. Favicon
    def favicon(self):
        if not self.soup or not self.soup.head:
            return -1
        try:
            for link in self.soup.head.find_all('link', rel=re.compile(r'icon', re.I)):
                href = link.get('href')
                if not href: continue
                
                parsed_href = urlparse(href)
                if not parsed_href.netloc or self.domain in parsed_href.netloc:
                    return 1  # Safe if relative or from same domain
            return -1
        except Exception:
            return -1

    # 11. Non-Standard Port
    def non_std_port(self):
        try:
            return -1 if self.urlparse.port and self.urlparse.port not in [80, 443] else 1
        except Exception:
            return -1

    # 12. HTTPS in Domain
    def https_in_domain(self):
        return -1 if 'https' in self.domain else 1

    # 13. Request URL (External Objects)
    def request_url(self):
        if not self.soup: return -1
        try:
            i, success = 0, 0
            for tag in self.soup.find_all(['img', 'audio', 'embed', 'iframe'], src=True):
                src_domain = urlparse(tag['src']).netloc
                if src_domain and self.domain not in src_domain:
                    success += 1
                i += 1
            if i == 0: return 1
            percentage = (success / float(i)) * 100
            if percentage < 22.0: return 1
            if 22.0 <= percentage < 61.0: return 0
            return -1
        except Exception:
            return -1

    # 14. Anchor URL
    def anchor_url(self):
        if not self.soup: return -1
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('#') or 'javascript:void(0)' in href.lower():
                    unsafe += 1
                elif self.domain not in urlparse(href).netloc and urlparse(href).netloc != '':
                    unsafe += 1
                i += 1
            if i == 0: return 1
            percentage = (unsafe / float(i)) * 100
            if percentage < 31.0: return 1
            if 31.0 <= percentage < 67.0: return 0
            return -1
        except Exception:
            return -1

    # 15. Links in <script>, <link>
    def links_in_tags(self):
        if not self.soup: return -1
        try:
            i, success = 0, 0
            tags = self.soup.find_all('link', href=True) + self.soup.find_all('script', src=True)
            for tag in tags:
                source = tag.get('href') or tag.get('src')
                src_domain = urlparse(source).netloc
                if src_domain and self.domain in src_domain:
                    success += 1
                i += 1
            if i == 0: return 1
            percentage = (success / float(i)) * 100
            if percentage < 17.0: return -1
            if 17.0 <= percentage < 81.0: return 0
            return 1
        except Exception:
            return -1

    # 16. Server Form Handler (SFH)
    def sfh(self):
        if not self.soup: return 1
        try:
            forms = self.soup.find_all('form', action=True)
            if not forms: return 1
            for form in forms:
                action = form['action']
                if action == "" or action == "about:blank": return -1
                action_domain = urlparse(action).netloc
                if action_domain and self.domain not in action_domain: return 0
            return 1
        except Exception:
            return -1

    # 17. Submitting to Email
    def submit_to_email(self):
        return -1 if self.response and re.findall(r"mailto:", self.response.text) else 1

    # 18. Abnormal URL
    def abnormal_url(self):
        return 1 if self.whois_response and self.domain in str(self.whois_response) else -1

    # 19. Website Forwarding
    def website_forwarding(self):
        if not self.response: return -1
        history_len = len(self.response.history)
        if history_len <= 1: return 1
        if 2 <= history_len <= 4: return 0
        return -1

    # 20. Status Bar Customization
    def statusbar_cust(self):
        return -1 if self.response and re.findall(r"onmouseover", self.response.text, re.I) else 1

    # 21. Disabling Right Click
    def disable_right_click(self):
        return -1 if self.response and re.findall(r"event.button ?== ?2", self.response.text) else 1

    # 22. Popup Window
    def popup_window(self):
        return -1 if self.response and re.findall(r"alert\(", self.response.text) else 1

    # 23. IFrame
    def iframe(self):
        return -1 if self.soup and self.soup.find_all(['iframe', 'frame']) else 1

    # 24. Age of Domain
    def age_of_domain(self):
        if not self.whois_response: return -1
        try:
            cre_date = self.whois_response.creation_date
            cre_date = cre_date[0] if isinstance(cre_date, list) else cre_date
            if not cre_date: return -1
            age = (datetime.now().year - cre_date.year) * 12 + (datetime.now().month - cre_date.month)
            return 1 if age >= 6 else -1
        except Exception:
            return -1

    # 25. DNS Record
    def dns_record(self):
        return 1 if self.whois_response else -1

    # 26. Website Traffic (Alexa Rank is DEPRECATED)
    def website_traffic(self):
        # The Alexa API was retired. This feature is no longer reliable.
        # Returning 0 as a neutral value to maintain the feature count.
        return 0

    # 27. Page Rank (This is DEPRECATED)
    def page_rank(self):
        # Google PageRank is no longer a public metric.
        # Returning -1 as it's not possible to verify.
        return -1

    # 28. Google Index
    def google_index(self):
        try:
            # We just need to know if any result exists.
            results = list(search(self.url, stop=1))
            return 1 if results else -1
        except Exception:
            return -1

    # 29. Links Pointing to Page
    def links_pointing_to_page(self):
        if not self.soup: return -1
        number_of_links = len(self.soup.find_all('a'))
        if number_of_links == 0: return 1
        if 1 <= number_of_links <= 2: return 0
        return -1

    # 30. Stats Report
    def stats_report(self):
        try:
            ip_address = socket.gethostbyname(self.domain)
            url_match = re.search(r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es', self.url)
            ip_match = re.search(r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88', ip_address)
            if url_match or ip_match:
                return -1
            return 1
        except Exception:
            return 1 # If lookup fails, assume it's safe for this check
