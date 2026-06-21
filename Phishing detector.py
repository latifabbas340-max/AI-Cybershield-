"""
Phishing URL Detector Module
Identifies suspicious links and potential phishing attempts
"""

import re
from typing import Dict, List
from urllib.parse import urlparse

def detect_phishing(url: str) -> Dict:
    """
    Detect potential phishing in a URL using multiple indicators
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        Dict: Dictionary containing:
            - url (str): The analyzed URL
            - risk_level (str): Risk level with emoji
            - risk_score (int): Numerical score
            - indicators (list): List of detected indicators
            - recommendation (str): Recommendation for user
            
    Example:
        >>> result = detect_phishing("https://secure-paypal.com/verify")
        >>> result['risk_level']
        'High Risk 🔴'
    """
    
    # Initialize variables
    suspicious_indicators = []
    risk_score = 0
    
    # ==================== CHECK 1: Suspicious Keywords ====================
    
    suspicious_keywords = [
        'verify', 'confirm', 'update', 'urgent', 'click', 'secure', 
        'account', 'suspended', 'locked', 'action_required', 'immediate',
        'unusual_activity', 'reactivate', 'validate', 'authenticate'
    ]
    
    url_lower = url.lower()
    for keyword in suspicious_keywords:
        if keyword in url_lower:
            suspicious_indicators.append(f"⚠️ Contains suspicious keyword: '{keyword}'")
            risk_score += 1
            break  # Only count once
    
    # ==================== CHECK 2: IP Address Instead of Domain ====================
    
    if re.match(r'http(s)?://\d+\.\d+\.\d+\.\d+', url):
        suspicious_indicators.append("🔴 Uses IP address instead of domain name")
        risk_score += 2
    
    # ==================== CHECK 3: Protocol Validation ====================
    
    if url.startswith('http://'):
        suspicious_indicators.append("🟠 Uses HTTP instead of secure HTTPS")
        risk_score += 1
    
    # ==================== CHECK 4: Unusual Characters ====================
    
    # Check for suspicious characters that might indicate obfuscation
    if re.search(r'[^a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]', url):
        suspicious_indicators.append("⚠️ Contains unusual or suspicious characters")
        risk_score += 1
    
    # ==================== CHECK 5: URL Length ====================
    
    if len(url) > 75:
        suspicious_indicators.append("⚠️ URL is unusually long (often used to hide malicious content)")
        risk_score += 1
    
    # ==================== CHECK 6: Multiple Subdomains ====================
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        subdomain_count = domain.count('.')
        
        if subdomain_count > 2:
            suspicious_indicators.append("⚠️ URL has multiple subdomains (potential subdomain spoofing)")
            risk_score += 1
    except:
        pass
    
    # ==================== CHECK 7: Punycode/IDN Spoofing ====================
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if 'xn--' in domain:
            suspicious_indicators.append("⚠️ Possible internationalized domain spoofing (IDN attack)")
            risk_score += 2
    except:
        pass
    
    # ==================== CHECK 8: Port Number Anomaly ====================
    
    if re.search(r':\d+(?:/|$)', url):
        port_match = re.search(r':(\d+)', url)
        if port_match:
            port = int(port_match.group(1))
            if port not in [80, 443, 8080, 8443]:
                suspicious_indicators.append(f"⚠️ Non-standard port number ({port}) detected")
                risk_score += 1
    
    # ==================== CHECK 9: Domain Name Similarity ====================
    
    # Common brands to check against
    common_brands = {
        'paypal': ['paypa1', 'paypai', 'paypa', 'pay-pal'],
        'amazon': ['amazo', 'amazon-secure', 'amazon-verify'],
        'apple': ['apple-id', 'apple-secure', 'apples'],
        'google': ['goole', 'googl', 'google-secure', 'accounts-google'],
        'microsoft': ['microso', 'micro-soft'],
    }
    
    for brand, typos in common_brands.items():
        for typo in typos:
            if typo in url_lower:
                suspicious_indicators.append(f"⚠️ Domain appears to mimic '{brand}' (typosquatting)")
                risk_score += 2
                break
    
    # ==================== CHECK 10: Query Parameter Overload ====================
    
    try:
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parsed_url.query.split('&')
            if len(params) > 5:
                suspicious_indicators.append("⚠️ URL has excessive parameters (suspicious)")
                risk_score += 1
    except:
        pass
    
    # ==================== RISK LEVEL DETERMINATION ====================
    
    if risk_score == 0:
        risk_level = "Low Risk ✅"
    elif risk_score <= 2:
        risk_level = "Medium Risk ⚠️"
    elif risk_score <= 4:
        risk_level = "High Risk 🔴"
    else:
        risk_level = "Very High Risk 🛑"
    
    # ==================== RECOMMENDATION ====================
    
    if risk_score == 0:
        recommendation = "✅ This link appears to be safe. However, always verify sender information."
    elif risk_score <= 2:
        recommendation = "⚠️ Be cautious with this link. Verify the source before clicking."
    elif risk_score <= 4:
        recommendation = "🔴 This link appears suspicious. Do not click unless you're certain of its legitimacy."
    else:
        recommendation = "🛑 This link shows high phishing characteristics. DO NOT click this link!"
    
    # ==================== RETURN RESULT ====================
    
    return {
        'url': url,
        'risk_level': risk_level,
        'risk_score': risk_score,
        'indicators': suspicious_indicators if suspicious_indicators else ['✅ No obvious phishing indicators detected'],
        'recommendation': recommendation,
        'details': {
            'has_suspicious_keywords': any('keyword' in ind for ind in suspicious_indicators),
            'uses_ip_address': any('IP address' in ind for ind in suspicious_indicators),
            'uses_http': url.startswith('http://'),
            'has_unusual_chars': any('unusual' in ind.lower() for ind in suspicious_indicators),
            'url_length': len(url),
        }
    }


def check_domain_reputation(domain: str) -> Dict:
    """
    Check domain reputation (basic implementation)
    
    Args:
        domain (str): The domain to check
        
    Returns:
        Dict: Domain reputation information
    """
    
    # List of known malicious patterns
    malicious_patterns = [
        r'bit\.ly',
        r'tinyurl',
        r'url\.shortener',
    ]
    
    reputation_score = 100  # Start with 100 (safe)
    warnings = []
    
    # Check for known malicious patterns
    for pattern in malicious_patterns:
        if re.search(pattern, domain, re.IGNORECASE):
            reputation_score -= 25
            warnings.append(f"⚠️ Domain matches known malicious pattern: {pattern}")
    
    # Check if domain is too new (would need actual WHOIS data)
    # This is a placeholder for demonstration
    
    return {
        'domain': domain,
        'reputation_score': reputation_score,
        'is_safe': reputation_score > 50,
        'warnings': warnings
    }


def get_phishing_prevention_tips() -> List[str]:
    """
    Return list of phishing prevention tips
    
    Returns:
        List[str]: Tips for avoiding phishing
    """
    
    return [
        "🔍 Hover over links to see the actual URL before clicking",
        "🔐 Look for HTTPS and a padlock icon in the browser",
        "📧 Verify sender email address carefully (not just display name)",
        "⚠️ Be suspicious of urgent requests for personal information",
        "🚫 Never click links in unexpected emails",
        "🔗 Type URLs directly in browser instead of clicking links",
        "🔄 Check spelling of domain names carefully",
        "📱 Verify requests through official contact method",
        "🆔 Use two-factor authentication for important accounts",
        "🧠 When in doubt, contact the organization directly",
      ]
      
