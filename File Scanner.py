"""
Suspicious File Scanner Module
Analyzes files for potential security threats
"""

import os
from typing import Dict, List

# ==================== DANGEROUS FILE EXTENSIONS ====================

DANGEROUS_EXTENSIONS = {
    # Executable files
    '.exe': 'Windows executable',
    '.bat': 'Batch script',
    '.cmd': 'Command file',
    '.com': 'MS-DOS executable',
    '.pif': 'Program information file',
    '.scr': 'Screen saver',
    
    # Script files
    '.vbs': 'Visual Basic script',
    '.vbe': 'Encoded VB script',
    '.js': 'JavaScript file',
    '.jse': 'Encoded JavaScript',
    '.ws': 'Windows Script',
    '.wsh': 'Windows Script Host',
    '.psw': 'PowerShell script',
    '.ps1': 'PowerShell script',
    '.ps2': 'PowerShell script',
    '.psc1': 'PowerShell script',
    '.psc2': 'PowerShell script',
    
    # Archive files (potentially dangerous)
    '.zip': 'Compressed archive',
    '.rar': 'Compressed archive',
    '.7z': 'Compressed archive',
    '.ace': 'Compressed archive',
    '.cab': 'Cabinet archive',
    
    # Java
    '.jar': 'Java archive',
    '.class': 'Java class file',
    '.jnlp': 'Java Web Start',
    
    # Other executable-like
    '.msi': 'Windows installer',
    '.app': 'Application bundle',
    '.dmg': 'Disk image',
    '.iso': 'ISO image',
    '.img': 'Disk image',
    '.run': 'Unix executable',
    '.bin': 'Binary executable',
    '.sh': 'Shell script',
    '.bash': 'Bash script',
    
    # Documents with macros
    '.docm': 'Word macro-enabled',
    '.xlsm': 'Excel macro-enabled',
    '.pptm': 'PowerPoint macro-enabled',
}

# ==================== SUSPICIOUS EXTENSIONS ====================

SUSPICIOUS_EXTENSIONS = {
    '.pdf': 'PDF (can contain malicious code)',
    '.doc': 'Word document (outdated, potential risks)',
    '.xls': 'Excel spreadsheet (outdated, potential risks)',
    '.ppt': 'PowerPoint (outdated, potential risks)',
}

def scan_file(filename: str) -> Dict:
    """
    Scan a file for potential security threats
    
    Args:
        filename (str): The filename to analyze
        
    Returns:
        Dict: Dictionary containing:
            - filename (str): The analyzed filename
            - extension (str): File extension
            - threat_level (str): Threat level with emoji
            - risk_score (int): Numerical score
            - indicators (list): List of detected threats
            - recommendation (str): What to do with file
            
    Example:
        >>> result = scan_file("document.exe")
        >>> result['threat_level']
        'Dangerous 🔴'
    """
    
    # Initialize variables
    risk_indicators = []
    risk_score = 0
    
    # ==================== CHECK 1: Get File Extension ====================
    
    _, file_extension = os.path.splitext(filename)
    file_extension = file_extension.lower()
    
    # ==================== CHECK 2: Check for Dangerous Extensions ====================
    
    if file_extension in DANGEROUS_EXTENSIONS:
        danger_desc = DANGEROUS_EXTENSIONS[file_extension]
        risk_indicators.append(f"🔴 Dangerous file type: {file_extension} ({danger_desc})")
        risk_score += 3
    
    # ==================== CHECK 3: Check for Suspicious Extensions ====================
    
    elif file_extension in SUSPICIOUS_EXTENSIONS:
        suspicious_desc = SUSPICIOUS_EXTENSIONS[file_extension]
        risk_indicators.append(f"🟠 Potentially suspicious file type: {file_extension} ({suspicious_desc})")
        risk_score += 1
    
    # ==================== CHECK 4: Double Extension Detection ====================
    
    if filename.count('.') > 1:
        # Get all extensions
        parts = filename.split('.')
        if len(parts) > 2:
            first_extension = '.' + parts[-2]
            second_extension = '.' + parts[-1]
            
            risk_indicators.append(f"⚠️ File has multiple extensions ({first_extension} + {second_extension})")
            risk_indicators.append("   Attackers often use this to hide dangerous file types")
            risk_score += 2
    
    # ==================== CHECK 5: Check for Double Extension Tricks ====================
    
    dangerous_double_extensions = [
        '.exe.txt', '.exe.doc', '.exe.pdf',
        '.zip.txt', '.zip.doc',
        '.bat.txt', '.bat.doc',
        '.cmd.txt', '.cmd.doc',
        '.jar.pdf',
        '.scr.txt',
    ]
    
    filename_lower = filename.lower()
    for double_ext in dangerous_double_extensions:
        if filename_lower.endswith(double_ext):
            risk_indicators.append(f"🔴 Suspicious double extension detected: {double_ext}")
            risk_indicators.append("   File claims to be one type but is actually another")
            risk_score += 2
            break
    
    # ==================== CHECK 6: Space in Extension Trick ====================
    
    if ' .' in filename:
        risk_indicators.append("⚠️ Filename contains space before extension")
        risk_indicators.append("   Potential technique to hide dangerous file type")
        risk_score += 1
    
    # ==================== CHECK 7: Suspicious Filename Patterns ====================
    
    suspicious_patterns = {
        r'invoice.*\.exe': 'Looks like invoice but is executable',
        r'document.*\.exe': 'Looks like document but is executable',
        r'image.*\.exe': 'Looks like image but is executable',
        r'video.*\.exe': 'Looks like video but is executable',
        r'pdf.*\.exe': 'Looks like PDF but is executable',
        r'resume.*\.exe': 'Looks like resume but is executable',
    }
    
    import re
    for pattern, description in suspicious_patterns.items():
        if re.search(pattern, filename_lower):
            risk_indicators.append(f"⚠️ Suspicious filename pattern: {description}")
            risk_score += 1
            break
    
    # ==================== CHECK 8: Very Long Filename ====================
    
    if len(filename) > 255:
        risk_indicators.append("⚠️ Filename is unusually long (potential obfuscation)")
        risk_score += 1
    elif len(filename) > 100:
        risk_indicators.append("⚠️ Filename is quite long (could hide malicious intent)")
        risk_score += 1
    
    # ==================== CHECK 9: All Special Characters ====================
    
    special_char_count = sum(1 for c in filename if not c.isalnum() and c not in '.-_ ')
    if special_char_count > 5:
        risk_indicators.append("⚠️ Filename contains many special characters")
        risk_score += 1
    
    # ==================== CHECK 10: No Visible Extension ====================
    
    if not file_extension or file_extension == '':
        risk_indicators.append("⚠️ File has no extension or hidden extension")
        risk_indicators.append("   Files without extensions can execute without user knowledge")
        risk_score += 1
    
    # ==================== THREAT LEVEL DETERMINATION ====================
    
    if risk_score == 0:
        threat_level = "Safe ✅"
        recommendation = "This file appears to be safe to open"
    elif risk_score <= 1:
        threat_level = "Low Risk ✅"
        recommendation = "This file appears generally safe, but always be cautious"
    elif risk_score <= 2:
        threat_level = "Medium Risk ⚠️"
        recommendation = "Exercise caution with this file. Scan with antivirus before opening"
    elif risk_score <= 4:
        threat_level = "High Risk 🔴"
        recommendation = "This file shows concerning characteristics. Do NOT open unless absolutely sure"
    else:
        threat_level = "Very Dangerous 🛑"
        recommendation = "DO NOT open this file! It appears to be malicious. Delete it immediately"
    
    # ==================== RETURN RESULT ====================
    
    return {
        'filename': filename,
        'extension': file_extension if file_extension else 'No extension',
        'threat_level': threat_level,
        'risk_score': risk_score,
        'indicators': risk_indicators if risk_indicators else ['✅ File appears to be safe'],
        'recommendation': recommendation,
        'details': {
            'is_executable': file_extension in DANGEROUS_EXTENSIONS,
            'extension_type': DANGEROUS_EXTENSIONS.get(file_extension, 'Unknown'),
            'length': len(filename),
            'has_multiple_extensions': filename.count('.') > 1,
        }
    }


def get_file_security_tips() -> List[str]:
    """
    Return list of file security tips
    
    Returns:
        List[str]: Tips for file safety
    """
    
    return [
        "🔍 Always check file extensions and enable viewing hidden extensions",
        "🔐 Be suspicious of unexpected file attachments",
        "🛡️ Use updated antivirus/anti-malware software",
        "⚠️ Be wary of executable files (.exe, .bat, .scr)",
        "📧 Don't open email attachments from unknown senders",
        "🔗 Download files only from trusted sources",
        "🗜️ Be careful with archive files (.zip, .rar) from unknown sources",
        "💾 Enable file extension viewing in your operating system",
        "🔄 Keep your operating system and software updated",
        "🧠 When in doubt, scan the file with antivirus software first",
        "🚫 Disable macros in Microsoft Office documents",
        "📱 Don't open files from untrusted USB drives or storage devices",
    ]


def categorize_file(filename: str) -> Dict:
    """
    Categorize a file by type
    
    Args:
        filename (str): The filename to categorize
        
    Returns:
        Dict: File category information
    """
    
    _, extension = os.path.splitext(filename)
    extension = extension.lower()
    
    categories = {
        'executable': ['.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.msi', '.app', '.jar'],
        'script': ['.vbs', '.js', '.ps1', '.sh', '.bash'],
        'document': ['.doc', '.docx', '.docm', '.pdf', '.txt', '.rtf'],
        'spreadsheet': ['.xls', '.xlsx', '.xlsm', '.csv'],
        'presentation': ['.ppt', '.pptx', '.pptm'],
        'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'],
        'video': ['.mp4', '.avi', '.mov', '.mkv', '.flv', '.wmv'],
        'audio': ['.mp3', '.wav', '.flac', '.aac', '.m4a'],
        'archive': ['.zip', '.rar', '.7z', '.tar', '.gz', '.ace', '.cab'],
        'other': []
    }
    
    for category, extensions in categories.items():
        if extension in extensions:
            return {
                'filename': filename,
                'extension': extension,
                'category': category,
                'description': f'{category.capitalize()} file'
            }
    
    return {
        'filename': filename,
        'extension': extension,
        'category': 'other',
        'description': 'Unknown file type'
}
  
