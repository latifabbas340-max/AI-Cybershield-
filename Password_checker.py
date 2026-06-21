"""
Password Strength Checker Module
Analyzes passwords and provides recommendations for improvement
"""

import re
from typing import Dict, List

def check_password_strength(password: str) -> Dict:
    """
    Analyze password strength based on multiple criteria
    
    Args:
        password (str): The password to analyze
        
    Returns:
        Dict: Dictionary containing:
            - score (int): Score from 0-6
            - strength (str): Strength level with emoji
            - feedback (list): List of recommendations
            - percentage (float): Percentage strength
            
    Example:
        >>> result = check_password_strength("MyP@ssw0rd123!")
        >>> result['strength']
        'Very Strong 💪'
    """
    
    # Initialize score and feedback
    score = 0
    feedback = []
    
    # ==================== CRITERION 1: Length ====================
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password should be at least 8 characters long (ideally 12+)")
    
    if len(password) >= 12:
        score += 1
    
    # ==================== CRITERION 2: Lowercase Letters ====================
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("❌ Add lowercase letters (a-z) for better security")
    
    # ==================== CRITERION 3: Uppercase Letters ====================
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("❌ Add uppercase letters (A-Z) for better security")
    
    # ==================== CRITERION 4: Numbers ====================
    
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("❌ Add numbers (0-9) to increase security")
    
    # ==================== CRITERION 5: Special Characters ====================
    
    special_chars_pattern = r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]'
    if re.search(special_chars_pattern, password):
        score += 1
    else:
        feedback.append("❌ Add special characters (!@#$%^&*) for maximum security")
    
    # ==================== STRENGTH LEVELS ====================
    
    # Map scores to strength levels
    strength_levels = {
        0: "Very Weak 🔴",
        1: "Weak 🟠",
        2: "Fair 🟡",
        3: "Good 🟢",
        4: "Strong 💪",
        5: "Very Strong 🔐",
        6: "Excellent 🔐✅"
    }
    
    strength = strength_levels.get(score, 'Unknown')
    
    # ==================== PERCENTAGE CALCULATION ====================
    
    percentage = (score / 6) * 100
    
    # ==================== ADDITIONAL FEEDBACK ====================
    
    # If password is strong, add positive feedback
    if score >= 4:
        if not feedback:
            feedback.append("✅ Excellent password! Your password is strong and secure.")
        else:
            feedback.insert(0, "✅ Good foundation! Consider the suggestions below for even better security.")
    elif score >= 2:
        if not feedback:
            feedback.append("✅ Your password is acceptable, but could be improved.")
    
    # ==================== COMMON PATTERNS WARNING ====================
    
    common_patterns = {
        r'123456': "⚠️ Contains common number sequence",
        r'qwerty': "⚠️ Contains common keyboard pattern",
        r'password': "⚠️ Contains the word 'password'",
        r'admin': "⚠️ Contains the word 'admin'",
        r'letmein': "⚠️ Contains the word 'letmein'",
    }
    
    for pattern, warning in common_patterns.items():
        if re.search(pattern, password, re.IGNORECASE):
            if warning not in feedback:
                feedback.append(warning)
    
    # ==================== RETURN RESULT ====================
    
    return {
        'score': score,
        'strength': strength,
        'feedback': feedback if feedback else ['✅ Perfect password!'],
        'percentage': round(percentage, 1),
        'details': {
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_numbers': bool(re.search(r'[0-9]', password)),
            'has_special_chars': bool(re.search(special_chars_pattern, password)),
            'length': len(password),
            'length_sufficient': len(password) >= 8,
            'length_ideal': len(password) >= 12,
        }
    }


def estimate_crack_time(password: str) -> Dict:
    """
    Estimate how long it would take to crack the password
    Using simple brute force calculation
    
    Args:
        password (str): The password to analyze
        
    Returns:
        Dict: Estimated crack time and breakdown
    """
    
    # Define character set sizes
    lowercase_count = 26
    uppercase_count = 26
    digit_count = 10
    special_count = 32  # Common special characters
    
    # Calculate total possible characters
    possible_chars = 0
    if re.search(r'[a-z]', password):
        possible_chars += lowercase_count
    if re.search(r'[A-Z]', password):
        possible_chars += uppercase_count
    if re.search(r'[0-9]', password):
        possible_chars += digit_count
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        possible_chars += special_count
    
    if possible_chars == 0:
        possible_chars = lowercase_count
    
    # Calculate total combinations
    total_combinations = possible_chars ** len(password)
    
    # Assume average guess rate of 1 million passwords per second
    guesses_per_second = 1_000_000
    average_time_seconds = total_combinations / (2 * guesses_per_second)
    
    # Convert to human-readable format
    if average_time_seconds < 1:
        time_string = "Less than 1 second"
    elif average_time_seconds < 60:
        time_string = f"{int(average_time_seconds)} seconds"
    elif average_time_seconds < 3600:
        time_string = f"{int(average_time_seconds / 60)} minutes"
    elif average_time_seconds < 86400:
        time_string = f"{int(average_time_seconds / 3600)} hours"
    elif average_time_seconds < 31536000:
        time_string = f"{int(average_time_seconds / 86400)} days"
    elif average_time_seconds < 1000000000:
        time_string = f"{int(average_time_seconds / 31536000)} years"
    else:
        time_string = "Centuries or more"
    
    return {
        'estimated_time': time_string,
        'seconds': round(average_time_seconds, 2),
        'total_combinations': total_combinations,
        'character_set_size': possible_chars,
        'password_length': len(password)
    }


def generate_password_suggestions(password: str) -> List[str]:
    """
    Generate specific suggestions for improving the password
    
    Args:
        password (str): The current password
        
    Returns:
        List[str]: List of specific improvement suggestions
    """
    
    suggestions = []
    
    # Length suggestion
    if len(password) < 8:
        suggestions.append(f"Increase password length from {len(password)} to at least 8 characters")
    elif len(password) < 12:
        suggestions.append(f"Consider increasing to 12+ characters (currently {len(password)})")
    
    # Character variety suggestions
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add at least one uppercase letter (A-Z)")
    
    if not re.search(r'[a-z]', password):
        suggestions.append("Add at least one lowercase letter (a-z)")
    
    if not re.search(r'[0-9]', password):
        suggestions.append("Add at least one number (0-9)")
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        suggestions.append("Add at least one special character (!@#$%^&*)")
    
    # Pattern suggestions
    if re.search(r'(.)\1{2,}', password):
        suggestions.append("Avoid repeating characters (like 'aaa' or '111')")
    
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password):
        suggestions.append("Avoid sequential characters or numbers")
    
    return suggestions
  
