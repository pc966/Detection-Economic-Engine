import re

def validate_username(username):
    """Validate username format"""
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, ""

def validate_password(password):
    """Validate password strength"""
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters"
    return True, ""

def validate_email(email):
    """Validate email format"""
    if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return False, "Invalid email format"
    return True, ""

def validate_score_fields(accuracy, fp_rate):
    """Validate score fields"""
    try:
        acc = float(accuracy)
        fp = float(fp_rate)
        if acc < 0 or acc > 100:
            return False, "Accuracy must be between 0 and 100"
        if fp < 0 or fp > 100:
            return False, "False positive rate must be between 0 and 100"
        return True, ""
    except ValueError:
        return False, "Invalid number format"