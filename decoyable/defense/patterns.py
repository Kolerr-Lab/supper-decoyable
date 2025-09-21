"""
decoyable/defense/patterns.py

Attack pattern definitions and constants for DECOYABLE defense system.
"""

# Attack classification patterns (improved specificity)
ATTACK_PATTERNS = {
    "sqli": [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION)\b.*\b(FROM|INTO|TABLE|WHERE|ALL)\b)",
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bOR\b.*['\"]\s*\d+\s*=\s*\d+\s*['\"])",
        r"(\bAND\b.*['\"]\s*\d+\s*=\s*\d+\s*['\"])",
        r"(\%27|\%22|%3B)",  # URL encoded quotes and semicolons
        r"(\blike\b.*\%.*\%|\blike\b.*\_.*\_)",  # LIKE with wildcards
        r"(1=1|1=0|\d+=\d+.*--|'\d+'\s*=\s*'\d+')",  # Common SQL injection payloads
        r"(\bor\b.*\d+\s*=\s*\d+)",  # OR 1=1 patterns
        r"OR.*=.*",  # Simple OR = pattern
    ],
    "xss": [
        r"(<script[^>]*>.*?</script>)",
        r"(<iframe[^>]*>.*?</iframe>)",
        r"(javascript:)",
        r"(vbscript:)",
        r"(on\w+\s*=.*[<>\"'])",
        r"(<img[^>]*onerror[^>]*=)",
        r"(<svg[^>]*onload[^>]*=)",
        r"(eval\(|document\.|window\.)",
    ],
    "command_injection": [
        r"(\|\s*\w+|\&\s*\w+|;\s*\w+)",  # Command chaining
        r"(\$\([^)]+\)|\`[^`]+\`)",  # Command substitution
        r"(\b(cat|ls|pwd|whoami|id|ps|netstat|wget|curl|nc|bash|sh|python|perl)\b.*\|)",
        r"(\b(rm|del|format|shutdown|reboot|halt)\b.*[;&|])",
        r"(\$\{[^}]+\})",  # Variable expansion
    ],
    "path_traversal": [
        r"(\.\./|\.\.\\){2,}",  # Multiple directory traversals
        r"(\.\./\.\./)",
        r"(%2e%2e%2f|%2e%2e%5c){2,}",  # URL encoded
        r"(etc/passwd|etc/shadow|boot.ini|web.config)",  # Common target files
        r"(\.\./.*\.\./.*\.\./)",  # Complex traversals
    ],
    "brute_force": [
        r"(\badmin\b.*\bpassword\b|\broot\b.*\bpassword\b)",  # Specific credential attempts
        r"(\blogin\b.*\bfailed\b|\bauth\b.*\bfailed\b)",  # Failed login patterns
        r"(\buser\b.*\bpass\b.*\battempt\b)",  # Brute force attempt patterns
    ],
    "reconnaissance": [
        r"(\b(nmap|nikto|dirbuster|sqlmap|metasploit|nessus|acunetix|burpsuite|owasp|qualys)\b)",
        r"(User-Agent:.*(scanner|bot|crawler|spider|dirbuster|gobuster|acunetix|qualys|nessus))",
        r"(\.php|\.asp|\.jsp|\.bak|\.old|\.txt|\.sql|\.env|\.git|\.svn|\.DS_Store|\.htaccess|\.htpasswd)",
        r"(\badminer\b|\bphpmyadmin\b|\bwebmin\b|\bcpanel\b|\bplesk\b|\bwhm\b)",
        r"(\?C=|\?N=|\?O=|\?S=|index\.php\?page=|script\.php\?id=)",  # Directory listing attempts
        r"(\b/etc/passwd\b|\b/etc/shadow\b|\b/proc/version\b|\b/proc/cpuinfo\b)",  # System file access
    ],
}