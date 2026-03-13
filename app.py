from flask import Flask, render_template, request, jsonify
import re
import socket
import math

app = Flask(__name__)

COMMON_PASSWORDS = [
    "password", "123456", "password1", "qwerty", "abc123",
    "letmein", "monkey", "dragon", "master", "hello",
    "sunshine", "princess", "welcome", "shadow", "football",
    "iloveyou", "admin", "login", "pass", "test", "root"
]

SUSPICIOUS_PATTERNS = [
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'IP address used instead of domain'),
    (r'(login|verify|update|secure|account|banking|paypal|ebay|amazon|netflix).*\.', 'Suspicious keyword in URL'),
    (r'\.(tk|ml|ga|cf|gq)$', 'Suspicious free domain extension'),
    (r'(bit\.ly|tinyurl|goo\.gl|t\.co)', 'URL shortener detected'),
    (r'@', '@ symbol in URL'),
    (r'https?://[^/]*-[^/]*-[^/]*\.', 'Multiple hyphens in domain'),
]

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
    5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt', 27017: 'MongoDB'
}

SQL_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users;--",
    "' UNION SELECT * FROM users--", "admin'--", "1' AND '1'='1"
]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check-password', methods=['POST'])
def check_password():
    data = request.get_json()
    password = data.get('password', '')
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    long_enough = len(password) >= 8
    not_common = password.lower() not in COMMON_PASSWORDS
    no_repeat = not bool(re.search(r'(.)\1{2,}', password))
    checks = {
        'length': long_enough, 'uppercase': has_upper,
        'lowercase': has_lower, 'numbers': has_digit,
        'special': has_special, 'not_common': not_common, 'no_repeat': no_repeat
    }
    pool = 0
    if has_lower: pool += 26
    if has_upper: pool += 26
    if has_digit: pool += 10
    if has_special: pool += 32
    entropy = round(len(password) * math.log2(pool)) if pool and password else 0
    score = sum(checks.values())
    if score <= 2: strength = "Very Weak"
    elif score <= 3: strength = "Weak"
    elif score <= 4: strength = "Fair"
    elif score <= 5: strength = "Good"
    elif score <= 6: strength = "Strong"
    else: strength = "Very Strong"
    crack_secs = (2 ** entropy) / 1e10 if entropy else 0
    if crack_secs < 1: crack_time = "Instant"
    elif crack_secs < 60: crack_time = f"{int(crack_secs)} seconds"
    elif crack_secs < 3600: crack_time = f"{int(crack_secs/60)} minutes"
    elif crack_secs < 86400: crack_time = f"{int(crack_secs/3600)} hours"
    elif crack_secs < 31536000: crack_time = f"{int(crack_secs/86400)} days"
    elif crack_secs < 3153600000: crack_time = f"{int(crack_secs/31536000)} years"
    else: crack_time = "Centuries"
    return jsonify({'checks': checks, 'strength': strength, 'score': score, 'entropy': entropy, 'crack_time': crack_time})

@app.route('/scan-ports', methods=['POST'])
def scan_ports():
    data = request.get_json()
    host = data.get('host', '').strip()
    results = []
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return jsonify({'error': 'Invalid host or domain'}), 400
    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            status = 'Open' if result == 0 else 'Closed'
            sock.close()
        except:
            status = 'Error'
        results.append({'port': port, 'service': service, 'status': status})
    open_count = sum(1 for r in results if r['status'] == 'Open')
    return jsonify({'host': host, 'ip': ip, 'results': results, 'open_count': open_count})

@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url', '').strip()
    flags = []
    for pattern, description in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            flags.append(description)
    score = len(flags)
    if score == 0: risk = 'Safe'
    elif score == 1: risk = 'Suspicious'
    else: risk = 'High Risk'
    return jsonify({'url': url, 'risk': risk, 'flags': flags, 'score': score})

@app.route('/sqli-payloads', methods=['GET'])
def sqli_payloads():
    return jsonify({'payloads': SQL_PAYLOADS, 'count': len(SQL_PAYLOADS)})

@app.route('/test-sqli', methods=['POST'])
def test_sqli():
    data = request.get_json()
    input_val = data.get('input', '')
    detected = []
    sqli_patterns = [
        r"('|\")\s*(OR|AND)\s*('|\")?\d*('|\")?\s*=\s*('|\")?\d*",
        r"(--|#|/\*)",
        r"(DROP|DELETE|INSERT|UPDATE|SELECT|UNION)\s+",
        r"(exec|execute|xp_|sp_)\w+",
        r"0x[0-9a-fA-F]+"
    ]
    for pattern in sqli_patterns:
        if re.search(pattern, input_val, re.IGNORECASE):
            detected.append(pattern)
    vulnerable = len(detected) > 0
    return jsonify({
        'input': input_val, 'vulnerable': vulnerable,
        'patterns_detected': len(detected),
        'verdict': 'SQL Injection Detected!' if vulnerable else 'Input looks clean'
    })

if __name__ == '__main__':
    app.run(debug=True)