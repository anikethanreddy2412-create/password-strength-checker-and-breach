import os
import hashlib
import sqlite3
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
DB_FILE = "test_history.db"

# Initialize SQLite database to store test history
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                length INTEGER,
                strength_rating TEXT,
                breach_count INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

init_db()

def check_hibp_api(password):
    """Checks the HIBP API using k-anonymity securely."""
    # Step 1: Hash the password using SHA-1
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    
    # Step 2: Query HIBP with only the first 5 characters
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return 0
    except requests.RequestException:
        return 0 # Fallback if API is down

    # Step 3: Parse results to find our suffix
    hashes = (line.split(':') for line in response.text.splitlines())
    for target_suffix, count in hashes:
        if target_suffix == suffix:
            return int(count)
    
    return 0

def evaluate_strength(password):
    """Calculates password score, rating, and explicit reasoning."""
    score = 0
    reasons = []
    
    if len(password) >= 8: score += 1
    else: reasons.append("Password is too short (less than 8 characters).")
    
    if any(c.isupper() for c in password): score += 1
    else: reasons.append("Missing at least one uppercase letter.")
        
    if any(c.islower() for c in password): score += 1
    
    if any(c.isdigit() for c in password): score += 1
    else: reasons.append("Missing at least one number.")
        
    if any(c in '!@#$%^&*(),.?":{}|<>+=-_' for c in password): score += 1
    else: reasons.append("Missing at least one special character.")

    # Contextual adjustments for length bonus
    if len(password) >= 14: score += 1 

    # Determine Rating
    if score <= 2:
        rating = "Weak"
    elif score <= 4:
        rating = "Moderate"
    else:
        rating = "Strong"
        
    if not reasons:
        reasons.append("Great job! Your password meets all basic structural safety criteria.")
        
    return score, rating, reasons

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json or {}
    password = data.get('password', '')
    
    if not password:
        return jsonify({"error": "Empty password"}), 400
    
    # Run tests
    score, rating, reasons = evaluate_strength(password)
    breach_count = check_hibp_api(password)
    
    # Log metadata to SQLite database (excluding the actual password for security!)
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO tests (length, strength_rating, breach_count) VALUES (?, ?, ?)",
            (len(password), rating, breach_count)
        )
        conn.commit()
        
    return jsonify({
        "score": score, # Scale 0 to 6
        "rating": rating,
        "reasons": reasons,
        "breach_count": breach_count
    })

if __name__ == '__main__':
    app.run(debug=True)