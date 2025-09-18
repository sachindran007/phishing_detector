from flask import Flask, request, jsonify
from flask_cors import CORS
import re
from urllib.parse import urlparse
from datetime import datetime
import os
import json
from dotenv import load_dotenv
import google.generativeai as genai
import whois
import requests 

# --- Load Environment Variables and Configure Services ---
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
UPTIMEROBOT_API_KEY = os.getenv("UPTIMEROBOT_API_KEY")

USE_GEMINI = bool(GEMINI_API_KEY)
if USE_GEMINI:
    print("Gemini API key found. AI analysis is ENABLED.")
    genai.configure(api_key=GEMINI_API_KEY)
else:
    print("CRITICAL: Gemini API key not found. AI analysis is DISABLED.")

if UPTIMEROBOT_API_KEY:
    print("UptimeRobot API key found. Reputation check is ENABLED.")
else:
    print("WARNING: UptimeRobot API key not found. Reputation check is DISABLED.")


# --- TOOL 1: Real-Time Website Status Checker ---
def check_website_status(url):
    """Performs an instant check to see if a website is online."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        return f"Online (Status: {response.status_code})" if 200 <= response.status_code < 300 else f"Responded with Error (Status: {response.status_code})"
    except requests.exceptions.SSLError: return "SSL Certificate Error"
    except requests.exceptions.Timeout: return "Offline (Request Timed Out)"
    except requests.exceptions.ConnectionError: return "Offline (Connection Failed)"
    except requests.exceptions.RequestException: return "Could not be determined"


# --- TOOL 2: UptimeRobot Reputation Check ---
def get_uptimerobot_reputation(domain):
    """Checks if a domain is monitored by UptimeRobot and gets its reputation."""
    if not UPTIMEROBOT_API_KEY:
        return "Not configured"
    
    api_url = "https://api.uptimerobot.com/v2/getMonitors"
    payload = {
        "api_key": UPTIMEROBOT_API_KEY,
        "format": "json",
        "search": domain
    }
    try:
        response = requests.post(api_url, data=payload, timeout=5)
        response.raise_for_status()
        data = response.json()

        if data.get("stat") == "ok" and data.get("monitors"):
            monitor = data["monitors"][0]
            status_map = {0: "Paused", 1: "Not Checked Yet", 2: "Up", 8: "Seems Down", 9: "Down"}
            status_text = status_map.get(monitor.get("status"), "Unknown")
            uptime_ratio = monitor.get("custom_uptime_ratio", "N/A")
            return f"Monitored - Status: {status_text} (Uptime: {uptime_ratio}%)"
        else:
            return "Not found in monitoring service"
    except requests.exceptions.RequestException as e:
        print(f"UptimeRobot API error: {e}")
        return "Could not be determined"


# --- TOOL 3 & OTHERS: Feature Extraction Function ---
def extract_url_features(url):
    """Calculates all features to provide as evidence to the AI."""
    features = {}
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        features["Real-Time Status"] = check_website_status(url)
        features["Monitoring Reputation"] = get_uptimerobot_reputation(domain)
        features["URL Length"] = len(url)
        features["Uses HTTPS"] = "Yes" if parsed_url.scheme == 'https' else "No"
        
        keywords = ["login", "verify", "bank", "account", "secure", "update", "signin"]
        features["Number of Suspicious Keywords"] = sum(1 for keyword in keywords if keyword in url.lower())

        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list): creation_date = creation_date[0]
            features["Domain Age"] = f"{(datetime.now() - creation_date).days} days" if creation_date else "Could not be determined"
        except Exception:
            features["Domain Age"] = "Could not be determined"
            
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

# --- AI Analysis Function ---
def analyze_with_gemini(url, features):
    if not USE_GEMINI: 
        return {"verdict": "Error", "reason": "AI is not configured."}
    
    try:
        model = genai.GenerativeModel('gemini-pro')
        feature_string = "\n".join([f"- {key}: {value}" for key, value in features.items()])
        prompt = f'''
        As a cybersecurity expert, analyze the following URL based on the evidence. Classify it as "Phishing Detected", "High Risk", "Suspicious", or "Looks Safe".
        URL: "{url}"
        Evidence:
        {feature_string}
        A site with a positive "Monitoring Reputation" is a strong sign of legitimacy.
        If the 'Real-Time Status' starts with 'Online', mention in your 'reason' that the website is confirmed to be live.
        Respond ONLY with a valid JSON object with two keys: "verdict" and "reason".
        '''
        response = model.generate_content(prompt)
        cleaned_text = response.text.strip().replace("```json", "").replace("```", "")
        return json.loads(cleaned_text)
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return {"verdict": "Suspicious", "reason": "AI analysis failed."}

# --- Flask App Setup & Endpoint (This is the critical part) ---
app = Flask(__name__)
allowed_origins = ["https://localhost:3000", "https://phishing-detector-api-d3mu.onrender.com"]
CORS(app, resources={r"/analyze": {"origins": allowed_origins}})

@app.route('/analyze', methods=['POST'])
def analyze():
    raw_url = request.get_json().get('url', '').strip()
    if not raw_url:
        return jsonify({"error": "URL is required"}), 400
    full_url_for_analysis = raw_url if re.match(r'^(https?://)', raw_url) else 'https://' + raw_url
    
    features = extract_url_features(full_url_for_analysis)
    if not features:
        return jsonify({"error": "Could not process the URL"}), 500
        
    ai_result = analyze_with_gemini(full_url_for_analysis, features)
    
    # THIS IS THE LOGIC THAT MUST BE RUNNING ON YOUR SERVER
    findings = [{"description": f"AI Analysis: {ai_result['reason']}"}]
    for key, value in features.items():
        findings.append({"description": f"{key}: {value}"})
        
    return jsonify({
        "url": raw_url, 
        "verdict": ai_result['verdict'], 
        "findings": findings # Return the FULL list
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000, ssl_context='adhoc')