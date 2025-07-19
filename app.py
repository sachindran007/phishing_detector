# phishing_detector/app.py

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

# --- Load Environment Variables and Configure Gemini ---
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
USE_GEMINI = bool(GEMINI_API_KEY)

if USE_GEMINI:
    print("Gemini API key found. AI analysis is ENABLED.")
    genai.configure(api_key=GEMINI_API_KEY)
else:
    print("CRITICAL: Gemini API key not found in .env file. AI analysis is DISABLED.")

# --- Feature Extraction Function ---
def extract_url_features(url):
    features = {}
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        features["URL Length"] = len(url)
        features["Uses HTTPS"] = "Yes" if parsed_url.scheme == 'https' else "No"
        keywords = ["login", "verify", "bank", "account", "secure", "update", "signin"]
        features["Number of Suspicious Keywords"] = sum(1 for keyword in keywords if keyword in url.lower())
        special_chars = ['@', '%', '=', '?', '-']
        features["Number of Special Characters"] = sum(url.count(char) for char in special_chars)
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list): creation_date = creation_date[0]
            if creation_date:
                features["Domain Age"] = f"{(datetime.now() - creation_date).days} days"
            else:
                features["Domain Age"] = "Could not be determined"
        except Exception:
            features["Domain Age"] = "Could not be determined"
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

# --- AI Analysis Function ---
def analyze_with_gemini(url, features):
    if not USE_GEMINI: 
        return {"verdict": "Error", "reason": "AI is not configured. Please check the server's .env file."}
    try:
        model = genai.GenerativeModel('gemini-pro')
        feature_string = "\n".join([f"- {key}: {value}" for key, value in features.items()])
        prompt = f'''
        As a cybersecurity expert, analyze the following URL and classify it into ONE of the four following categories: "Phishing Detected", "High Risk", "Suspicious", or "Looks Safe".
        URL: "{url}"
        Here is the evidence I have gathered about the URL:
        {feature_string}
        Based on this evidence, which of the four categories is the most appropriate expert judgment?
        Respond ONLY with a valid JSON object containing two keys:
        1. "verdict": A string containing your choice from the four categories.
        2. "reason": A string with a concise, one-sentence explanation for your verdict.
        '''
        response = model.generate_content(prompt)
        cleaned_text = response.text.strip().replace("```json", "").replace("```", "")
        return json.loads(cleaned_text)
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return {"verdict": "Suspicious", "reason": "The AI analysis could not be completed, so this link is flagged as suspicious by default."}

# --- Flask App Setup ---
app = Flask(__name__)
CORS(app)

@app.route('/analyze', methods=['POST'])
def analyze():
    raw_url = request.get_json().get('url', '').strip()
    if not raw_url:
        return jsonify({"error": "URL is required"}), 400
    full_url_for_analysis = 'https://' + raw_url if not re.match(r'^(https?://)', raw_url) else raw_url
    features = extract_url_features(full_url_for_analysis)
    if not features:
        return jsonify({"error": "Could not process the URL"}), 500
    ai_result = analyze_with_gemini(full_url_for_analysis, features)
    return jsonify({
        "url": raw_url,
        "verdict": ai_result['verdict'],
        "findings": [{"description": f"AI Analysis: {ai_result['reason']}"}]
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000, ssl_context='adhoc')