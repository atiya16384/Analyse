from tracemalloc import BaseFilter
from flask import Flask, request, jsonify, render_template
import re
from pdf2image import convert_from_path
from pytesseract import image_to_string
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import tokenizer_from_json
import json
from textblob import TextBlob
import nltk
from PIL import Image, ImageFilter, UnidentifiedImageError
import magic  # To detect file MIME type
import cv2
import numpy as np
from werkzeug.utils import secure_filename
import math 
# Initialize Flask app
app = Flask(__name__)

# Load your trained scam detection model
model = tf.keras.models.load_model("optimized_scam_detection_model.keras")

# Load the tokenizer
with open("tokenizer_config.json", "r") as file:
    tokenizer_json = file.read()
    tokenizer = tokenizer_from_json(json.loads(tokenizer_json))

# Define heuristics array with consolidated heuristics
heuristics = {
    "text_and_domain_analysis": {
        "function": "detect_text_and_domain_issues",  # Dynamic function
        "score": 40,  # Max score
        "weight": 0.6,  # Weighted contribution to overall heuristic score
        "description": "Analyzes general text and embedded domains/URLs for anomalies such as spelling errors, grammar issues, and suspicious patterns."
    },
    "attachment_patterns": {
        "regex": r"(\.exe|\.scr|\.zip|\.rar|\.js|\.bat)",
        "score": 15,
        "weight": 0.4,
        "description": "Detects potentially harmful file attachments."
    },
}

scam_keywords = {
    # High-impact keywords (15 points)
    "password": 15, "credit card": 15, "click here": 15, "claim reward": 15, "refund": 15,
    "bank account": 15, "verify": 15, "free money": 15, "bit.ly": 15, "tinyurl": 15, "update details": 15,
    "SSN": 15, "Social Security Number": 15, "Suspicious activity": 15, "verify account": 15,
    "unusual activity": 15, "account suspended": 15, "security alert": 15, "verify information": 15,
    "verify identity": 15, "unlock account": 15, "Get rich quick": 15, "Double your investment": 15,
    "Guaranteed returns": 15, "Gift card": 15, "Free trial": 15, "Limited offer": 15, "Special promotion": 15,
    "Bank:": 15, "click to claim": 15, "URGENT": 15, "ACTION REQUIRED": 15, "DO THIS NOW": 15,
    "IMPORTANT": 15, "$$$": 15, "€€€": 15, "£££": 15, "₽": 15, "₹": 15, "¥": 15, "₿": 15, "₩": 15,
    "₦": 15, "₫": 15, "!": 15, "!!!": 15, "⚠️": 15, "⚠️ ALERT": 15, "💰": 15, "💵": 15, "💶": 15, "💷": 15,
    "🎉": 15, "prize money": 15, "jackpot": 15, "lottery winner": 15, "lucky draw": 15, "phishing alert": 15,
    "security notice": 15, "malware": 15, "virus detected": 15, "confirm your credentials": 15,
    "click to unblock": 15, "24-hour notice": 15, "contact support now": 15, "click the link below" : 15,

    # Medium-impact keywords (10 points)
    "Congratulations": 10, "winner": 10, "inheritance": 10, "lottery": 10, "jackpot": 10, "prize": 10,
    "limited time": 10, "Need urgent help": 10, "Your account has been compromised": 10, "offer": 10,
    "deal": 10, "free": 10, "special discount": 10, "confirm account": 10, "claim your $": 10,
    "exclusive deal": 10, "secure your €": 10, "pay now": 10, "£10,000 prize": 10, "low-cost offer": 10,
    "⚠️": 10, "💵": 10, "💶": 10, "💷": 10, "limited access": 10, "your balance is low": 10, "claim €100": 10,
    "₹500 reward": 10, "₿50 free": 10, "pay a small fee": 10, "click to avoid suspension": 10,
    "identity verification required": 10, "unusual login attempt": 10, "debt relief": 10, "fake invoice": 10,
    "service terminated": 10, "tax refund": 10, "crypto mining": 10, "crypto wallet": 10, "expired" : 10,

    # Low-impact keyword/s (5 points)
    "deal": 5, "free": 5, "special discount": 5, "click to claim": 5, "act now": 5, "urgent action required": 5,
    "payment details": 5, "login": 5, "account": 5, "Payment": 5, "secure payment": 5, "pay here": 5,
    "win big": 5, "limited access": 5, "claim €100": 5, "₹500 reward": 5, "₿50 free": 5, "get $100": 5,
    "low-cost membership": 5, "validate your identity": 5, "new login detected": 5, "fake charity": 5,
    "emergency fund": 5, "technical support": 5, "click to activate": 5, "confirm now": 5,
    "call us for assistance": 5, "unknown device detected": 5,
}

# Legitimate Domains
legitimate_domains = [
    "google.com", "paypal.com", "microsoft.com", "amazon.com", "apple.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "facebook.com",
    "instagram.com", "twitter.com", "linkedin.com", "github.com", "zoom.us",
    "dropbox.com", "ebay.com", "icloud.com", "hsbc.com", "citibank.com",
    "americanexpress.com", "venmo.com", "stripe.com", "squareup.com",
    "netflix.com", "adobe.com", "youtube.com", "tumblr.com", "reddit.com",
    "tiktok.com", "pinterest.com", "yahoo.com", "outlook.com", "mail.ru",
]

# Preprocess images for OCR
def preprocess_image_for_ocr(temp_path):
    img = cv2.imread(temp_path, cv2.IMREAD_COLOR)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
    pil_img = Image.fromarray(thresh)
    text = image_to_string(pil_img, config="--psm 6", lang="eng")
    return text

def detect_text_and_domain_issues(text):
    """
    Analyze text for spelling, grammar, phishing domains, and both positive and negative traits.
    """
    blob = TextBlob(text)
    errors = 0
    positive_score = 0
    details = []
    positive_details = []

    # Check spelling and grammar
    misspelled_words = [word for word in blob.words if word.lower() != word.correct().lower()]
    if not misspelled_words:
        positive_score += 2  # Reduced impact
        positive_details.append("No spelling or grammar issues detected.")
    else:
        for word in misspelled_words:
            errors += 10  # Increased impact of errors
            details.append(f"Misspelled word: {word}")

    # Extract domains/URLs from text
    domains = re.findall(r'\b(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', text)

    if not domains:
        positive_score += 5  # Reduced impact
        positive_details.append("No suspicious domains or URLs detected.")

    for domain in domains:
        # Suspicious TLDs
        if re.search(r'\.(xyz|info|buzz|click|top|online|icu|club|zip|ru|tk|ml|ga|cf|gq|pw)$', domain):
            errors += 15
            details.append(f"Suspicious TLD detected: {domain}")
        else:
            positive_score += 5 # Further reduced impact
            positive_details.append(f"Legitimate-looking domain detected: {domain}")

        # Subdomain-heavy domains
        if len(domain.split('.')) > 3:
            errors += 10
            details.append(f"Suspicious subdomain structure: {domain}")
        else:
            positive_score += 5  # Minimal impact
            positive_details.append(f"Domain has a simple structure: {domain}")

        # Check for legitimate domain spoofing
        spoofing_issue = detect_legitimate_domain_spoofing(domain)
        if spoofing_issue:
            errors += 15
            details.append(spoofing_issue)
        else:
            positive_score += 5  # Minimal impact
            positive_details.append(f"No spoofing detected for domain: {domain}")

    # Check for IP-based domains
    ip_based_domains = [domain for domain in domains if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain)]
    if not ip_based_domains:
        positive_score += 5  # Minimal impact
        positive_details.append("No IP-based domains detected.")
    else:
        for domain in ip_based_domains:
            errors += 15
            details.append(f"IP-based domain detected: {domain}")

    # Check for absence of shortened URLs
    if not re.search(r'\b(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|rb\.gy)\b', text):
        positive_score += 5  # Minimal impact
        positive_details.append("No shortened URLs detected.")
    else:
        errors += 15
        details.append("Shortened URL detected.")

    # Check 'From' and 'Reply-To' headers
    headers = re.findall(r'From:.*?<(.*?)>', text)
    if not headers:
        positive_score += 5  # Minimal impact
        positive_details.append("No suspicious 'From' or 'Reply-To' headers detected.")
    for header in headers:
        if not any(domain in header for domain in legitimate_domains):
            errors += 15
            details.append(f"Suspicious 'From' header: {header}")
        else:
            positive_score += 1  # Minimal impact
            positive_details.append(f"Valid 'From' header detected: {header}")

    # Check for suspicious keywords
    keyword_density = sum(1 for keyword in scam_keywords if keyword.lower() in text.lower()) / (len(blob.words) + 1)
    if keyword_density < 0.05:
        positive_score += 2  # Minimal impact
        positive_details.append("Low keyword density suggests legitimate content.")
    else:
        errors += int(keyword_density * 80)
        details.append(f"High keyword density detected: {keyword_density:.2f}")

    # No phishing indicators
    if errors == 0:
        positive_score += 2  # Minimal impact
        positive_details.append("No phishing indicators detected in text.")

    # Calculate overall score
    total_words = len(blob.words) if len(blob.words) > 0 else 1
    error_ratio = errors / total_words
    score = int(min(error_ratio * 100, 100))  # Cap negative score at 100%

    return score, details, positive_score, positive_details

# Function to check for legitimate domain spoofing
def detect_legitimate_domain_spoofing(domain):
    """
    Check if the domain spoofs a legitimate domain from the trusted list.
    """
    for legit_domain in legitimate_domains:
        if legit_domain in domain.lower() and not domain.lower().startswith(f"www.{legit_domain}"):
            return f"Potential spoofing of legitimate domain: {domain}"
    return None

# Function to calculate entropy
def calculate_entropy(string):
    probabilities = [string.count(c) / len(string) for c in set(string)]
    entropy = -sum(p * math.log2(p) for p in probabilities)
    return entropy

# Updated analyze_text_with_model function
def analyze_text_with_model(text):
    """
    Analyzes the input text for scam detection using the ML model and heuristic-based methods.
    """
    try:
        # Tokenize and pad input
        sequences = tokenizer.texts_to_sequences([text])
        padded_sequences = pad_sequences(sequences, maxlen=100, padding="post", truncating="post")

        # ML model prediction
        prediction = model.predict(padded_sequences)[0][0]
        model_score = round(prediction * 100, 2)

        # Combine scores
        result = calculate_combined_score(text, model_score)

        # Log important debugging information
        print("\n--- DEBUG INFO ---")
        print(f"Input Text: {text}")
        print(f"Model Prediction Score: {model_score}")
        print(f"Combined Scam Score: {result.get('scam_score', 0)}")
        print(f"Threat Level: {result.get('threat_level', 'Green')}")
        print(f"Details: {result.get('details', [])}")
        print(f"Positive Indicators: {result.get('positive_details', [])}\n")

        return {
            "model_label": "scam" if model_score > 50 else "not scam",
            "model_confidence": model_score,
            "scam_score": float(result.get("scam_score", 0)),
            "heuristic_scam_score": float(result.get("heuristic_score", 0)),
            "positive_score": float(result.get("positive_score", 0)),
            "threat_level": result.get("threat_level", "Green"),
            "risk_label": result.get("risk_label", "Low Risk"),
            "classification": result.get("classification", "not scam"),
            "details": result.get("details", []),
            "positive_details": result.get("positive_details", []),
        }
    except Exception as e:
        print(f"Error in analyze_text_with_model: {e}")
        return {
            "error": "Failed to analyze the text. Please check the input and model configuration."
        }

# Improved calculate_combined_score function
def calculate_combined_score(text, model_score):
    """
    Combines ML model confidence, scam keyword scores, and heuristic scores
    with proper normalization and weighting.
    """
    try:
        # Analyze scam keywords
        keyword_score, keyword_details = analyze_keywords(text)

        # Analyze domain and text issues (including positives)
        heuristic_score, heuristic_details, positive_score, positive_details = detect_text_and_domain_issues(text)

        # Assign weights
        weighted_ml_score = model_score * 0.2  # ML contributes 20%
        remaining_weight = 1 - 0.2  # Allocate 80% to keyword and heuristic scores

        # Normalize keyword and heuristic scores
        total_heuristic_keywords = keyword_score + heuristic_score
        keyword_weight = keyword_score / total_heuristic_keywords if total_heuristic_keywords > 0 else 0.5
        heuristic_weight = 1 - keyword_weight

        # Limit positive impact
        max_positive_impact = heuristic_score * 0.25  # Positive indicators reduce score by up to 25%
        adjusted_heuristic_score = max(0, heuristic_score - min(positive_score, max_positive_impact))

        # Calculate weighted scores
        weighted_keyword_score = keyword_score * remaining_weight * keyword_weight
        weighted_heuristic_score = adjusted_heuristic_score * remaining_weight * heuristic_weight

        # Final score calculation
        total_score = min(weighted_ml_score + weighted_keyword_score + weighted_heuristic_score, 100)

        # Threat level assignment
        if total_score > 70:
            threat_level = "Red"
            risk_label = "High Risk"
        elif total_score > 35:
            threat_level = "Yellow"
            risk_label = "Medium Risk"
        else:
            threat_level = "Green"
            risk_label = "Low Risk"

        return {
            "scam_score": float(total_score),
            "threat_level": threat_level,
            "risk_label": risk_label,
            "details": keyword_details + heuristic_details,
            "positive_details": positive_details,
        }
    except Exception as e:
        print(f"Error in calculate_combined_score: {e}")
        return {
            "scam_score": 0,
            "threat_level": "Green",
            "risk_label": "Low Risk",
            "details": [],
            "positive_details": [],
        }

# Enhanced analyze_keywords function
def analyze_keywords(text):
    """
    Analyzes the text for scam-related keywords and calculates a score based on their weight.
    """
    score = 0
    details = []

    for keyword, weight in scam_keywords.items():
        if keyword.lower() in text.lower():
            score += weight
            details.append(f"Keyword detected: {keyword} ({weight} points)")

    return score, details


# Helper function to sanitize data
def sanitize_analysis_data(data):
    if isinstance(data, dict):
        return {k: sanitize_analysis_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_analysis_data(v) for v in data]
    elif isinstance(data, (int, float, str, bool)) or data is None:
        return data
    elif isinstance(data, (np.float32, np.float64)):  # Handle NumPy float types
        return float(data)
    elif isinstance(data, (np.int32, np.int64)):  # Handle NumPy integer types
        return int(data)
    else:
        return str(data)

# Flask routes
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze-text", methods=["POST"])
def analyze_text():
    text = request.form.get("text", "")
    if not text:
        return render_template("error.html", message="No text provided!")
    result = analyze_text_with_model(text)
    return render_template("results.html", analysis=result, input_text=text)

@app.route("/analyze-image", methods=["POST"])
def analyze_image():
    file = request.files.get("image")
    if not file:
        return render_template("error.html", message="No image provided!")
    try:
        # Save the uploaded file
        temp_path = f"/tmp/{file.filename}"
        file.save(temp_path)

        # Detect file type
        file_type = magic.from_file(temp_path, mime=True)
        print(f"Uploaded file type: {file_type}")

        # Validate supported file types
        if file_type not in ["image/png", "image/jpeg", "image/bmp", "image/tiff"]:
            return render_template("error.html", message="Unsupported image format! Supported formats: PNG, JPEG, BMP, TIFF.")

        # Attempt to open the image
        try:
            img = Image.open(temp_path)
        except UnidentifiedImageError:
            return render_template("error.html", message="Cannot identify image file. Please upload a valid image!")

        # Preprocess the image for OCR
        img = img.convert("L").filter(ImageFilter.SHARPEN)

        # Extract text using pytesseract
        text = image_to_string(img)
        if not text.strip():
            return render_template("error.html", message="No text detected in the image!")

        # Analyze extracted text
        result = analyze_text_with_model(text)
        return render_template("results.html", analysis=result, input_text=text)

    except Exception as e:
        # Log exception for debugging
        print(f"Error: {str(e)}")
        return render_template("error.html", message=f"Error processing image: {str(e)}")

@app.route("/analyze-pdf", methods=["POST"])
def analyze_pdf():
    file = request.files.get("pdf")
    if not file:
        return render_template("error.html", message="No PDF provided!")
    try:
        temp_path = f"/tmp/{file.filename}"
        file.save(temp_path)
        pages = convert_from_path(temp_path)
        text = ''.join(image_to_string(page) for page in pages)
        result = analyze_text_with_model(text)
        return render_template("results.html", analysis=result, input_text=text)
    except Exception as e:
        return render_template("error.html", message=f"Error processing PDF: {e}")

@app.route("/analyze-link", methods=["POST"])
def analyze_link():
    link = request.form.get("link", "")
    if not link:
        return render_template("error.html", message="No link provided!")
    result = analyze_text_with_model(link)
    return render_template("results.html", analysis=result, input_text=link)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)