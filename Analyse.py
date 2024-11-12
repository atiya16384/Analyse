import os
import requests
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import tensorflow as tf
import pytesseract
from transformers import pipeline
from PIL import Image
import pdfplumber

# Set environment variable to prevent tokenizer parallelism warning
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Disable GPU for TensorFlow on M1/M2 Macs
tf.config.set_visible_devices([], 'GPU')

# Set path for Tesseract OCR (update path if Tesseract is installed in a different location)
pytesseract.pytesseract.tesseract_cmd = r'/usr/local/bin/tesseract'  # Change this if needed

# Google Safe Browsing API Key for Link Analysis
GOOGLE_API_KEY = 'AIzaSyDtKbncP45QC6Qv5JjhymNO84vaVUqG-C4'

# Scam score function
def get_scam_score_and_risk_level(prediction_prob):
    scam_score = int(prediction_prob * 100)
    if scam_score > 80:
        return scam_score, "High Risk", "Red"
    elif 50 < scam_score <= 80:
        return scam_score, "Moderate Risk", "Yellow"
    else:
        return scam_score, "Low Risk", "Green"

# 1. Text Analysis Model using a Lightweight Pre-trained Model
try:
    scam_text_classifier = pipeline("text-classification", model="distilbert-base-uncased", device=-1)
except Exception as e:
    print("Error loading text classifier model:", e)

# Example usage for Text Analysis
try:
    text_input = "Free entry in a weekly competition! Send your credit card details."
    text_prediction = scam_text_classifier(text_input, truncation=True)[0]
    prediction_prob = text_prediction["score"]
    scam_score_text, risk_level_text, color_text = get_scam_score_and_risk_level(prediction_prob)
    print(f"Text Scam Score: {scam_score_text}%, Risk Level: {risk_level_text}, Color: {color_text}")
except Exception as e:
    print("Error during text analysis:", e)

# 2. Link Analysis using Google Safe Browsing API
def check_url_with_safe_browsing(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    headers = {"Content-Type": "application/json"}
    data = {
        "client": {
            "clientId": "cyberApp",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(endpoint, headers=headers, json=data)
        if response.status_code == 200:
            if response.json():
                return "High Risk", "Red"
            else:
                return "Low Risk", "Green"
        else:
            print("Error with Google Safe Browsing API:", response.status_code)
            return "Unknown Risk", "Gray"
    except requests.RequestException as e:
        print("Network error:", e)
        return "Unknown Risk", "Gray"

# Test URL for Link Analysis
try:
    test_url = "http://kf8gmb.shop/"
    risk_level_link, color_link = check_url_with_safe_browsing(test_url)
    print(f"Link Risk Level: {risk_level_link}, Color: {color_link}")
except Exception as e:
    print("Error during link analysis:", e)

# 3. File Analysis (OCR + Text Classifier)
class FileAnalyzer:
    def __init__(self, text_classifier):
        self.text_classifier = text_classifier

    def analyze_image(self, file_path):
        try:
            text = pytesseract.image_to_string(Image.open(file_path))
            return self.analyze_text(text)
        except Exception as e:
            print(f"Error analyzing image {file_path}:", e)
            return {"error": str(e)}

    def analyze_pdf(self, file_path):
        text = ""
        try:
            with pdfplumber.open(file_path) as pdf:
                for page in pdf.pages:
                    text += page.extract_text() + "\n"
            return self.analyze_text(text)
        except Exception as e:
            print(f"Error analyzing PDF {file_path}:", e)
            return {"error": str(e)}

    def analyze_text(self, text):
        try:
            prediction = self.text_classifier(text, truncation=True)[0]
            prediction_prob = prediction["score"]
            scam_score, risk_level, color = get_scam_score_and_risk_level(prediction_prob)
            return {
                "scam_score": scam_score,
                "risk_level": risk_level,
                "color": color,
                "extracted_text": text[:500]  # Limit to 500 characters for readability
            }
        except Exception as e:
            print("Error during text classification:", e)
            return {"error": str(e)}

# Example usage of File Analyzer
file_analyzer = FileAnalyzer(scam_text_classifier)

try:
    image_analysis_result = file_analyzer.analyze_image("1326.png")
    print("Image Analysis Result:", image_analysis_result)
    
    pdf_analysis_result = file_analyzer.analyze_pdf("scamemail.pdf")
    print("PDF Analysis Result:", pdf_analysis_result)
except Exception as e:
    print("Error during file analysis:", e)
