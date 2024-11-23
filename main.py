import re
from pdf2image import convert_from_path
from pytesseract import image_to_string
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import tokenizer_from_json
import json

# Load your trained scam detection model
model = tf.keras.models.load_model("optimized_scam_detection_model.keras")

# Load the tokenizer
with open("tokenizer_config.json", "r") as file:
    tokenizer_json = file.read()
    tokenizer = tokenizer_from_json(json.loads(tokenizer_json))

# Define scam keywords with weights
scam_keywords = {
    # High-impact keywords (15 points)
    "urgent": 15, "password": 15, "credit card": 15, "click here": 15,
    "claim reward": 15, "refund": 15, "bank account": 15, "verify": 15,
    "free money": 15, "bit.ly": 15, "tinyurl": 15, "update details": 15,
    "SSN": 15, "Social Security Number": 15, "Suspicious activity": 15,
    "verify account": 15, "unusual activity": 15, "account suspended": 15,
    "security alert": 15, "verify information": 15, "verify identity": 15,
    "confirm account": 15, "unlock account": 15,
    "payment details": 15, "login": 15, "account": 15, "Payment": 15,
    "Get rich quick": 15, "Double your investment": 15, "Guaranteed returns": 15,
    "Gift card": 15, "Free trial": 15, "Limited offer": 15, "Special promotion": 15,
    "Bank:" : 15, "click to claim" : 10,
    
    
    # Medium-impact keywords (10 points)
    "Congratulations": 10, "winner": 10, "inheritance": 10,
    "lottery": 10, "jackpot": 10, "prize": 10, "limited time": 10,
    "Need urgent help": 10, "Your account has been compromised": 10,
    "offer": 10, "deal": 10, "free": 10, "special discount": 10,

    "" 

    # Low-impact keywords (5 points)
    "offer": 5, "deal": 5, "free": 5, "special discount": 5,
    "click to claim": 5, "act now": 5, "urgent action required": 5,
}

# Define scam patterns with weights
scam_patterns = {
    r"http[s]?://[^\s]*bit\.ly": 15,
    r"http[s]?://[^\s]*tinyurl": 15,
    r"\bDear (user|customer|friend)\b": 10,
    r"action required|urgent": 12,
    r"send .* bitcoin": 20,
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}": 8,
    r"win .* prize|claim .* prize": 12,
    r"verify .* account|verify .* identity": 15,
    r"account .* suspended|locked": 12,
    r"limited time|offer expires": 10,
    r"confirm .* payment|confirm .* details": 15,
    r"http[s]?://.*secure|http[s]?://.*verify": 15,
    r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+": 15,
    r"congratulations|winner|lottery|jackpot": 12,
    r"unusual activity|suspicious login": 12,
    r"important notice|security update": 10,
}

# Functions to calculate scam scores
def calculate_scam_score(text):
    """Calculate score based on keywords."""
    return sum(weight for word, weight in scam_keywords.items() if word.lower() in text.lower())

def calculate_pattern_score(text):
    """Calculate score based on patterns."""
    return sum(weight for pattern, weight in scam_patterns.items() if re.search(pattern, text))

def calculate_combined_score(text):
    keyword_score = calculate_scam_score(text)
    pattern_score = calculate_pattern_score(text)
    total_score = min(keyword_score + pattern_score, 100)

    if total_score > 70:
        threat_level = "Red"
        risk_label = "High Risk"
    elif total_score > 35:
        threat_level = "Yellow"
        risk_label = "Medium Risk"
    else:
        threat_level = "Green"
        risk_label = "Low Risk"

    return {"scam_score": total_score, "threat_level": threat_level, "risk_label": risk_label}

def analyze_text_with_model(text):
    """Analyze text using the trained model."""
    try:
        # Tokenize and pad the text
        sequences = tokenizer.texts_to_sequences([text])
        padded_sequences = pad_sequences(sequences, maxlen=100, padding="post", truncating="post")

        # Predict using the model
        prediction = model.predict(padded_sequences)
        classification_label = "scam" if prediction[0][0] > 0.5 else "not scam"
        classification_score = prediction[0][0]

        # Combine with heuristic-based scores
        combined_score = calculate_combined_score(text)

        return {
            "model_label": classification_label,
            "model_score": classification_score,
            "heuristic_scam_score": combined_score["scam_score"],
            "overall_threat_level": combined_score["threat_level"]
        }
    except Exception as e:
        return {"error": str(e)}

# Extract text from PDF
def extract_text_from_pdf(pdf_path):
    """Extract text from a PDF file."""
    pages = convert_from_path(pdf_path)
    extracted_text = ""
    for page in pages:
        extracted_text += image_to_string(page)
    return extracted_text

# Analyze PDF
def analyze_pdf(pdf_path):
    """Analyze PDF for scam indicators."""
    try:
        text = extract_text_from_pdf(pdf_path)
        print("\nExtracted Text from PDF:")
        print(text)

        return analyze_text_with_model(text)
    except Exception as e:
        return {"error": str(e)}

# Analyze raw text
def analyze_text(text):
    """Analyze raw text for scam indicators."""
    return analyze_text_with_model(text)

# Analyze images
def analyze_image(image_path):
    """Analyze an image for text and scam indicators."""
    try:
        text = image_to_string(image_path)
        print("\nExtracted Text from Image:")
        print(text)

        return analyze_text_with_model(text)
    except Exception as e:
        return {"error": str(e)}

# Analyze links
def analyze_link(link):
    """Analyze links for scam patterns."""
    try:
        scores = calculate_combined_score(link)
        return {
            "link": link,
            "scam_score": scores["scam_score"],
            "threat_level": scores["threat_level"],
        }
    except Exception as e:
        return {"error": str(e)}

# Main function
def main():
    # Test for text analysis
    text = "Congratulations! You've won a $1,000 gift card. Click here: bit.ly/12345"
    print("\nText Analysis Result:")
    print(analyze_text(text))

    # Test for image analysis
    image_path = "1326.png"
    print("\nImage Analysis Result:")
    print(analyze_image(image_path))

    # Test for PDF analysis
    pdf_path = "netflixscreenshot.pdf"
    print("\nPDF Analysis Result:")
    print(analyze_pdf(pdf_path))

    # Test for link analysis
    link = "http://101.10.1.101"
    print("\nLink Analysis Result:")
    print(analyze_link(link))

if __name__ == "__main__":
    main()
