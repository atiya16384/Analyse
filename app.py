from flask import Flask, request, jsonify, render_template
import re
from pdf2image import convert_from_path
from pytesseract import image_to_string
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import tokenizer_from_json
import json

# Initialize Flask app
app = Flask(__name__)

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

def calculate_combined_score(text):
    """Calculate combined scam score based on keywords and patterns."""
    keyword_score = sum(weight for word, weight in scam_keywords.items() if word.lower() in text.lower())
    pattern_score = sum(weight for pattern, weight in scam_patterns.items() if re.search(pattern, text))
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
    """Analyze text using the model and heuristics."""
    sequences = tokenizer.texts_to_sequences([text])
    padded_sequences = pad_sequences(sequences, maxlen=100, padding="post", truncating="post")
    prediction = model.predict(padded_sequences)[0][0]
    model_label = "scam" if prediction > 0.5 else "not scam"
    combined_score = calculate_combined_score(text)

    return {
        "model_label": model_label,
        "model_score": round(prediction * 100, 2),
        "heuristic_scam_score": combined_score["scam_score"],
        "threat_level": combined_score["threat_level"],
        "risk_label": combined_score["risk_label"]
    }

@app.route("/")

def home():
    return render_template("index.html")

@app.route("/analyze-text", methods=["POST"])
def analyze_text():
    text = request.form.get("text", "")
    if not text:
        return render_template("error.html", message="No text provided!")
    result = analyze_text_with_model(text)

    # Debugging: Print the result
    print("[DEBUG] Text Analysis Result:", result)

    # Ensure scam_score is an integer
    result["scam_score"] = int(result["heuristic_scam_score"])
    return render_template("results.html", analysis=result, input_text=text)

@app.route("/analyze-image", methods=["POST"])
def analyze_image():
    file = request.files.get("image")
    if not file:
        return render_template("error.html", message="No image provided!")
    try:
        # Save the image temporarily for processing
        temp_path = f"/tmp/{file.filename}"
        file.save(temp_path)

        # Extract text from the image
        text = image_to_string(temp_path)

        # Debugging: Log the extracted text
        print("[DEBUG] Extracted Text from Image:", text)

        # Analyze the extracted text
        result = analyze_text_with_model(text)

        # Debugging: Log the analysis result
        print("[DEBUG] Image Analysis Result:", result)

        # Render the results
        return render_template("results.html", analysis=result, input_text=text)
    except Exception as e:
        print("[DEBUG] Error in Image Analysis:", str(e))
        return render_template("error.html", message=f"Error processing image: {e}")



@app.route("/analyze-pdf", methods=["POST"])
def analyze_pdf():
    file = request.files.get("pdf")
    if not file:
        return render_template("error.html", message="No PDF provided!")
    try:
        temp_path = f"/tmp/{file.filename}"
        file.save(temp_path)

        # Extract text from the PDF
        pages = convert_from_path(temp_path)
        text = ''.join(image_to_string(page) for page in pages)

        # Debugging: Print extracted text
        print("[DEBUG] Extracted Text from PDF:", text)

        result = analyze_text_with_model(text)
        result["scam_score"] = int(result["heuristic_scam_score"])
        return render_template("results.html", analysis=result, input_text=text)
    except Exception as e:
        print("[DEBUG] PDF Analysis Error:", e)
        return render_template("error.html", message=f"Error processing PDF: {e}")


@app.route("/analyze-link", methods=["POST"])
def analyze_link():
    link = request.form.get("link", "")
    if not link:
        return render_template("error.html", message="No link provided!")
    try:
        result = calculate_combined_score(link)
        print("[DEBUG] Combined Score:", result)  # Debugging output
        result["scam_score"] = int(result["scam_score"])
        print("[DEBUG] Result Passed to Template:", result)  # Debugging output
        return render_template("results.html", analysis=result, input_text=link)
    except Exception as e:
        print("[DEBUG] Error in Link Analysis:", str(e))
        return render_template("error.html", message=f"Error analyzing the link: {e}")


if __name__ == "__main__":
    app.run(debug=True)