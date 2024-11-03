import tensorflow as tf
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout, Conv2D, MaxPooling2D, Flatten
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
import numpy as np
import cv2
import pandas as pd
import pytesseract  # For OCR in file analysis
import os
import requests
from sklearn.model_selection import train_test_split # For splitting data into training and testing sets

# Set path for Tesseract OCR (if needed for file analysis later)
pytesseract.pytesseract.tesseract_cmd = r'/usr/bin/tesseract'  # Adjust if necessary

# Load SMS Spam Dataset for Text Analysis
sms_data = pd.read_csv('sms+spam+collection/SMSSpamCollection.csv', encoding='latin-1')[['v1', 'v2']]
sms_data.columns = ['label', 'message']
sms_data['label'] = sms_data['label'].map({'ham': 0, 'spam': 1})

text_samples = sms_data['message'].tolist()
text_labels = sms_data['label'].tolist()

# 1. Text Analysis Model (Spam/Bot Detection)
class TextClassifier:
    def __init__(self, max_words=5000, max_len=100):
        self.tokenizer = Tokenizer(num_words=max_words)
        self.max_len = max_len

    def preprocess_text(self, texts, labels):
        self.tokenizer.fit_on_texts(texts)
        sequences = self.tokenizer.texts_to_sequences(texts)
        x_train = pad_sequences(sequences, maxlen=self.max_len)
        y_train = np.array(labels)
        return x_train, y_train

    def build_model(self):
        model = tf.keras.Sequential([
            Embedding(input_dim=5000, output_dim=128, input_length=self.max_len),
            LSTM(64, return_sequences=True),
            Dropout(0.2),
            LSTM(32),
            Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model

    def train_model(self, x_train, y_train):
        self.model = self.build_model()
        self.model.fit(x_train, y_train, epochs=10, validation_split=0.2)

    def predict_threat_level(self, text):
        sequence = self.tokenizer.texts_to_sequences([text])
        padded = pad_sequences(sequence, maxlen=self.max_len)
        prediction = self.model.predict(padded)
        return "High" if prediction[0] > 0.5 else "Low"



# Train Text Analysis Model
text_classifier = TextClassifier()
x_text, y_text = text_classifier.preprocess_text(text_samples, text_labels)
text_classifier.train_model(x_text, y_text)



# Set up directories for downloaded images
categories = {
    "drawings": 0,
    "hentai": 1,
    "neutral": 0,
    "porn": 1,
    "sexy": 1
}
base_dir = "nsfw_images"
os.makedirs(base_dir, exist_ok=True)

def download_images():
    for category, label in categories.items():
        os.makedirs(f"{base_dir}/{category}", exist_ok=True)
        with open(f"nsfw_data_scraper/raw_data/{category}/urls_{category}.txt", 'r') as file:
            urls = file.readlines()
            for idx, url in enumerate(urls):
                try:
                    img_data = requests.get(url.strip()).content
                    img_path = f"{base_dir}/{category}/{category}_{idx}.jpg"
                    with open(img_path, 'wb') as handler:
                        handler.write(img_data)
                except Exception as e:
                    print(f"Failed to download {url.strip()}: {e}")

# Run this once to download the images
# download_images()

# Preprocess downloaded images for model training
def load_images():
    images = []
    labels = []
    for category, label in categories.items():
        category_path = os.path.join(base_dir, category)
        for img_name in os.listdir(category_path):
            img_path = os.path.join(category_path, img_name)
            try:
                img = cv2.imread(img_path)
                img = cv2.resize(img, (128, 128))
                img = img / 255.0  # Normalize
                images.append(img)
                labels.append(label)
            except Exception as e:
                print(f"Error processing {img_path}: {e}")
    return np.array(images), np.array(labels)

# Load and split data for training
images, labels = load_images()
x_train, x_test, y_train, y_test = train_test_split(images, labels, test_size=0.2, random_state=42)

# Define and train the image classifier

class ImageClassifier:
    def __init__(self):
        self.model = self.build_model()

    def build_model(self):
        model = Sequential([
            Conv2D(32, (3, 3), activation='relu', input_shape=(128, 128, 3)),
            MaxPooling2D(pool_size=(2, 2)),
            Conv2D(64, (3, 3), activation='relu'),
            MaxPooling2D(pool_size=(2, 2)),
            Flatten(),
            Dense(128, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model

    def train_model(self, x_train, y_train):
        self.model.fit(x_train, y_train, epochs=10, validation_split=0.2)

    def predict_threat_level(self, image):
        image = cv2.resize(image, (128, 128))
        image = image / 255.0
        prediction = self.model.predict(np.array([image]))
        return "High" if prediction[0][0] > 0.5 else "Low"

# Train the model
image_classifier = ImageClassifier()
image_classifier.train_model(x_train, y_train)

# Example usage
sample_image_path = "path/to/test_image.jpg"  # Replace with actual test image path
sample_image = cv2.imread(sample_image_path)
threat_level = image_classifier.predict_threat_level(sample_image)
print(f"Image Threat Level: {threat_level}")
