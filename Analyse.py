import tensorflow as tf
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout, Conv2D, MaxPooling2D, Flatten
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from sklearn.ensemble import IsolationForest
import numpy as np
import cv2


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
        return 3 if prediction[0] > 0.5 else 1


# 2. Image Analysis Model (Sensitive Content Detection)
class ImageClassifier:
    def __init__(self):
        self.model = None

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
        self.model = model

    def train_model(self, images, labels):
        self.build_model()
        self.model.fit(images, labels, epochs=10, validation_split=0.2)

    def predict_threat_level(self, image_path):
        image = cv2.imread(image_path)
        image = cv2.resize(image, (128, 128))
        image = image / 255.0
        prediction = self.model.predict(np.array([image]))
        return 3 if prediction[0][0] > 0.5 else 1


# 3. Metadata Analysis (Anomaly Detection)
class MetadataAnalyzer:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1)

    def train_model(self, metadata_features):
        self.model.fit(metadata_features)

    def predict_threat_level(self, feature_vector):
        prediction = self.model.predict([feature_vector])
        return 3 if prediction[0] == -1 else 1


# 4. Aggregation Model (Threat Level Calculation)
class ThreatAggregator:
    def __init__(self, text_classifier, image_classifier, metadata_analyzer):
        self.text_classifier = text_classifier
        self.image_classifier = image_classifier
        self.metadata_analyzer = metadata_analyzer

    def aggregate_threat_level(self, text, image_path, metadata):
        text_score = self.text_classifier.predict_threat_level(text)
        image_score = self.image_classifier.predict_threat_level(image_path)
        metadata_score = self.metadata_analyzer.predict_threat_level(metadata)

        weighted_score = 0.4 * text_score + 0.4 * image_score + 0.2 * metadata_score

        if weighted_score >= 2.5:
            return "Red"  # High threat
        elif weighted_score >= 1.5:
            return "Yellow"  # Moderate threat
        else:
            return "Green"  # Low threat


# 5. Full Threat Analysis Pipeline
def analyze_data_package(text, image_path, metadata_features, text_samples, text_labels, image_samples, image_labels):
    # Initialize models
    text_classifier = TextClassifier()
    image_classifier = ImageClassifier()
    metadata_analyzer = MetadataAnalyzer()

    # Train models
    x_text, y_text = text_classifier.preprocess_text(text_samples, text_labels)
    text_classifier.train_model(x_text, y_text)
    image_classifier.train_model(image_samples, image_labels)
    metadata_analyzer.train_model(metadata_features)

    # Aggregate threat level
    threat_aggregator = ThreatAggregator(text_classifier, image_classifier, metadata_analyzer)
    threat_level = threat_aggregator.aggregate_threat_level(text, image_path, metadata_features)

    return threat_level


# Example Usage
text = "Congratulations! You've won a free gift. Just send your credit card details."
image_path = "path/to/image.jpg"
metadata_features = [0.5, 0.2]  # Example metadata features (normalized)

# Sample training data (placeholder data)
text_samples = ["example text 1", "example text 2"]
text_labels = [1, 0]  # 1 = spam, 0 = non-spam
image_samples = np.random.rand(100, 128, 128, 3)  # Placeholder image data
image_labels = np.random.randint(0, 2, 100)  # Placeholder labels

threat_level = analyze_data_package(text, image_path, metadata_features, text_samples, text_labels, image_samples, image_labels)
print("Threat Level:", threat_level)
