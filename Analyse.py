import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Step 1: Load the Balanced Dataset
balanced_data = pd.read_csv("balanced_combined_dataset.csv")

# Step 2: Split Dataset into Features and Labels
X = balanced_data["message"]
y = balanced_data["label"].map({"scam": 1, "not scam": 0})  # Map labels to binary

# Step 3: Split Data into Training and Testing Sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 4: Tokenize and Pad Text Data
tokenizer = Tokenizer(num_words=5000, oov_token="<OOV>")  # Max 5000 unique words
tokenizer.fit_on_texts(X_train)

X_train_seq = tokenizer.texts_to_sequences(X_train)
X_test_seq = tokenizer.texts_to_sequences(X_test)

X_train_padded = pad_sequences(X_train_seq, maxlen=100, padding="post", truncating="post")
X_test_padded = pad_sequences(X_test_seq, maxlen=100, padding="post", truncating="post")

# Step 5: Build the LSTM Model
model = Sequential([
    Embedding(input_dim=5000, output_dim=64, input_length=100),  # Word embedding
    LSTM(128, return_sequences=True),
    Dropout(0.3),
    LSTM(64),
    Dropout(0.3),
    Dense(32, activation="relu"),
    Dense(1, activation="sigmoid")  # Binary classification
])

# Step 6: Compile the Model
model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])

# Step 7: Display Model Summary
model.summary()

# Step 8: Train the Model
history = model.fit(
    X_train_padded, y_train,
    validation_data=(X_test_padded, y_test),
    epochs=5, batch_size=32
)

# Step 9: Evaluate the Model
y_pred = (model.predict(X_test_padded) > 0.5).astype("int32")
print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Optional: Save the Model
model.save("scam_detection_model.h5")
