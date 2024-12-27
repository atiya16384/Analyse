# ML Algorithm Cyber Project

This repository contains Python scripts and resources for building and running a scam detection system. The project leverages machine learning, natural language processing (NLP), and heuristic analysis for detecting scams in text, images, links, and other sources.

## Project Structure

### Python Files

- **Analyse.py**
    - Main analysis script for processing text, links, and documents.
    - Includes heuristic and ML-based analysis functions.
    - Outputs scam scores, threat levels, and detailed analysis results.

- **Analyse2.py**
    - An alternate or extended version of the main analysis script.
    - Used for testing different preprocessing or feature extraction techniques.
    - Supports integration with additional datasets.

- **extract.py**
    - Extracts information from messages in platforms like WhatsApp.
    - Captures sender details, text, links, and takes message-specific screenshots.
    - Inserts extracted data into the SQLite database (whatsapp_data.db).

- **firebase.py**
    - Handles integration with Firebase for storing and retrieving app-related data.
    - Manages user authentication, real-time database updates, and storage.

- **share.py**
    - Responsible for implementing a feature that allows sharing analysis results.
    - Facilitates exporting and sharing scam detection reports.

- **testUI.py**
    - Script for testing the Flask-based web interface.
    - Includes routes for analyzing text, images, links, and PDFs.
    - Provides a web-based front end for scam analysis.

### Datasets

- **balanced_combined_dataset.csv**
    - A balanced dataset for training and testing the scam detection model.
    - Combines multiple sources of scam and non-scam data.

- **link_dataset.csv**
    - Dataset of links used for detecting phishing and malicious domains.

- **malicious_phish.csv**
    - A phishing dataset containing examples of malicious URLs and associated metadata.

- **Phishing_Email.csv**
    - Email-specific dataset used for training the scam detection model.

- **scam.csv**
    - General-purpose dataset for detecting scam patterns in text.

### Model and Configuration

- **optimized_scam_detection_model.keras**
    - Pretrained TensorFlow/Keras scam detection model.
    - Used for predicting the likelihood of scam content.

- **tokenizer_config.json**
    - Tokenizer configuration used for preprocessing text inputs for the ML model.

### Database

- **whatsapp_data.db**
    - SQLite database for storing extracted message data from WhatsApp.
    - Contains information like sender details, timestamps, and message content.

### Other Files

- **requirements.txt**
    - Contains the list of Python dependencies required for the project.

- **README.md**
    - Documentation file describing the repository and its contents.

## Instructions

### Setup Environment:

1. Install Python and required dependencies: `pip install -r requirements.txt`.
2. Configure Firebase and database settings.

### Run Flask App:

1. Start the Flask server using `testUI.py` to test the web interface.

### Extract Data:

1. Use `extract.py` to scrape and analyze messages from WhatsApp.

### Analyze Data:

1. Run `Analyse.py` or `Analyse2.py` for heuristic and ML-based scam detection.

### Share Results:

1. Use `share.py` to export or share scam analysis results.

