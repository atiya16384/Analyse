import time
import json
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import firebase_admin
from firebase_admin import credentials, firestore

# Firebase Configuration
FIREBASE_CREDENTIALS = "google-services.json"  # Replace with your Firebase JSON key path
FIREBASE_DB_URL = "https://cyber-175cd.firebaseio.com"  # Replace with your Firebase Database URL

# Initialize Firebase
cred = credentials.Certificate(FIREBASE_CREDENTIALS)
firebase_admin.initialize_app(cred, {"databaseURL": FIREBASE_DB_URL})
db = firestore.client()

# WebDriver Configuration
CHROMEDRIVER_PATH = "/path/to/chromedriver"  # Replace with your ChromeDriver path
chrome_options = Options()
chrome_options.add_argument("--user-data-dir=./User_Data")  # Keeps session logged in
chrome_options.add_argument("--profile-directory=Default")
service = Service(CHROMEDRIVER_PATH)
driver = webdriver.Chrome(service=service, options=chrome_options)

# Firebase Storage Function
def store_in_firebase(source, sender, content, attachments=None):
    try:
        doc_ref = db.collection("messages").document()
        doc_ref.set({
            "source": source,
            "sender": sender,
            "content": content,
            "attachments": attachments if attachments else [],
            "timestamp": firestore.SERVER_TIMESTAMP,
        })
        print(f"Message from {source} stored successfully.")
    except Exception as e:
        print(f"Error storing message in Firebase: {e}")

# WhatsApp Scraper
def fetch_whatsapp_messages(chat_name):
    try:
        driver.get("https://web.whatsapp.com")
        print("Waiting for QR code scan...")
        time.sleep(20)  # Allow time for login
        chat = driver.find_element(By.XPATH, f"//span[@title='{chat_name}']")
        chat.click()

        messages = driver.find_elements(By.XPATH, "//div[@class='_1Gy50']")  # Adjust as per the WhatsApp DOM
        for msg in messages:
            content = msg.text
            store_in_firebase("whatsapp", chat_name, content)
    except Exception as e:
        print(f"Error fetching WhatsApp messages: {e}")

# Telegram Scraper
def fetch_telegram_messages(chat_name):
    try:
        driver.get("https://web.telegram.org")
        print("Waiting for Telegram Web login...")
        time.sleep(20)  # Allow time for login
        chat = driver.find_element(By.XPATH, f"//div[@data-peer-title='{chat_name}']")
        chat.click()

        messages = driver.find_elements(By.XPATH, "//div[contains(@class, 'message')]")
        for msg in messages:
            content = msg.text
            store_in_firebase("telegram", chat_name, content)
    except Exception as e:
        print(f"Error fetching Telegram messages: {e}")

# Instagram Scraper
def fetch_instagram_messages(username):
    try:
        driver.get("https://www.instagram.com/direct/inbox/")
        print("Waiting for Instagram Web login...")
        time.sleep(20)  # Allow time for login
        chat = driver.find_element(By.XPATH, f"//div[contains(text(), '{username}')]")
        chat.click()

        messages = driver.find_elements(By.XPATH, "//div[contains(@class, 'text')]")
        for msg in messages:
            content = msg.text
            store_in_firebase("instagram", username, content)
    except Exception as e:
        print(f"Error fetching Instagram messages: {e}")

# Outlook Scraper
def fetch_outlook_emails():
    try:
        driver.get("https://outlook.live.com/mail/0/")
        print("Waiting for Outlook Web login...")
        time.sleep(20)  # Allow time for login
        emails = driver.find_elements(By.XPATH, "//div[contains(@class, 'lvHighlightSubject')]")
        for email in emails:
            sender = email.find_element(By.XPATH, ".//span[@class='lvHighlightSender']").text
            subject = email.find_element(By.XPATH, ".//span[@class='lvHighlightSubject']").text
            content = email.find_element(By.XPATH, ".//span[@class='lvHighlightContent']").text
            store_in_firebase("outlook", sender, f"Subject: {subject}\n\n{content}")
    except Exception as e:
        print(f"Error fetching Outlook emails: {e}")

# Main Execution
if __name__ == "__main__":
    try:
        fetch_whatsapp_messages("Your WhatsApp Chat Name")  # Replace with WhatsApp chat name
        fetch_telegram_messages("Your Telegram Chat Name")  # Replace with Telegram chat name
        fetch_instagram_messages("Your Instagram Username")  # Replace with Instagram username
        fetch_outlook_emails()
    finally:
        driver.quit()
