import os
import time
import sqlite3
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from PIL import Image

# ChromeDriver configuration
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument("--disable-notifications")
chrome_options.add_argument("--start-maximized")
chrome_options.add_argument("--user-data-dir=./chrome_session")  # Saves browser session
service = Service("./chromedriver")
driver = webdriver.Chrome(service=service, options=chrome_options)

# SQLite setup
DB_FILE = "whatsapp_data.db"
members_info = {}  # Cache for storing member names and numbers


def setup_database():
    """Create the SQLite database and messages table."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            sender TEXT,
            text TEXT,
            link TEXT,
            screenshot_path TEXT
        )
    """)
    conn.commit()
    conn.close()
    print("✅ Database setup complete. Table 'messages' is ready.")


def insert_to_db(data):
    """Insert message data into the SQLite database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO messages (timestamp, sender, text, link, screenshot_path)
            VALUES (?, ?, ?, ?, ?)
        """, (data.get('timestamp'), data.get('sender'), data.get('text'), data.get('link'), data.get('screenshot_path')))
        conn.commit()
        print(f"✅ Data inserted into database: {data}")
    except Exception as e:
        print(f"❌ Failed to insert into database: {e}")
    finally:
        conn.close()


def take_message_screenshot(message_element, name="message.png"):
    """Takes a screenshot of a specific message element."""
    screenshot_dir = "screenshots"
    os.makedirs(screenshot_dir, exist_ok=True)
    screenshot_path = os.path.join(screenshot_dir, name)
    location = message_element.location
    size = message_element.size
    driver.save_screenshot("temp_full_screen.png")
    full_image = Image.open("temp_full_screen.png")
    left = location['x']
    top = location['y']
    right = left + size['width']
    bottom = top + size['height']
    cropped_image = full_image.crop((left, top, right, bottom))
    cropped_image.save(screenshot_path)
    os.remove("temp_full_screen.png")
    print(f"📸 Screenshot saved: {screenshot_path}")
    return screenshot_path
def extract_group_members():
    """Extract group members' names and phone numbers."""
    try:
        print("👥 Extracting group members' info...")

        # Click the rightmost three-dot menu
        menu_button_xpath = "(//div[@role='button' and @title='Menu'])[2]"
        WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, menu_button_xpath))
        ).click()
        print("✅ Rightmost three-dot menu clicked.")

        # Click 'Group info'
        group_info_xpath = "//div[@role='button']//span[contains(text(), 'Group info')]"
        WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, group_info_xpath))
        ).click()
        print("✅ Group info opened.")

        # Extract group members
        members_list_xpath = "//div[@role='listitem']"
        members = WebDriverWait(driver, 10).until(
            EC.presence_of_all_elements_located((By.XPATH, members_list_xpath))
        )

        # Loop through and extract members' names
        for member in members:
            try:
                name = member.find_element(By.XPATH, ".//span[contains(@class, '_3YS_f')]").text
                print(f"👤 Member: {name}")
                members_info[name] = name
            except Exception as e:
                print(f"⚠️ Could not extract member info: {e}")

        print("✅ Group member extraction complete.")
    except Exception as e:
        print(f"❌ Error extracting group members: {e}")


def process_message(msg_element):
    """Processes a single message element."""
    try:
        timestamp = time.time()
        sender_name = "Unknown"  # Default name

        # Extract sender name using 'data-pre-plain-text'
        try:
            sender_element = msg_element.find_element(By.XPATH, ".//div[@data-pre-plain-text]")
            pre_text = sender_element.get_attribute("data-pre-plain-text")
            sender_name = pre_text.split("]")[1].split(":")[0].strip() if pre_text else "Unknown"
        except Exception as e:
            print(f"⚠️ Unable to extract sender: {e}")

        # Extract message text
        try:
            text_elements = msg_element.find_elements(By.XPATH, ".//span[@class='selectable-text']")
            text = " ".join([t.text for t in text_elements]) if text_elements else None
        except:
            text = None

        # Extract links
        link_elements = msg_element.find_elements(By.XPATH, ".//a[contains(@href, 'http')]")
        link = link_elements[0].get_attribute("href") if link_elements else None

        # Screenshot message
        screenshot_path = take_message_screenshot(msg_element, f"screenshots/message_{int(timestamp)}.png")

        # Insert into database
        data = {"timestamp": timestamp, "sender": sender_name, "text": text, "link": link, "screenshot_path": screenshot_path}
        insert_to_db(data)

        # Print debug info
        print(f"👤 Sender: {sender_name}")
        if text:
            print(f"📝 Text: {text}")
        if link:
            print(f"🔗 Link: {link}")
        print(f"📸 Screenshot Path: {screenshot_path}")

    except Exception as e:
        print(f"❌ Error processing message: {e}")


def scrape_whatsapp_group(group_name, chat_name):
    """Main function to scrape WhatsApp messages."""
    try:
        print("🚀 Opening WhatsApp Web...")
        driver.get("https://web.whatsapp.com")
        time.sleep(15)  # Wait for QR login

        # Open the target group chat
        print(f"🟢 Opening group: {group_name}")
        group_element = WebDriverWait(driver, 20).until(
            EC.element_to_be_clickable((By.XPATH, f"//span[@title='{group_name}']"))
        )
        group_element.click()

        print("🔍 Extracting group members...")
        extract_group_members()

        # Process messages with duplicates prevention
        processed_ids = set()
        print("🔍 Processing messages...")
        chat_area = driver.find_element(By.XPATH, "//div[@id='main']")
        for _ in range(10):  # Limit scrolls
            messages = driver.find_elements(By.XPATH, "//div[contains(@class, 'message-in') or contains(@class, 'message-out')]")
            for msg in messages:
                process_message(msg_element=msg)
            driver.execute_script("arguments[0].scrollTop -= 1000;", chat_area)
            time.sleep(2)

        print("🎉 All messages processed successfully.")

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        driver.quit()
        print("🔒 Browser closed.")

if __name__ == "__main__":
    setup_database()
    scrape_whatsapp_group("App_server", "General")
