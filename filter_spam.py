import pandas as pd

# Load the dataset
file_path = 'sms+spam+collection/SMSSpamCollection.csv'  # Adjust the path if needed
data = pd.read_csv(file_path, sep='\t', header=None, names=['label', 'message'])

# Define relevant scam keywords and patterns
scam_keywords = ["visa", "immigration", "urgent", "click here", 
                 "deportation", "credit card", "bank", "prize", "win", "lottery"]

# Filter messages containing relevant keywords
def is_relevant(message):
    return any(keyword in message.lower() for keyword in scam_keywords)

# Apply the filter to the dataset
data['is_relevant'] = data['message'].apply(is_relevant)

# Filter only relevant spam messages
relevant_data = data[(data['label'] == 'spam') & (data['is_relevant'])]
relevant_data.drop(columns=['is_relevant'], inplace=True)

# Save the filtered data to a new CSV file
output_file_path = 'RelevantSpamMessages.csv'
relevant_data.to_csv(output_file_path, index=False)

print(f"Filtered data saved to {output_file_path}")
