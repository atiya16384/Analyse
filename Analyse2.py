import pandas as pd

# Load phishing email dataset
phishing_data = pd.read_csv("Phishing_Email.csv", encoding="ISO-8859-1")

# Ensure columns are properly named
phishing_data.columns = ["index", "message", "label"]  # Rename based on your screenshot
phishing_data = phishing_data[["message", "label"]]  # Keep only the relevant columns

# Drop rows with missing values
phishing_data = phishing_data.dropna(subset=["message", "label"])

# Map labels to 'scam' and 'not scam'
phishing_data["label"] = phishing_data["label"].map({
    "Phishing Email": "scam",
    "Safe Email": "not scam"
})

# Load scam.csv dataset
scam_data = pd.read_csv("scam.csv", usecols=[0, 1], encoding="ISO-8859-1")
scam_data.columns = ["label", "message"]

# Map labels for scam.csv to 'scam' and 'not scam'
scam_data["label"] = scam_data["label"].map({"spam": "scam", "ham": "not scam"})

# Combine both datasets
combined_data = pd.concat([scam_data, phishing_data], ignore_index=True)

# Drop duplicate rows if any
combined_data = combined_data.drop_duplicates()

# Undersample 'not scam' to match the number of 'scam'
scam_data = combined_data[combined_data["label"] == "scam"]
not_scam_data = combined_data[combined_data["label"] == "not scam"].sample(len(scam_data), random_state=42)

# Combine balanced dataset
balanced_data = pd.concat([scam_data, not_scam_data], ignore_index=True).sample(frac=1, random_state=42)  # Shuffle

# Save the balanced dataset
balanced_data.to_csv("balanced_combined_dataset.csv", index=False)

# Display dataset summary
print("\nOriginal dataset shape:", combined_data.shape)
print("Original label counts:")
print(combined_data["label"].value_counts())

print("\nBalanced dataset shape:", balanced_data.shape)
print("Balanced label counts:")
print(balanced_data["label"].value_counts())
