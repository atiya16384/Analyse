from textblob import TextBlob
import nltk

# Add the correct nltk_data path
# nltk.data.path.append('./nltk_data/tokenizers/punkt/english.pickle')

# Test with a sample sentence
blob = TextBlob("This is a test sentence.")
print(blob.words)

# print(nltk.data.path)  # Check that './nltk_data' appears in this list
