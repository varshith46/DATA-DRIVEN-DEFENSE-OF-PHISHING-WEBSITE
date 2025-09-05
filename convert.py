#
# This is the complete and fixed code for your convert.py file.
# Replace the entire content of your file with this code.
#
import re
import csv

def convertion(url, prediction):
    """
    Checks the URL and formats the prediction result into a list that index.html can use.
    It now always returns a list with 5 elements.
    """
    # First, check if the URL is a shortened link using your logic.
    if shortlink(url) == -1:
        # ❌ Case: It's a shortened link, which is suspicious.
        return [url, "Unsafe", "Shortened links are not recommended", False, 0.10]
    
    # Next, check the model's prediction.
    if prediction == 1:
        # ✅ Case: Model predicts the website is Safe.
        return [url, "Safe", "Proceed to Website", True, 0.95]
    
    else:
        # ❌ Case: Model predicts the website is Unsafe (Phishing).
        return [url, "Unsafe", "Do Not Proceed", False, 0.10]

def shortlink(url):
    """
    Your original function to detect shortened URLs. Unchanged.
    """
    match = re.search('bit\\.ly|goo\\.gl|shorte\\.st|go2l\\.ink|x\\.co|ow\\.ly|t\\.co|tinyurl|tr\\.im|is\\.gd|cli\\.gs|'
                      'yfrog\\.com|migre\\.me|ff\\.im|tiny\\.cc|url4\\.eu|twit\\.ac|su\\.pr|twurl\\.nl|snipurl\\.com|'
                      'short\\.to|BudURL\\.com|ping\\.fm|post\\.ly|Just\\.as|bkite\\.com|snipr\\.com|fic\\.kr|loopt\\.us|'
                      'doiop\\.com|short\\.ie|kl\\.am|wp\\.me|rubyurl\\.com|om\\.ly|to\\.ly|bit\\.do|t\\.co|lnkd\\.in|'
                      'db\\.tt|qr\\.ae|adf\\.ly|goo\\.gl|bitly\\.com|cur\\.lv|tinyurl\\.com|ow\\.ly|bit\\.ly|ity\\.im|'
                      'q\\.gs|is\\.gd|po\\.st|bc\\.vc|twitthis\\.com|u\\.to|j\\.mp|buzurl\\.com|cutt\\.us|u\\.bb|yourls\\.org|'
                      'x\\.co|prettylinkpro\\.com|scrnch\\.me|filoops\\.info|vzturl\\.com|qr\\.net|1url\\.com|tweez\\.me|v\\.gd|tr\\.im|link\\.zip\\.net',
                      url)
    if match:
        return -1
    return 1

def find_url_in_csv(csv_file, target_url):
    """
    Your original function to find a URL in a CSV file. Unchanged.
    """
    with open(csv_file, 'r', newline='', encoding='utf-8') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            url = row [0].strip()
            if url == target_url:
                return url
    return None
