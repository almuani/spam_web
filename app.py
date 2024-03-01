from flask import Flask, render_template, request
import joblib
import requests
import tldextract
import re
from urllib.parse import urlparse
import ipaddress
import pandas as pd
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)

# Load the XGBoost model from the joblib file


import gdown

# Replace 'YOUR_GOOGLE_DRIVE_FILE_URL' with the shareable link of your file
gdown.download('https://drive.google.com/drive/folders/1REfb8cSmea7qd_KFxOpef0A-STXPdXF2?usp=drive_link',
               output='XGBClassifier_model.joblib', quiet=False)
# Load the XGBoost model from the downloaded file
# model = joblib.load('XGBClassifier_model.joblib')    
# model = joblib.load('../rf_model.joblib')  
model = joblib.load('XGBClassifier_model.joblib')


# Mapping dictionary
#type_mapping = {'benign': 0, 'defacement': 1, 'malware': 2, 'phishing': 3}
# Function to check URL and handle redirects
def check_url(url):
    try:
        response = requests.head(url, allow_redirects=True)
        if response.status_code == 200:
            return "URL is valid."
        elif response.status_code == 304:
            return "URL has not been modified since the last request."
        else:
            return f"URL returned status code: {response.status_code}"
    except Exception as e:
        return f"Error checking URL: {str(e)}"


def abnormal_url(url: str) -> int:
    # Extract hostname from the URL
    hostname = urlparse(url).hostname

    # Convert hostname to a string
    hostname = str(hostname)

    # Search for the hostname in the URL
    match = re.search(hostname, url)

    # Return 1 if a match is found, otherwise return 0
    return 1 if not match else 0

# Function to count digits in the URL
def digit_count(url: str) -> int:
    return sum(1 for i in url if i.isnumeric())

# Function to count letters in the URL
def letter_count(url: str) -> int:
    return sum(1 for i in url if i.isalpha())

def shortening_service(url: str) -> int:
    return int(bool(re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                              r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                              r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                              r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                              r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                              r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                              r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                              r'tr\.im|link\.zip\.net', url)))

def having_ip_address(url: str) -> int:
    # Extract potential IP addresses using a regular expression
    ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', url)

    # Check if any of the extracted matches are valid IP addresses
    for ip_match in ip_matches:
        try:
            ipaddress.ip_address(ip_match)
            return 1
        except ValueError:
            pass
    # If no valid IP addresses found, return 0
    return 0


# Function to preprocess input data
def preprocess_input(url):
    url_status = check_url(url)
    
    try:
        res = tldextract.extract(url)
        protocol = res.scheme if hasattr(res, 'scheme') else ''
        domain = res.domain if hasattr(res, 'domain') else ''

    except Exception as e:
        print(f"Error extracting information from URL '{url}': {str(e)}")
        return pd.DataFrame()  # Return an empty DataFrame if there's an error
    
    # Additional features
    feature_chars = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',']
    data = {}
    for char in feature_chars:
        count = url.count(char)
        data[char] = [count]

    # Include abnormal_url result
    is_abnormal = abnormal_url(url)
    data['abnormal_url'] = [is_abnormal]

    # Include digit and letter counts
    data['digits'] = [digit_count(url)]
    data['letters'] = [letter_count(url)]

    # Include shortening_service feature
    is_shortened = shortening_service(url)
    data['shortening_service'] = [is_shortened]

    # Include having_ip_address feature
    has_ip_address = having_ip_address(url)
    data['has_ip_address'] = [has_ip_address]

    data['url_length'] = [len(url)]
    data['protocol'] = [protocol]
    data['domain'] = [domain]

    # Add a placeholder for the missing feature
    data['url_type'] = ['']

    # Print the data for debugging
    # print("Preprocessed Data:")
    # print(data)
    
    # {'@': [0], '?': [1], '-': [0], '=': [1], '.': [2], '#': [0], '%': [0], '+': [0], '$': [0], '!': [0], '*': [0], ',': [0], 'abnormal_url': [0], 
    # 'digits': [10], 'letters': [80], 'shortening_service': [0], 'has_ip_address': [0], 'url_length': [100], 'protocol': [''], 'domain': ['binance']}

    # Convert the data dictionary to a DataFrame
    data_df = pd.DataFrame(data)

    return data_df


@app.route('/')

def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])

def predict():
    url = request.form['url']
    
    # Preprocess the input
    input_data = preprocess_input(url)

    if isinstance(input_data, int):
        print("Error in preprocess_input:", input_data)
        return render_template('index.html', url=url, prediction="Error in preprocessing")

    # Extract relevant features from the DataFrame

   
    try:
        features = input_data[['abnormal_url', '.', '=', 'letters', 'url_length', 'digits', '?','has_ip_address', '-', '%']].values
    except Exception as e:
        print("Error extracting features:", str(e))
        return render_template('index.html', url=url, prediction="Error extracting features")

    # Make a prediction using the loaded XGBoost model
    prediction = model.predict(features.reshape(1, -1))[0]

    # Map the prediction to the corresponding class
    class_mapping = {0: 'Benign', 1: 'Defacement', 2: 'Malware', 3: 'Phishing'}

    predicted_class = class_mapping[int(prediction)]

    return render_template('index.html', url=url, prediction=predicted_class)

if __name__ == '__main__':
    app.run(debug=True)

#'abnormal_url', '.', '=', 'letters', 'url_length', 'digits', '?', 'has_ip_address', '-', '%'
    
#'abnormal_url', '.', '=', 'letters', 'url_length', 'digits', '?', 'has_ip_address', '-', '%'pk