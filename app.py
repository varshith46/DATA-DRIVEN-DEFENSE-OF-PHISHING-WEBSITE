#importing required libraries

from flask import Flask, request, render_template
import numpy as np
import warnings
import pickle, os
# It's better practice to use a 'with' statement to handle files.
# This ensures the file is closed even if errors occur.
try:
    # Construct a robust path to the model file relative to the script's location
    base_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(base_dir, "newmodel.pkl")
    with open(filepath, "rb") as file:
        gbc = pickle.load(file)
except FileNotFoundError:
    print(f"Error: Model file not found at '{filepath}'. Make sure 'newmodel.pkl' is in the same directory as app.py.")
    gbc = None # Set to None so the app can still start, though prediction will fail.

app = Flask(__name__)

# Import these after Flask app is defined to avoid circular imports if they depend on app context
from convert import convertion
from feature import FeatureExtraction
warnings.filterwarnings('ignore')
@app.route("/")
def home():
    return render_template("index.html")

@app.route('/result', methods=['POST'])
def predict():
    if gbc is None:
        return render_template("index.html", name="Model not loaded. Please check server logs.")

    url = request.form["name"]
    obj = FeatureExtraction(url)
    x = np.array(obj.get_features_list()).reshape(1, 30)
    y_pred = gbc.predict(x)[0]
    # 1 is safe, -1 is unsafe (assuming this from your comment)
    name = convertion(url, int(y_pred))
    return render_template("index.html", name=name)

@app.route('/usecases', methods=['GET'])
def usecases():
    return render_template('usecases.html')

if __name__ == "__main__":
    # Make sure debug is set to True
    app.run(debug=True)