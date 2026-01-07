import logging
from flask import Flask, render_template, request, jsonify
from markupsafe import escape
from analysis import analyze_message

logging.basicConfig(filename="app.log", level=logging.INFO)

app = Flask(__name__)


def sanitize_input(text):
    if len(text) > 10000:  # Character limit
        return None, "Input too long (max 10000 characters)"
    return escape(text), None


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    message = data.get("message", "")
    url = data.get("url", "")

    # Validate and sanitize inputs
    sanitized_message, msg_error = sanitize_input(message)
    if msg_error:
        return jsonify({"error": msg_error}), 400
    sanitized_url, url_error = sanitize_input(url)
    if url_error:
        return jsonify({"error": url_error}), 400

    result = analyze_message(sanitized_message, sanitized_url)

    # Log anonymized analysis data
    logging.info(
        f"Analysis performed: risk={result['risk_level']}, patterns_found={len(result['explanations'])}"
    )

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
