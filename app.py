from flask import Flask, request, jsonify
import time
from checker_script import check_card  # তোমার মূল স্ক্রিপ্ট ফাইল

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({"message": "Flask CC Checker Running"})

@app.route("/check", methods=["GET"])
def check_single_card():
    card = request.args.get("card")
    if not card:
        return jsonify({"error": "card parameter is required"}), 400
    
    result = check_card(card)
    return jsonify(result)

@app.route("/bulk-check", methods=["POST"])
def check_multiple_cards():
    data = request.get_json()
    if not data or "cards" not in data:
        return jsonify({"error": "cards list is required"}), 400
    
    results = []
    for card in data["cards"]:
        result = check_card(card)
        results.append(result)
        time.sleep(0)  # agar delay chahiye to yaha seconds de do (e.g., time.sleep(2))
    
    return jsonify({"results": results})

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
