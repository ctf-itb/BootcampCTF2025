from flask import Flask, render_template, request, jsonify
import random
from db import init_db, get_random_message, cleanup_databases

app = Flask(__name__)

def calculate_sq_score(scenario_response):
    score_mapping = {
        'interrupt': 25,
        'wait_silent': 45,
        'acknowledge': 70,
        'engage_later': 85,
        'facilitate': 95 
    }
    
    base_score = score_mapping.get(scenario_response, 50)
    variation = random.randint(-5, 5)
    final_score = max(0, min(100, base_score + variation))
    
    if final_score >= 80:
        category = "high"
    elif final_score >= 60:
        category = "medium"
    else:
        category = "low"
    
    return final_score, category

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/test', methods=['POST'])
def test():
    data = request.get_json()
    name = data.get('name', '')
    scenario_response = data.get('scenario', '')
    
    score, category = calculate_sq_score(scenario_response)
    message = get_random_message(scenario_response)
    
    return jsonify({
        'score': score,
        'message': message,
        'name': name,
        'category': category
    })

if __name__ == '__main__':
    cleanup_databases()
    init_db()
    app.run(debug=False, host='0.0.0.0', port=6970)
