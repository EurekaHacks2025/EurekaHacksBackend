from flask import Flask, request, Response, jsonify
from flask_cors import CORS
import requests
from ultralytics import YOLOWorld
import cv2
import numpy as np
import sqlite3
from datetime import datetime, timedelta
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

app = Flask(__name__)
CORS(app) # Add cors policy
# Configuration
DATABASE = 'usrdata.db'
SECRET_KEY = os.urandom(16)  # Used for additional encryption layer

# DB Init
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            apikey TEXT PRIMARY KEY,
            encrypted_data TEXT,
            last_updated DATE,
            streak INTEGER DEFAULT 0,
            last_score_update DATE
        )
    ''')
    conn.commit()
    conn.close()

# Encryption/Decryption helpers
def get_cipher(apikey):
    # Derive a consistent key from the API key
    key = hashlib.sha256(apikey.encode()).digest()[:16]
    return AES.new(key, AES.MODE_ECB)

def encrypt_data(apikey, data):
    cipher = get_cipher(apikey)
    padded_data = pad(data.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted).decode()

def decrypt_data(apikey, encrypted_data):
    cipher = get_cipher(apikey)
    encrypted = base64.b64decode(encrypted_data)
    decrypted = cipher.decrypt(encrypted)
    return unpad(decrypted, AES.block_size).decode()

# Database helpers
def get_UserData(apikey):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT encrypted_data, streak FROM users WHERE apikey = ?', (apikey,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        return None, 0
    
    try:
        decrypted = decrypt_data(apikey, result[0])
        return eval(decrypted), result[1]  # Using eval for simplicity, would be changed in prod
    except:
        return None, 0

def UpdateUserData(apikey, data, update_score=False):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT last_updated, streak, last_score_update FROM users WHERE apikey = ?', (apikey,))
    user = cursor.fetchone()
    
    today = datetime.now().date()
    streak = 0
    last_score_update = None
    
    if user:
        last_update = datetime.strptime(user[0], '%Y-%m-%d').date() if isinstance(user[0], str) else user[0]
        streak = user[1]
        last_score_update = datetime.strptime(user[2], '%Y-%m-%d').date() if isinstance(user[2], str) else user[2]
        
        if update_score:
            if last_score_update and (today - last_score_update).days == 1:
                streak += 1
            elif last_score_update and (today - last_score_update).days > 1:
                streak = 1
            elif not last_score_update:
                streak = 1
            last_score_update = today
    
    encrypted_data = encrypt_data(apikey, str(data))
    
    if user:
        cursor.execute('''
            UPDATE users 
            SET encrypted_data = ?, last_updated = ?, streak = ?, last_score_update = ?
            WHERE apikey = ?
        ''', (encrypted_data, today, streak, last_score_update, apikey))
    else:
        cursor.execute('''
            INSERT INTO users (apikey, encrypted_data, last_updated, streak, last_score_update)
            VALUES (?, ?, ?, ?, ?)
        ''', (apikey, encrypted_data, today, streak, last_score_update if update_score else None))
    
    conn.commit()
    conn.close()
    return streak

# Load YOLOWorld model
model = YOLOWorld("yolov8x-worldv2.pt")
model.set_classes(["grass", "hand"])

@app.route('/touchinggrass', methods=['POST'])
def detect():
    # Check API key
    apikey = request.args.get('apikey') or request.form.get('apikey')
    if not apikey:
        return jsonify({'error': 'API key is required'}), 400
    
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    np_img = np.frombuffer(file.read(), np.uint8)
    img = cv2.imdecode(np_img, cv2.IMREAD_COLOR)

    results = model.predict(img, conf=0.25)

    DetectedClasses = results[0].names
    ClassIDs = results[0].boxes.cls.int().tolist()
    ClassNames = [DetectedClasses[i] for i in ClassIDs]

    HasGrass = "grass" in ClassNames
    HasHand = "hand" in ClassNames
    BothPres = HasGrass and HasHand

    if BothPres:
        UserData, streak = get_UserData(apikey)
        if not UserData:
            UserData = {'country': None, 'score': 5}
        else:
            UserData['score'] = UserData.get('score', 0) + 5
        streak = UpdateUserData(apikey, UserData, update_score=True)
        return jsonify({
            'Touching': True,
            'score': UserData['score'],
            'streak': streak
        })
    else:
        UserData, streak = get_UserData(apikey)
        CurrentScore = UserData['score'] if UserData else 0
        return jsonify({
            'Touching': False,
            'score': CurrentScore,
            'streak': streak
        })

@app.route('/country', methods=['GET', 'POST'])
def country():
    apikey = request.args.get('apikey') or request.form.get('apikey')
    if not apikey:
        return jsonify({'error': 'API key is required'}), 400
    
    UserData, _ = get_UserData(apikey)
    
    if request.method == 'POST':
        new_country = request.args.get('country') or request.form.get('country')
        if not new_country:
            return jsonify({'error': 'Country parameter is required'}), 400
        
        if not UserData:
            UserData = {'country': new_country, 'score': 0}
        else:
            UserData['country'] = new_country
        
        streak = UpdateUserData(apikey, UserData)
        return jsonify({'country': new_country, 'streak': streak})
    
    if not UserData:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({'country': UserData.get('country'), 'streak': _})

@app.route('/score', methods=['GET', 'POST', 'PUT'])
def score():
    apikey = request.args.get('apikey') or request.form.get('apikey')
    if not apikey:
        return jsonify({'error': 'API key is required'}), 400
    
    UserData, streak = get_UserData(apikey)
    
    if request.method in ['POST', 'PUT']:
        try:
            score_change = int(request.args.get('score') or request.form.get('score') or 0)
        except ValueError:
            return jsonify({'error': 'Invalid score value'}), 400
        
        if not UserData:
            UserData = {'country': None, 'score': score_change}
        else:
            UserData['score'] = UserData.get('score', 0) + score_change
        
        streak = UpdateUserData(apikey, UserData, update_score=True)
        return jsonify({'score': UserData['score'], 'streak': streak})
    
    if not UserData:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({'score': UserData.get('score', 0), 'streak': streak})

@app.route('/streak', methods=['GET'])
def get_streak():
    apikey = request.args.get('apikey') or request.form.get('apikey')
    if not apikey:
        return jsonify({'error': 'API key is required'}), 400
    
    _, streak = get_UserData(apikey)
    return jsonify({'streak': streak})

@app.route('/user', methods=['POST'])
def create_user():
    apikey = request.args.get('apikey') or request.form.get('apikey')
    if not apikey:
        return jsonify({'error': 'API key is required'}), 400
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT 1 FROM users WHERE apikey = ?', (apikey,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'User already exists'}), 409
    
    initial_data = {'country': None, 'score': 0}
    encrypted_data = encrypt_data(apikey, str(initial_data))
    
    cursor.execute('''
        INSERT INTO users (apikey, encrypted_data, last_updated, streak, last_score_update)
        VALUES (?, ?, ?, ?, ?)
    ''', (apikey, encrypted_data, datetime.now().date(), 0, None))
    
    conn.commit()
    conn.close()
    return jsonify({'message': 'User created successfully', 'apikey': apikey})

if __name__ == '__main__':
    init_db()
    app.run(port=8000, debug=True)