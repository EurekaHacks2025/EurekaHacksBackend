from flask import Flask, request, jsonify
from ultralytics import YOLOWorld
import cv2
import numpy as np
import sqlite3


app = Flask(__name__)
DBCon = sqlite3.connect("")

# Load YOLOWorld model and set class targets
model = YOLOWorld("yolov8x-worldv2.pt")
model.set_classes(["grass", "hand"])

@app.route('/touchinggrass', methods=['POST'])
def detect():
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

    return jsonify({'Touching': BothPres})

if __name__ == '__main__':
    app.run(debug=True)

