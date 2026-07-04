import os
import sqlite3
from datetime import datetime
from io import BytesIO
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import cv2
import numpy as np
from flask import Flask, request, jsonify, render_template, send_file
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from ultralytics import YOLO

app = Flask(__name__)

model = YOLO('yolov8x.pt')
os.makedirs('static', exist_ok=True)

def init_db():
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            filename TEXT,
            chair_count INTEGER,
            people_count INTEGER,
            occupancy_percent REAL,
            result_image TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def save_to_db(timestamp, filename, chair_count, people_count, occupancy_percent, result_image):
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    c.execute(
        '''INSERT INTO requests 
           (timestamp, filename, chair_count, people_count, occupancy_percent, result_image) 
           VALUES (?, ?, ?, ?, ?, ?)''',
        (timestamp, filename, chair_count, people_count, occupancy_percent, result_image)
    )
    conn.commit()
    conn.close()
    return c.lastrowid

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_image():
    if 'image' not in request.files:
        return jsonify({'error': 'Файл не передан'}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'Имя файла пустое'}), 400

    img_bytes = file.read()
    np_arr = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    if img is None:
        return jsonify({'error': 'Невозможно декодировать изображение'}), 400

    height, width = img.shape[:2]

    results = model(img, classes=[0, 56], conf=0.15, iou=0.3, imgsz=1920)

    chairs = []
    persons = []

    
    MIN_AREA = 150
    MAX_AREA = width * height * 0.7

    for box in results[0].boxes:
        cls = int(box.cls[0])
        x1, y1, x2, y2 = map(int, box.xyxy[0].tolist())
        area = (x2 - x1) * (y2 - y1)
        if area < MIN_AREA or area > MAX_AREA:
            continue
        if cls == 56:
            chairs.append(box)
        elif cls == 0:
            persons.append(box)

    empty_chairs = len(chairs)
    total_people = len(persons)

    total_seats = empty_chairs + total_people
    if total_seats == 0:
        occupancy_percent = 0
    else:
        occupancy_percent = round((total_people / total_seats) * 100, 1)
        occupancy_percent = min(100, occupancy_percent)

    img_copy = img.copy()
    for box in chairs:
        x1, y1, x2, y2 = map(int, box.xyxy[0].tolist())
        cv2.rectangle(img_copy, (x1, y1), (x2, y2), (0, 255, 0), 2)
        cv2.putText(img_copy, 'chair', (x1, y1 - 5), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)
    for box in persons:
        x1, y1, x2, y2 = map(int, box.xyxy[0].tolist())
        cv2.rectangle(img_copy, (x1, y1), (x2, y2), (255, 0, 0), 2)
        cv2.putText(img_copy, 'person', (x1, y1 - 5), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 0, 0), 2)

    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    result_filename = f'result_{timestamp_str}.png'  
    result_path = os.path.join('static', result_filename)
    cv2.imwrite(result_path, img_copy, [cv2.IMWRITE_PNG_COMPRESSION, 9]) 

    row_id = save_to_db(
        datetime.now().isoformat(),
        file.filename,
        empty_chairs,
        total_people,
        occupancy_percent,
        result_filename
    )

    return jsonify({
        'count': empty_chairs,
        'people': total_people,
        'occupancy': occupancy_percent,
        'result_image': result_filename,
        'id': row_id
    })

@app.route('/history')
def history():
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    rows = c.execute('''
        SELECT timestamp, filename, chair_count, people_count, occupancy_percent, result_image, id 
        FROM requests ORDER BY id DESC
    ''').fetchall()
    conn.close()
    return render_template('history.html', rows=rows)

@app.route('/report/<int:req_id>')
def generate_report(req_id):
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    row = c.execute('''
        SELECT timestamp, filename, chair_count, people_count, occupancy_percent, result_image 
        FROM requests WHERE id = ?
    ''', (req_id,)).fetchone()
    conn.close()

    if not row:
        return 'Запись не найдена', 404

    timestamp, filename, chair_count, people_count, occupancy_percent, result_image = row
    result_path = os.path.join('static', result_image)

    # Попробуем загрузить шрифт из текущей папки (DejaVuSans.ttf)
    font_name = 'Helvetica'  # запасной вариант (без кириллицы)
    try:
        # Если файл лежит в корне проекта
        pdfmetrics.registerFont(TTFont('DejaVuSans', 'DejaVuSans.ttf'))
        font_name = 'DejaVuSans'
    except Exception as e:
        # Если не найден, можно попробовать системный путь (пример для Linux)
        try:
            pdfmetrics.registerFont(TTFont('DejaVuSans', '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'))
            font_name = 'DejaVuSans'
        except:
            # Если ничего не сработало – остаёмся с Helvetica (кириллица не отобразится)
            print('Шрифт с поддержкой кириллицы не найден, используется Helvetica')


    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # Все текстовые строки используют зарегистрированный шрифт
    pdf.setFont(font_name, 16)
    pdf.drawString(72, height - 72, 'Отчёт по анализу зала')
    pdf.setFont(font_name, 12)
    pdf.drawString(72, height - 100, f'Время обработки: {timestamp}')
    pdf.drawString(72, height - 120, f'Исходный файл: {filename}')
    pdf.drawString(72, height - 140, f'Пустых стульев: {chair_count}')
    pdf.drawString(72, height - 160, f'Людей: {people_count}')
    pdf.drawString(72, height - 180, f'Заполненность: {occupancy_percent}%')


    if os.path.exists(result_path):
        try:
            from PIL import Image
            img = Image.open(result_path)
            img_width, img_height = img.size
            max_width = width - 144
            max_height = height - 300
            scale = min(max_width / img_width, max_height / img_height, 1.0)
            draw_width = img_width * scale
            draw_height = img_height * scale
            x_offset = (width - draw_width) / 2
            y_offset = 220

            pdf.drawImage(result_path, x_offset, y_offset, width=draw_width, height=draw_height)
        except Exception as e:
            pdf.setFont(font_name, 10)
            pdf.drawString(72, 220, f'Ошибка вставки изображения: {str(e)}')
    else:
        pdf.setFont(font_name, 10)
        pdf.drawString(72, 220, f'Файл не найден: {result_path}')

    pdf.save()
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'report_{req_id}.pdf',
        mimetype='application/pdf'
    )

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)