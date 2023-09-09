from datetime import datetime, timedelta
import jwt
import sqlite3
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length
from flask_bcrypt import Bcrypt
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'secret23'
app.config['JWT_SECRET_KEY'] = 'key23'

conn = sqlite3.connect('data.sql', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')
conn.commit()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS uploaded_images (
        id INTEGER PRIMARY KEY,
        image_name TEXT NOT NULL,
        image_data BLOB NOT NULL
    )
''')
conn.commit()

jwt = JWTManager(app)
csrf = CSRFProtect(app)

bcrypt = Bcrypt()
API_REQUESTS_PER_MINITE_DEFINE_HERE = 5
MAX_REQUESTS_PER_MINUTE = API_REQUESTS_PER_MINITE_DEFINE_HERE * 2
REQUEST_TIME_WINDOW = timedelta(minutes=1)
last_request_times = {}

def is_user_allowed(user_id):
    current_time = datetime.now()

    if user_id not in last_request_times:
        last_request_times[user_id] = []

    request_times = last_request_times[user_id]

    request_times = [t for t in request_times if current_time - t <= REQUEST_TIME_WINDOW]

    if len(request_times) < MAX_REQUESTS_PER_MINUTE:
        request_times.append(current_time)
        last_request_times[user_id] = request_times
        return True, 0

    remaining_time = (request_times[0] + REQUEST_TIME_WINDOW) - current_time
    return False, max(0, int(remaining_time.total_seconds()))

@app.before_request
def rate_limit():
    if request.endpoint == 'upload':
        user_id = request.remote_addr
        allowed, remaining_time = is_user_allowed(user_id)

        if allowed:
            return None
        return jsonify({'message': f'Rate limit exceeded. Please try again in {remaining_time} seconds'}), 429
    return None

class RegistrationForm:
    def __init__(self, username, password):
        self.username = username
        self.password = password

class LoginForm:
    def __init__(self, username, password):
        self.username = username
        self.password = password

@app.route('/register', methods=['POST'])
@csrf.exempt
def register():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Invalid request data'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()

    return jsonify({'message': 'Registration successful'}), 201

csrf.init_app(app)

@app.route('/login', methods=['POST'])
@csrf.exempt
def login():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Invalid request data'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    cursor.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
    user_data = cursor.fetchone()

    if user_data and bcrypt.check_password_hash(user_data[2], password):
        access_token = create_access_token(identity=username)
        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({'message': 'Login failed. Check your credentials'}), 401

@app.route('/upload', methods=['POST'])
@csrf.exempt
@jwt_required()
def upload():
    uploaded_file = request.files['file']
    if uploaded_file:
        image_name = uploaded_file.filename
        image_data = uploaded_file.read()

        allowed, remaining_time = is_user_allowed(request.remote_addr)

        if allowed:
            cursor.execute('INSERT INTO uploaded_images (image_name, image_data) VALUES (?, ?)', (image_name, image_data))
            conn.commit()
            return jsonify({'message': f"Image '{image_name}' uploaded successfully"}), 200
        else:
            return jsonify({'message': f'Rate limit exceeded. Please try again in {remaining_time} seconds'}), 429

    return jsonify({'message': 'No file provided'}), 400

@app.route('/last_uploaded_image', methods=['GET'])
@jwt_required()
def get_last_uploaded_image():
    cursor.execute('SELECT image_name FROM uploaded_images ORDER BY id DESC LIMIT 1')
    result = cursor.fetchone()
    if result:
        last_uploaded_image = result[0]
        return jsonify({'last_uploaded_image': last_uploaded_image}), 200
    else:
        return jsonify({'message': 'No uploaded images'}), 404

if __name__ == '__main__':
    app.run(debug=True)
