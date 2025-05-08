from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from PyPDF2 import PdfReader
import openai
import os
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
import bcrypt

app = Flask(__name__)
app.config.from_object(Config)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
app.secret_key = Config.SECRET_KEY
jwt = JWTManager(app)
openai.api_key = app.config['OPENAI_API_KEY']

# --- MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    points = db.Column(db.Integer, default=0)
    progress = db.Column(db.JSON, default={"iniciante": True, "intermediario": False, "avancado": False})

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

# --- ROTAS ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        if User.query.filter_by(username=data['username']).first():
            return "Usuário já existe"
        user = User(username=data['username'])
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        user = User.query.filter_by(username=data['username']).first()
        if user and user.check_password(data['password']):
            access_token = create_access_token(identity=user.id)
            session['token'] = access_token
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        return "Login inválido"
    return render_template('login.html')

@app.route('/dashboard')
@jwt_required(optional=True)
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    return render_template('dashboard.html', user=user)

@app.route('/upload', methods=['POST'])
@jwt_required(optional=True)
def upload_file():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Não autorizado"}), 401

    if 'file' not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Arquivo vazio"}), 400

    if file and file.filename.endswith('.pdf'):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        reader = PdfReader(filepath)
        text = ""
        for page in reader.pages:
            text += page.extract_text()

        prompt = f"Com base no seguinte conteúdo, gere 5 perguntas objetivas com respostas:\n\n{text[:3000]}"
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}]
        )
        questions = response.choices[0].message.content

        session['current_quiz'] = questions
        return redirect(url_for('quiz'))
    else:
        return jsonify({"error": "Formato inválido. Apenas PDF é aceito."}), 400

@app.route('/quiz')
def quiz():
    questions = session.get('current_quiz')
    if not questions:
        return redirect(url_for('dashboard'))
    return render_template('quiz.html', questions=questions)

@app.route('/check_answer', methods=['POST'])
@jwt_required(optional=True)
def check_answer():
    data = request.json
    correct = data.get("correct")
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if correct:
        user.points += 10
        db.session.commit()
        return jsonify({"msg": "Correto! +10 pontos"})
    else:
        return jsonify({"msg": "Errado. Tente novamente!"})

# --- INICIAR ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)