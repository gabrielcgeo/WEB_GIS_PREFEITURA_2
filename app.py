import os
import io
import zipfile
import glob
from flask import (Flask, render_template, jsonify, send_from_directory,
                   request, redirect, url_for, flash)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                       login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import geopandas as gpd
import warnings

warnings.filterwarnings('ignore', 'CRS related issues')

# --- CONFIGURAÇÃO INICIAL ---
app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] = 'uma-chave-secreta-forte-e-aleatoria-aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dados')
app.config['UPLOAD_FOLDER'] = DATA_DIR

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça login para acessar esta página."

# --- MODELOS DO BANCO DE DADOS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='admin')  # 'admin' ou 'super_admin'

class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- DECORATORS DE PERMISSÃO ---
def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'super_admin':
            flash("Acesso restrito ao Administrador Geral.")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- CONTEXTO GLOBAL PARA TEMPLATES ---
@app.context_processor
def inject_pages():
    try:
        pages = Page.query.all()
        return dict(pages=pages)
    except Exception:
        return dict(pages=[])

# --- ROTAS DE AUTENTICAÇÃO ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Email ou senha inválidos.')
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- ROTAS PÚBLICAS E APIS ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/page/<string:slug>')
def view_page(slug):
    page = Page.query.filter_by(slug=slug).first_or_404()
    return render_template('view_page.html', page=page)

@app.route('/api/camadas')
def listar_camadas():
    # ... (código existente) ...
    return jsonify([]) # Adapte para sua lógica

# --- ROTAS PROTEGIDAS (ADMINS) ---
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    # ... (código existente) ...
    return redirect(url_for('index'))

@app.route('/download/<string:nome_camada>')
def download_camada():
    # ... (código existente) ...
    return "Arquivo não encontrado.", 404

# --- ROTAS DE ADMIN ---
@app.route('/admin')
@login_required
def admin_dashboard():
    return render_template('admin/dashboard.html')

@app.route('/admin/pages')
@login_required
def admin_pages():
    pages = Page.query.all()
    return render_template('admin/manage_pages.html', pages=pages)

# ... (outras rotas de admin para criar, editar, deletar páginas) ...

# --- ROTAS DE SUPER ADMIN ---
@app.route('/admin/users')
@login_required
@super_admin_required
def admin_users():
    users = User.query.filter(User.role != 'super_admin').all()
    return render_template('admin/manage_users.html', users=users)

# ... (outras rotas de super admin para criar, deletar usuários e editar perfil) ...

# --- SETUP INICIAL ---
with app.app_context():
    os.makedirs(DATA_DIR, exist_ok=True)
    db.create_all()
    if not User.query.filter_by(role='super_admin').first():
        email = 'profgabrielcaldeira@gmail.com'
        password = 'Geografi@'
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        super_admin = User(email=email, password_hash=hashed_password, role='super_admin')
        db.session.add(super_admin)
        db.session.commit()
        print(f"Usuário Super Admin '{email}' criado.")