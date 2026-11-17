import os
import io
import re
import click
import zipfile
import secrets
import hmac
import hashlib
import pathlib
import sqlite3
import tempfile
from datetime import timedelta
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
from urllib.parse import urlparse
from datetime import datetime
from mimetypes import guess_type
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file, abort, current_app
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, func
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from docx import Document
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from config import Config

# ----------------- НАСТРОЙКИ -----------------
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
mail = Mail(app)
csrf = CSRFProtect(app)

# ----------------- МОДЕЛИ -----------------
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(250), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=True)
    avatar_url = db.Column(db.String(250), nullable=True)
    progress_percent = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, raw_password: str):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, raw_password)


class Material(db.Model):
    __tablename__ = 'material'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(512), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=True)
    file_name = db.Column(db.String(255), nullable=True)
    type = db.Column(db.String(20), nullable=False, default='theory')  # theory/practice
    language = db.Column(db.String(50), nullable=False, default='python')
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False)


class MaterialOpen(db.Model):
    __tablename__ = 'material_open'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    material_id = db.Column(db.Integer, db.ForeignKey('material.id', ondelete='CASCADE'), nullable=False)
    opened_at = db.Column(db.DateTime, server_default=func.now(), nullable=False)

    user = db.relationship('User')
    material = db.relationship('Material')


class AdminAccount(db.Model):
    """Dedicated administrator account separate from student registration."""
    __tablename__ = 'admin_account'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    session_version = db.Column(db.String(64), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        self.session_version = secrets.token_hex(32)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class LoginAttempt(db.Model):
    """Database-backed fixed-window throttle for shared deployments."""
    __tablename__ = 'login_attempt'
    signature = db.Column(db.String(64), primary_key=True)
    hits = db.Column(db.Integer, nullable=False, default=0)
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class SecurityAudit(db.Model):
    """Minimal activity log, without credentials or raw IP addresses."""
    __tablename__ = 'security_audit'
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(80), nullable=False)
    subject = db.Column(db.String(120), nullable=True)
    ip_hash = db.Column(db.String(32), nullable=False)
    at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class EmailVerification(db.Model):
    """Existing accounts without a row remain usable after an upgrade."""
    __tablename__ = 'email_verification'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    verified_at = db.Column(db.DateTime, nullable=True)


class StudentSession(db.Model):
    """Allows password changes and resets to invalidate older sessions."""
    __tablename__ = 'student_session'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    version = db.Column(db.String(64), nullable=False)


class PracticeCompletion(db.Model):
    """A learner may mark a practical material as complete once."""
    __tablename__ = 'practice_completion'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    material_id = db.Column(db.Integer, db.ForeignKey('material.id', ondelete='CASCADE'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'material_id', name='uq_practice_completion'),)


with app.app_context():
    db.create_all()


@app.cli.command('set-admin-login')
@click.argument('username')
def set_admin_login(username):
    """Create or reset the independent admin account."""
    if not re.fullmatch(r'[A-Za-z0-9_]{3,30}', username):
        raise click.ClickException('Login must contain 3-30 Latin characters, numbers or underscores.')
    password = click.prompt('Admin password', hide_input=True, confirmation_prompt=True)
    if (len(password) < 12 or len(password) > 128 or
            not re.search('[a-z]', password) or not re.search('[A-Z]', password) or
            not re.search('[0-9]', password)):
        raise click.ClickException('Use 12-128 chars, uppercase, lowercase and numbers.')
    with app.app_context():
        account = db.session.get(AdminAccount, 1)
        if not account:
            account = AdminAccount(id=1, username=username)
            db.session.add(account)
        else:
            account.username = username
        account.set_password(password)
        db.session.commit()
    click.echo('Admin login saved. Older admin sessions are now invalid.')


def is_admin():
    uid = session.get('admin_id')
    version = session.get('admin_session_version')
    if not uid or not isinstance(version, str):
        return False
    account = db.session.get(AdminAccount, uid)
    return bool(account and hmac.compare_digest(account.session_version, version))


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if is_admin():
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()[:50]
        password = request.form.get('password', '')
        if rate_limited('admin', username):
            flash('Слишком много попыток. Попробуйте через 15 минут.', 'danger')
            return render_template('admin_login.html'), 429
        account = AdminAccount.query.filter_by(username=username).first()
        if account and account.check_password(password):
            rate_clear('admin', username)
            session.clear()
            session.permanent = True
            session['csrf_token'] = secrets.token_hex(32)
            session['admin_id'] = account.id
            session['admin_session_version'] = account.session_version
            audit('admin_login', account.username)
            return redirect(url_for('admin_dashboard'))
        rate_fail('admin', username)
        flash('Неверный логин или пароль', 'danger')
        return render_template('admin_login.html'), 401
    return render_template('admin_login.html')



@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    if is_admin():
        audit('admin_logout')
    session.clear()
    flash('Вы вышли из панели администратора', 'info')
    return redirect(url_for('admin_login'))


def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if not is_admin():
            return redirect(url_for('admin_login'))
        return func(*args, **kwargs)
    return inner


@app.context_processor
def inject_global_helpers():
    return {'is_admin': is_admin, 'student_logged_in': student_session_valid}


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if request.path.startswith('/admin'):
        response.headers['Cache-Control'] = 'no-store'
    if app.config.get('SESSION_COOKIE_SECURE'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.errorhandler(413)
def file_too_large(error):
    flash('Файл слишком большой. Максимум 15 МБ.', 'warning')
    return redirect(url_for('admin_dashboard') if is_admin() else url_for('index'))

# ----------------- AUTH, EMAIL & SECURITY HELPERS -----------------
RATE_WINDOW = timedelta(minutes=15)
RATE_LIMIT = 5


def anonymized_key(*parts):
    value = ':'.join(str(part).lower().strip() for part in parts)
    return hmac.new(app.config['SECRET_KEY'].encode('utf-8'),
                    value.encode('utf-8'), hashlib.sha256).hexdigest()


def client_hash():
    # Do not trust client-supplied X-Forwarded-For headers.
    return anonymized_key('ip', request.remote_addr or 'unknown')[:32]


def audit(action, subject=None):
    db.session.add(SecurityAudit(action=action, subject=(subject or '')[:120],
                                 ip_hash=client_hash()))
    db.session.commit()


def rate_keys(scope, identity):
    return (anonymized_key('rate', scope, 'address', request.remote_addr or 'unknown'),
            anonymized_key('rate', scope, 'identity', identity))


def rate_limited(scope, identity):
    cutoff = datetime.utcnow() - RATE_WINDOW
    return any((attempt := db.session.get(LoginAttempt, key)) is not None
               and attempt.started_at >= cutoff and attempt.hits >= RATE_LIMIT
               for key in rate_keys(scope, identity))


def rate_fail(scope, identity):
    now = datetime.utcnow()
    if secrets.randbelow(50) == 0:
        LoginAttempt.query.filter(LoginAttempt.started_at < now - RATE_WINDOW).delete(synchronize_session=False)
    for key in rate_keys(scope, identity):
        attempt = db.session.get(LoginAttempt, key)
        if attempt is None:
            db.session.add(LoginAttempt(signature=key, hits=1, started_at=now))
        elif attempt.started_at < now - RATE_WINDOW:
            attempt.hits = 1
            attempt.started_at = now
        else:
            attempt.hits += 1
    db.session.commit()


def rate_clear(scope, identity):
    # Clear both the account and IP counters on successful authentication.
    for key in rate_keys(scope, identity):
        attempt = db.session.get(LoginAttempt, key)
        if attempt:
            db.session.delete(attempt)
    db.session.commit()


def token_serializer(salt):
    return URLSafeTimedSerializer(app.config['SECRET_KEY'], salt=salt)


def password_fingerprint(user):
    return hashlib.sha256(user.password_hash.encode('utf-8')).hexdigest()[:24]


def issue_user_token(user, purpose):
    return token_serializer(purpose).dumps(
        {'id': user.id, 'fp': password_fingerprint(user)})


def read_user_token(token, purpose, max_age):
    try:
        data = token_serializer(purpose).loads(token, max_age=max_age)
        user = db.session.get(User, data['id'])
        if user and hmac.compare_digest(data['fp'], password_fingerprint(user)):
            return user
    except (BadSignature, SignatureExpired, KeyError, ValueError, TypeError):
        return None
    return None


def smtp_ready():
    return bool(app.config.get('MAIL_USERNAME') and app.config.get('MAIL_PASSWORD')
                and app.config.get('MAIL_DEFAULT_SENDER'))


def send_account_mail(recipient, subject, body):
    if not smtp_ready():
        return False
    try:
        mail.send(Message(subject=subject, recipients=[recipient],
                          body=body, sender=app.config['MAIL_DEFAULT_SENDER']))
        return True
    except Exception:
        app.logger.exception('Could not send account email')
        return False


def student_session_valid():
    uid = session.get('user_id')
    version = session.get('student_session_version')
    if not uid or not version:
        return False
    record = db.session.get(StudentSession, uid)
    return bool(record and hmac.compare_digest(record.version, version))


def new_student_session(user):
    record = db.session.get(StudentSession, user.id)
    if record is None:
        record = StudentSession(user_id=user.id, version=secrets.token_hex(32))
        db.session.add(record)
        db.session.commit()
    session.clear()
    session.permanent = True
    session['csrf_token'] = secrets.token_hex(32)
    session['user_id'] = user.id
    session['student_session_version'] = record.version


def revoke_student_sessions(user):
    record = db.session.get(StudentSession, user.id)
    if record is None:
        record = StudentSession(user_id=user.id, version=secrets.token_hex(32))
        db.session.add(record)
    else:
        record.version = secrets.token_hex(32)


def verification_required(user):
    row = db.session.get(EmailVerification, user.id)
    return bool(row and row.verified_at is None)


def public_link(endpoint, **values):
    base = app.config.get('PUBLIC_BASE_URL', '').rstrip('/')
    if not base:
        app.logger.warning('PUBLIC_BASE_URL is missing; refusing to issue account links')
        return None
    with app.test_request_context(base_url=base + '/'):
        return base + url_for(endpoint, **values)


def send_verification(user):
    link = public_link('verify_email', token=issue_user_token(user, 'verify-email'))
    if not link:
        return False
    return send_account_mail(user.email, 'Green Code Academy: подтвердите почту',
                             'Для подтверждения адреса откройте ссылку (действует 24 часа):\n' + link)


# ----------------- ХЕЛПЕРЫ -----------------
USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,30}$')
EMAIL_RE = re.compile(r'^[^@]+@[^@]+\.[^@]+$')
PWD_RE = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{12,128}$')

def log_open(material_id: int):
    uid = session.get('user_id')
    if not student_session_valid():
        return
    try:
        recently = MaterialOpen.query.filter_by(user_id=uid, material_id=material_id).order_by(MaterialOpen.opened_at.desc()).first()
        if recently and recently.opened_at > datetime.utcnow() - timedelta(minutes=5):
            return
        db.session.add(MaterialOpen(user_id=uid, material_id=material_id))
        db.session.commit()
    except Exception:
        db.session.rollback()

# ----------------- ГЛАВНАЯ -----------------
@app.route('/')
def index():
    return render_template('index.html')

# ----------------- АВТОРИЗАЦИЯ -----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form.get('username', '').strip()[:50]
    password = request.form.get('password', '')
    if rate_limited('student', username):
        flash('Слишком много попыток. Попробуйте через 15 минут.', 'danger')
        return render_template('login.html'), 429

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        rate_fail('student', username)
        flash('Неверный логин или пароль', 'danger')
        return render_template('login.html'), 401

    if verification_required(user):
        flash('Подтвердите адрес электронной почты перед входом.', 'warning')
        return redirect(url_for('resend_verification'))

    rate_clear('student', username)
    new_student_session(user)
    flash('Добро пожаловать 👋', 'success')
    return redirect(url_for('programming_languages'))



@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Вы вышли из аккаунта', 'info')
    return redirect(url_for('index'))

# ----------------- РЕГИСТРАЦИЯ -----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    errors, form = {}, {}
    if request.method == 'GET':
        return render_template('register.html', errors=errors, form=form)

    form['username'] = request.form.get('username', '').strip()
    form['email'] = request.form.get('email', '').strip().lower()
    form['full_name'] = request.form.get('full_name', '').strip()
    password = request.form.get('password', '')
    confirm = request.form.get('confirm', '')

    if rate_limited('register', form['email']):
        flash('Слишком много запросов. Попробуйте позже.', 'warning')
        return redirect(url_for('register'))

    if not USERNAME_RE.fullmatch(form['username']):
        errors['username'] = 'Логин: 3–30 символов, латиница, цифры и _'
    elif User.query.filter_by(username=form['username']).first():
        errors['username'] = 'Такой логин уже занят'

    if len(form['email']) > 120 or not EMAIL_RE.fullmatch(form['email']):
        errors['email'] = 'Введите корректный адрес электронной почты'
    elif User.query.filter_by(email=form['email']).first():
        errors['email'] = 'Этот email уже используется'

    if len(form['full_name']) > 120:
        errors['full_name'] = 'Слишком длинное имя'
    if len(password) > 128 or not PWD_RE.fullmatch(password):
        errors['password'] = 'Пароль: 12–128 символов, большие и маленькие буквы, цифры'
    if password != confirm:
        errors['confirm'] = 'Пароли не совпадают'

    if app.config.get('REQUIRE_EMAIL_VERIFICATION') and not smtp_ready():
        flash('Регистрация временно недоступна: почтовый сервер не настроен.', 'danger')
        return redirect(url_for('register'))

    if errors:
        rate_fail('register', form['email'])
        return render_template('register.html', errors=errors, form=form), 400

    user = User(username=form['username'], email=form['email'],
                full_name=form['full_name'] or None)
    user.set_password(password)
    db.session.add(user)
    try:
        db.session.flush()
        if app.config.get('REQUIRE_EMAIL_VERIFICATION'):
            db.session.add(EmailVerification(user_id=user.id))
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('Логин или почта уже используются.', 'danger')
        return redirect(url_for('register'))

    rate_fail('register', form['email'])
    if app.config.get('REQUIRE_EMAIL_VERIFICATION'):
        if send_verification(user):
            flash('Письмо для подтверждения отправлено. Проверьте почту.', 'success')
        else:
            flash('Письмо не отправлено. Используйте повторную отправку подтверждения.', 'warning')
        return redirect(url_for('login'))

    flash('Регистрация успешна. Теперь войдите.', 'success')
    return redirect(url_for('login'))


@app.route('/verify-email/<token>')
def verify_email(token):
    user = read_user_token(token, 'verify-email', 24 * 3600)
    if not user:
        flash('Ссылка подтверждения недействительна или устарела.', 'danger')
        return redirect(url_for('login'))
    row = db.session.get(EmailVerification, user.id)
    if row and row.verified_at is None:
        row.verified_at = datetime.utcnow()
        db.session.commit()
    flash('Электронная почта подтверждена. Теперь можно войти.', 'success')
    return redirect(url_for('login'))


@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()[:120]
        if rate_limited('verify-resend', email):
            flash('Слишком много запросов. Попробуйте позже.', 'warning')
            return redirect(url_for('resend_verification'))
        rate_fail('verify-resend', email)
        user = User.query.filter_by(email=email).first()
        if user and verification_required(user):
            send_verification(user)
        flash('Если для адреса требуется подтверждение, письмо отправлено.', 'info')
        return redirect(url_for('login'))
    return render_template('resend_verification.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()[:120]
        if rate_limited('password-reset', email):
            flash('Слишком много запросов. Попробуйте через 15 минут.', 'warning')
            return redirect(url_for('forgot_password'))
        rate_fail('password-reset', email)
        user = User.query.filter_by(email=email).first()
        if user:
            token = issue_user_token(user, 'reset-password')
            link = public_link('reset_password', token=token)
            if link:
                send_account_mail(user.email, 'Green Code Academy: сброс пароля',
                                  'Ссылка для смены пароля действует 30 минут:\n' + link)
        flash('Если этот email зарегистрирован, инструкция будет отправлена.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = read_user_token(token, 'reset-password', 30 * 60)
    if not user:
        flash('Ссылка истекла или уже недействительна.', 'danger')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if len(password) > 128 or not PWD_RE.fullmatch(password) or password != confirm:
            flash('Пароль должен быть сложным и совпадать с подтверждением.', 'danger')
            return render_template('reset_password.html', token=token), 400
        user.set_password(password)
        revoke_student_sessions(user)
        db.session.commit()
        session.clear()
        flash('Пароль изменён. Войдите с новым паролем.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)


# ----------------- ПРОФИЛЬ -----------------
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    uid = session.get('user_id')
    if not student_session_valid():
        return redirect(url_for('login'))

    user = db.session.get(User, uid)
    if user is None:
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        avatar_url = request.form.get('avatar_url', '').strip()
        old_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm = request.form.get('confirm', '')

        if len(full_name) > 120 or len(avatar_url) > 250:
            flash('Имя или ссылка на аватар слишком длинные.', 'danger')
            return redirect(url_for('profile'))
        if avatar_url:
            parsed = urlparse(avatar_url)
            if parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password:
                flash('Для аватара разрешены только корректные HTTPS-ссылки.', 'danger')
                return redirect(url_for('profile'))

        if new_password or confirm:
            if not user.check_password(old_password):
                flash('Введите текущий пароль для его изменения.', 'danger')
                return redirect(url_for('profile'))
            if not PWD_RE.match(new_password) or new_password != confirm:
                flash('Новый пароль должен содержать 8+ символов, большие и маленькие буквы и цифру. Пароли должны совпадать.', 'danger')
                return redirect(url_for('profile'))
            user.set_password(new_password)
            revoke_student_sessions(user)

        user.full_name = full_name or None
        user.avatar_url = avatar_url or None
        db.session.commit()
        if new_password or confirm:
            new_student_session(user)
        flash('Настройки профиля сохранены.', 'success')
        return redirect(url_for('profile'))

    materials_count = Material.query.count()
    theory_count = Material.query.filter_by(type='theory').count()
    practice_count = Material.query.filter_by(type='practice').count()
    completed_count = (db.session.query(PracticeCompletion)
                       .join(Material, PracticeCompletion.material_id == Material.id)
                       .filter(PracticeCompletion.user_id == user.id, Material.type == 'practice')
                       .count())
    progress_percent = round(completed_count * 100 / practice_count) if practice_count else 0

    by_lang = (db.session.query(Material.language, func.count(Material.id))
               .group_by(Material.language)
               .order_by(func.count(Material.id).desc()).all())

    recent = (MaterialOpen.query
              .filter_by(user_id=user.id)
              .order_by(MaterialOpen.opened_at.desc()).limit(10).all())

    return render_template('profile.html', user=user, materials_count=materials_count,
                           theory_count=theory_count, practice_count=practice_count,
                           completed_count=completed_count, progress_percent=progress_percent,
                           by_lang=by_lang, recent=recent)


# ----------------- АДМИНКА -----------------
@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        try:
            title    = request.form['title'].strip()
            mat_type = request.form['mat_type'].strip()
            language = request.form['language'].strip()
            file     = request.files['file']

            if not title or not file or file.filename == '':
                flash('Укажите название и выберите файл', 'warning')
                return redirect(url_for('admin_dashboard'))

            if mat_type not in ('theory', 'practice'):
                abort(400)
            if not language or len(language) > 50:
                abort(400)
            extension = os.path.splitext(file.filename.lower())[1]
            allowed = {'.pdf', '.docx', '.txt', '.md', '.png', '.jpg', '.jpeg'}
            if extension not in allowed:
                flash('Разрешены PDF, DOCX, TXT, MD, PNG и JPG.', 'danger')
                return redirect(url_for('admin_dashboard'))

            file_name = secure_filename(file.filename) or ('material' + extension)
            file_data = file.read()
            if not file_data:
                flash('Файл пустой.', 'danger')
                return redirect(url_for('admin_dashboard'))
            if extension == '.pdf' and not file_data.startswith(b'%PDF-'):
                abort(400)
            if extension == '.png' and not file_data.startswith(b'\x89PNG\r\n\x1a\n'):
                abort(400)
            if extension in ('.jpg', '.jpeg') and not file_data.startswith(b'\xff\xd8\xff'):
                abort(400)
            if extension == '.docx':
                if not zipfile.is_zipfile(io.BytesIO(file_data)):
                    abort(400)
                with zipfile.ZipFile(io.BytesIO(file_data)) as archive:
                    infos = archive.infolist()
                    if (len(infos) > 1500 or
                            sum(info.file_size for info in infos) > 25 * 1024 * 1024 or
                            'word/document.xml' not in archive.namelist()):
                        abort(400)
            if extension in ('.txt', '.md'):
                try:
                    file_data.decode('utf-8')
                except UnicodeDecodeError:
                    flash('Текстовые файлы должны быть в UTF-8.', 'danger')
                    return redirect(url_for('admin_dashboard'))

            if len(title) > 512:
                flash('Название не должно быть длиннее 512 символов.', 'danger')
                return redirect(url_for('admin_dashboard'))
            m = Material(title=title, type=mat_type, language=language,
                         file_name=file_name, file_data=file_data)
            db.session.add(m)
            db.session.commit()
            audit('material_upload', str(m.id))
            flash('Материал добавлен', 'success')
        except Exception:
            db.session.rollback()
            app.logger.exception('Failed to add a material')
            flash('Не удалось добавить материал.', 'danger')

        return redirect(url_for('admin_dashboard'))

    materials = Material.query.order_by(Material.id.desc()).limit(200).all()
    return render_template('admin_panel.html', materials=materials)


@app.route('/admin/audit')
@admin_required
def admin_audit():
    events = SecurityAudit.query.order_by(SecurityAudit.id.desc()).limit(100).all()
    return render_template('admin_audit.html', events=events)


@app.route('/material/<int:material_id>/delete', methods=['POST'])
@admin_required
def delete_material(material_id):
    m = Material.query.get_or_404(material_id)
    try:
        MaterialOpen.query.filter_by(material_id=material_id).delete(synchronize_session=False)
        PracticeCompletion.query.filter_by(material_id=material_id).delete(synchronize_session=False)
        db.session.delete(m)
        db.session.commit()
        audit('material_delete', str(material_id))
        flash('Материал удалён', 'success')
    except Exception:
        db.session.rollback()
        app.logger.exception('Failed to delete material')
        flash('Не удалось удалить материал.', 'danger')
    return redirect(url_for('admin_dashboard'))

# ----------------- МАТЕРИАЛЫ (СОРТИРОВКА + ПАГИНАЦИЯ) -----------------
def get_materials_query(sort, filter_type, search, language=None):
    query = Material.query
    if language:
        query = query.filter_by(language=language)
    if filter_type in ("theory", "practice"):
        query = query.filter_by(type=filter_type)
    if search:
        term = f"%{search}%"
        query = query.filter(or_(
            Material.title.ilike(term),
            Material.language.ilike(term),
            Material.type.ilike(term)
        ))
    if sort == "title":
        query = query.order_by(Material.title.asc())
    else:
        query = query.order_by(Material.created_at.desc(), Material.id.desc())
    return query

@app.route('/materials')
def materials():
    sort = request.args.get("sort", "date")
    filter_type = request.args.get("filter")  # theory / practice
    filter_lang = request.args.get("lang")    # python, js, cpp ...
    search = request.args.get("search", "").strip()[:100]
    page = request.args.get("page", 1, type=int)
    per_page = 10

    query = Material.query

    # фильтр по типу
    if filter_type in ("theory", "practice"):
        query = query.filter_by(type=filter_type)

    # фильтр по языку
    if filter_lang:
        query = query.filter(Material.language.ilike(filter_lang))

    # поиск (без учёта регистра)
    if search:
        term = f"%{search}%"
        query = query.filter(or_(
            Material.title.ilike(term),
            Material.language.ilike(term),
            Material.type.ilike(term)
        ))

    # сортировка
    if sort == "title":
        query = query.order_by(Material.title.asc())
    else:
        query = query.order_by(Material.created_at.desc(), Material.id.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    items = pagination.items

    return render_template(
        "materials.html",
        materials=items,
        pagination=pagination,
        language=None,
        sort=sort,
        filter_type=filter_type,
        filter_lang=filter_lang,
        search=search
    )


@app.route('/materials/<language>')
def materials_by_language(language):
    sort = request.args.get("sort", "date")
    filter_type = request.args.get("filter")
    filter_lang = request.args.get("lang")
    search = request.args.get("search", "").strip()[:100]
    page = request.args.get("page", 1, type=int)
    per_page = 10

    query = Material.query.filter_by(language=language)

    if filter_type in ("theory", "practice"):
        query = query.filter_by(type=filter_type)

    if filter_lang:
        query = query.filter(Material.language.ilike(filter_lang))

    if search:
        term = f"%{search}%"
        query = query.filter(or_(
            Material.title.ilike(term),
            Material.language.ilike(term),
            Material.type.ilike(term)
        ))

    if sort == "title":
        query = query.order_by(Material.title.asc())
    else:
        query = query.order_by(Material.created_at.desc(), Material.id.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    items = pagination.items

    return render_template(
        "materials.html",
        materials=items,
        pagination=pagination,
        language=language,
        sort=sort,
        filter_type=filter_type,
        filter_lang=filter_lang,
        search=search
    )


@app.route('/theory')
def theory_list():
    sort = request.args.get("sort", "date")
    filter_type = request.args.get("filter")
    search = request.args.get("search", "").strip()[:100]
    page = request.args.get("page", 1, type=int)
    per_page = 10

    query = Material.query.filter_by(type='theory')

    if search:
        term = f"%{search}%"
        query = query.filter(or_(
            Material.title.ilike(term),
            Material.language.ilike(term),
            Material.type.ilike(term)
        ))

    if sort == "title":
        query = query.order_by(Material.title.asc())
    else:
        query = query.order_by(Material.created_at.desc(), Material.id.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    items = pagination.items

    return render_template(
        "materials.html",
        materials=items,
        pagination=pagination,
        language="theory",
        sort=sort,
        filter_type=filter_type,
        search=search
    )


@app.route('/practice')
def practice_list():
    sort = request.args.get("sort", "date")
    filter_type = request.args.get("filter")
    search = request.args.get("search", "").strip()[:100]
    page = request.args.get("page", 1, type=int)
    per_page = 10

    query = Material.query.filter_by(type='practice')

    if search:
        term = f"%{search}%"
        query = query.filter(or_(
            Material.title.ilike(term),
            Material.language.ilike(term),
            Material.type.ilike(term)
        ))

    if sort == "title":
        query = query.order_by(Material.title.asc())
    else:
        query = query.order_by(Material.created_at.desc(), Material.id.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    items = pagination.items

    return render_template(
        "materials.html",
        materials=items,
        pagination=pagination,
        language="practice",
        sort=sort,
        filter_type=filter_type,
        search=search
    )


# ----------------- МАТЕРИАЛ -----------------
@app.route('/material/<int:material_id>')
def material_detail(material_id):
    m = Material.query.get_or_404(material_id)
    log_open(material_id)
    done = bool(student_session_valid() and PracticeCompletion.query.filter_by(
        user_id=session['user_id'], material_id=m.id).first())
    return render_template('material_detail.html', material=m, done=done)


@app.route('/material/<int:material_id>/complete', methods=['POST'])
def complete_material(material_id):
    uid = session.get('user_id')
    if not student_session_valid():
        return redirect(url_for('login'))
    material = Material.query.get_or_404(material_id)
    if material.type != 'practice':
        abort(400)
    existing = PracticeCompletion.query.filter_by(user_id=uid, material_id=material_id).first()
    if existing is None:
        try:
            db.session.add(PracticeCompletion(user_id=uid, material_id=material_id))
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
        flash('Практика отмечена как выполненная.', 'success')
    else:
        db.session.delete(existing)
        db.session.commit()
        flash('Отметка выполнения снята.', 'info')
    return redirect(url_for('material_detail', material_id=material_id))

@app.route('/material/<int:material_id>/view')
def material_view(material_id):
    m = Material.query.get_or_404(material_id)
    log_open(material_id)

    fname = (m.file_name or '').lower()
    mime, _ = guess_type(fname)

    if fname.endswith(('.txt', '.md')):
        return send_file(io.BytesIO(m.file_data), mimetype='text/plain; charset=utf-8', download_name=m.file_name)
    if mime in ('image/png', 'image/jpeg', 'application/pdf'):
        response = send_file(io.BytesIO(m.file_data), mimetype=mime, download_name=m.file_name)
        response.headers['Content-Security-Policy'] = "sandbox; default-src 'none'"
        return response

    if fname.endswith('.docx'):
        try:
            with zipfile.ZipFile(io.BytesIO(m.file_data)) as archive:
                infos = archive.infolist()
                if len(infos) > 1500 or sum(info.file_size for info in infos) > 25 * 1024 * 1024:
                    raise ValueError('DOCX preview exceeds limits')
            doc = Document(io.BytesIO(m.file_data))
        except Exception:
            flash('Не удалось открыть DOCX. Скачайте исходный файл.', 'warning')
            return redirect(url_for('material_detail', material_id=material_id))
        paragraphs = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
        tables = [[ [cell.text.strip() for cell in row.cells] for row in t.rows] for t in doc.tables]
        return render_template('docx_view.html',
                               material=m,
                               title=m.title,
                               paragraphs=paragraphs,
                               tables=tables)

    flash('Этот тип файла нельзя показать онлайн. Скачайте его.', 'warning')
    return redirect(url_for('material_detail', material_id=material_id))

@app.route('/material/<int:material_id>/download')
def download_material(material_id):
    m = Material.query.get_or_404(material_id)
    log_open(material_id)
    response = send_file(io.BytesIO(m.file_data),
                         as_attachment=True,
                         download_name=m.file_name or 'material.bin')
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# ----------------- ЯЗЫКИ -----------------
@app.route('/programming_languages')
def programming_languages():
    by_lang = (db.session.query(Material.language, func.count(Material.id))
               .group_by(Material.language)
               .order_by(func.count(Material.id).desc())
               .all())
    return render_template('programming_languages.html', by_lang=by_lang)

# ----------------- ОБРАТНАЯ СВЯЗЬ -----------------
@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get('name', '').strip()[:80]
        email = request.form.get('email', '').strip().lower()[:120]
        message_text = request.form.get('message', '').strip()
        if rate_limited('contact', email):
            flash('Слишком много обращений. Попробуйте через 15 минут.', 'warning')
            return redirect(url_for('contact'))

        if not name or not email or not EMAIL_RE.fullmatch(email) or not message_text or len(message_text) > 4000:
            flash('Заполните все поля (сообщение до 4000 символов).', 'danger')
            return redirect(url_for('contact'))
        recipient = app.config.get('CONTACT_RECIPIENT') or app.config.get('MAIL_USERNAME')
        if not recipient:
            flash('Форма связи пока не настроена. Попробуйте позже.', 'warning')
            return redirect(url_for('contact'))

        if not smtp_ready():
            flash('Почтовый сервер не настроен.', 'warning')
            return redirect(url_for('contact'))
        rate_fail('contact', email)
        msg = Message(subject=f'Сообщение с сайта от {name}',
                      recipients=[recipient],
                      body=f'От: {name} <{email}>\n\n{message_text}',
                      sender=app.config['MAIL_DEFAULT_SENDER'])
        try:
            mail.send(msg)
            flash("✅ Сообщение успешно отправлено!", "success")
        except Exception:
            app.logger.exception('Contact mail failed')
            flash('Не удалось отправить сообщение. Попробуйте позже.', 'danger')

        return redirect(url_for("contact"))

    return render_template("contact.html")

@app.cli.command('import-materials')
@click.argument('directory', type=click.Path(exists=True, file_okay=False, path_type=pathlib.Path))
@click.option('--apply', is_flag=True, help='Commit the import; dry-run by default.')
def import_materials(directory, apply):
    """Import loose DOCX, PDF and text lessons without modifying originals."""
    allowed = {'.docx', '.pdf', '.txt', '.md'}
    langs = {'js': 'javascript', 'javascript': 'javascript', 'python': 'python',
             'css': 'css', 'c++': 'cpp', 'cpp': 'cpp', 'java': 'java',
             'go': 'go', 'rust': 'rust', 'node.js': 'node.js'}
    imported = skipped = 0
    with app.app_context():
        for path in sorted(directory.rglob('*')):
            if (not path.is_file() or path.suffix.lower() not in allowed
                    or any(part.startswith('.') for part in path.relative_to(directory).parts)):
                continue
            try:
                size = path.stat().st_size
                if size == 0 or size > app.config['MAX_CONTENT_LENGTH']:
                    skipped += 1
                    continue
                rel = path.relative_to(directory)
                language = langs.get(rel.parts[0].lower(), 'html' if directory.name.lower() == 'veb' else 'other')
                title = ' / '.join(rel.with_suffix('').parts)[:512]
                material_type = 'practice' if any(
                    tag in str(rel).lower() for tag in ('practice', 'практика', 'задания')) else 'theory'
                if Material.query.filter_by(title=title, language=language,
                                            type=material_type).first():
                    skipped += 1
                    continue
                data = path.read_bytes()
                if path.suffix.lower() == '.pdf' and not data.startswith(b'%PDF-'):
                    skipped += 1
                    continue
                if path.suffix.lower() == '.docx':
                    with zipfile.ZipFile(io.BytesIO(data)) as archive:
                        infos = archive.infolist()
                        if (len(infos) > 1500 or
                                sum(info.file_size for info in infos) > 25 * 1024 * 1024 or
                                'word/document.xml' not in archive.namelist()):
                            skipped += 1
                            continue
                if path.suffix.lower() in ('.txt', '.md'):
                    data.decode('utf-8')
            except (OSError, UnicodeError, ValueError, zipfile.BadZipFile):
                skipped += 1
                continue

            imported += 1
            if apply:
                db.session.add(Material(title=title, type=material_type,
                                        language=language, file_name=path.name, file_data=data))
        if apply:
            db.session.commit()
    click.echo(f'{"IMPORTED" if apply else "DRY-RUN"}: {imported}; skipped: {skipped}')


# ----------------- ПОИСК -----------------
@app.route('/search')
def search():
    q = request.args.get('q', '').strip()[:100]
    page = request.args.get('page', 1, type=int)
    if not q:
        return render_template('poisc.html', q=q, materials=[], total=0,
                               pagination=None, message='Введите запрос в поле поиска')

    term = f'%{q}%'
    query = Material.query.filter(or_(
        Material.title.ilike(term),
        Material.file_name.ilike(term),
        Material.language.ilike(term),
        Material.type.ilike(term)
    ))
    pagination = query.order_by(Material.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False)
    return render_template('poisc.html', q=q, materials=pagination.items,
                           total=pagination.total, pagination=pagination,
                           message=None)


# ----------------- ЗАПУСК -----------------
if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG') == '1')
