import os
import io
import re
import click
import zipfile
from functools import wraps
from urllib.parse import urlparse
from datetime import datetime
from mimetypes import guess_type
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file, abort
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, func
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


class AdminGrant(db.Model):
    """Admin permissions are assigned only through the server-side CLI."""
    __tablename__ = 'admin_grant'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)


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


@app.cli.command('grant-admin')
@click.argument('username')
def grant_admin(username):
    """Grant site administration to an existing user (run on the server)."""
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user is None:
            raise click.ClickException('User does not exist: ' + username)
        if db.session.get(AdminGrant, user.id) is None:
            db.session.add(AdminGrant(user_id=user.id))
            db.session.commit()
        click.echo('Admin access granted to ' + username)


def is_admin():
    user_id = session.get('user_id')
    return bool(user_id and db.session.get(AdminGrant, user_id))


def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if not is_admin():
            abort(403)
        return func(*args, **kwargs)
    return inner


@app.context_processor
def inject_global_helpers():
    return {'is_admin': is_admin}


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.errorhandler(413)
def file_too_large(error):
    flash('Файл слишком большой. Максимум 15 МБ.', 'warning')
    return redirect(url_for('admin_dashboard'))

# ----------------- ХЕЛПЕРЫ -----------------
USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,30}$')
EMAIL_RE = re.compile(r'^[^@]+@[^@]+\.[^@]+$')
PWD_RE = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$')

def log_open(material_id: int):
    uid = session.get('user_id')
    if not uid:
        return
    try:
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

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        flash('Неверный логин или пароль', 'danger')
        return redirect(url_for('login'))

    session.clear()
    session['user_id'] = user.id
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

    form['username']  = request.form.get('username', '').strip()
    form['email']     = request.form.get('email', '').strip()
    form['full_name'] = request.form.get('full_name', '').strip()
    password          = request.form.get('password', '')
    confirm           = request.form.get('confirm', '')

    if not form['username']:
        errors['username'] = 'Введите логин'
    elif not USERNAME_RE.match(form['username']):
        errors['username'] = 'Логин 3–30 символов, латиница/цифры/_'
    elif User.query.filter_by(username=form['username']).first():
        errors['username'] = 'Такой логин уже занят'

    if not form['email']:
        errors['email'] = 'Введите e-mail'
    elif not EMAIL_RE.match(form['email']):
        errors['email'] = 'Некорректный e-mail'
    elif User.query.filter_by(email=form['email']).first():
        errors['email'] = 'Такой e-mail уже используется'

    if not PWD_RE.match(password):
        errors['password'] = 'Пароль слабый (8+ символов, буквы верх/низ и цифра)'
    if password != confirm:
        errors['confirm'] = 'Пароли не совпадают'

    if errors:
        return render_template('register.html', errors=errors, form=form)

    user = User(username=form['username'], email=form['email'], full_name=form['full_name'] or None)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    flash('Регистрация успешна. Теперь войдите.', 'success')
    return redirect(url_for('login'))

# ----------------- ПРОФИЛЬ -----------------
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    uid = session.get('user_id')
    if not uid:
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

        user.full_name = full_name or None
        user.avatar_url = avatar_url or None
        db.session.commit()
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
                    if 'word/document.xml' not in archive.namelist():
                        abort(400)
            if extension in ('.txt', '.md'):
                try:
                    file_data.decode('utf-8')
                except UnicodeDecodeError:
                    flash('Текстовые файлы должны быть в UTF-8.', 'danger')
                    return redirect(url_for('admin_dashboard'))

            m = Material(title=title, type=mat_type, language=language,
                         file_name=file_name, file_data=file_data)
            db.session.add(m)
            db.session.commit()
            flash('Материал добавлен', 'success')
        except Exception:
            db.session.rollback()
            app.logger.exception('Failed to add a material')
            flash('Не удалось добавить материал.', 'danger')

        return redirect(url_for('admin_dashboard'))

    materials = Material.query.order_by(Material.id.desc()).all()
    return render_template('admin_panel.html', materials=materials)


@app.route('/material/<int:material_id>/delete', methods=['POST'])
@admin_required
def delete_material(material_id):
    m = Material.query.get_or_404(material_id)
    try:
        db.session.delete(m)
        db.session.commit()
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
    search = request.args.get("search", "").strip()
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
    search = request.args.get("search", "").strip()
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
    search = request.args.get("search", "").strip()
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
    search = request.args.get("search", "").strip()
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
    done = bool(session.get('user_id') and PracticeCompletion.query.filter_by(
        user_id=session['user_id'], material_id=m.id).first())
    return render_template('material_detail.html', material=m, done=done)


@app.route('/material/<int:material_id>/complete', methods=['POST'])
def complete_material(material_id):
    uid = session.get('user_id')
    if not uid:
        return redirect(url_for('login'))
    material = Material.query.get_or_404(material_id)
    if material.type != 'practice':
        abort(400)
    existing = PracticeCompletion.query.filter_by(user_id=uid, material_id=material_id).first()
    if existing is None:
        db.session.add(PracticeCompletion(user_id=uid, material_id=material_id))
        db.session.commit()
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

    if mime and (mime.startswith('image/') or mime == 'application/pdf' or mime.startswith('text/')):
        return send_file(io.BytesIO(m.file_data), mimetype=mime, download_name=m.file_name)

    if fname.endswith('.docx'):
        try:
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
    return send_file(io.BytesIO(m.file_data),
                     as_attachment=True,
                     download_name=m.file_name)

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
        name = request.form.get("name")
        email = request.form.get("email")
        message_text = request.form.get("message")

        if not name or not email or not message_text or len(message_text) > 4000:
            flash('Заполните все поля (сообщение до 4000 символов).', 'danger')
            return redirect(url_for('contact'))
        recipient = app.config.get('CONTACT_RECIPIENT') or app.config.get('MAIL_USERNAME')
        if not recipient:
            flash('Форма связи пока не настроена. Попробуйте позже.', 'warning')
            return redirect(url_for('contact'))

        msg = Message(
            subject=f"Сообщение с сайта от {name[:80]}",
            recipients=[recipient],
            body=f"От: {name} <{email}>\n\n{message_text}",
            sender=app.config["MAIL_DEFAULT_SENDER"]
        )

        try:
            mail.send(msg)
            flash("✅ Сообщение успешно отправлено!", "success")
        except Exception:
            app.logger.exception('Contact mail failed')
            flash('Не удалось отправить сообщение. Попробуйте позже.', 'danger')

        return redirect(url_for("contact"))

    return render_template("contact.html")

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
