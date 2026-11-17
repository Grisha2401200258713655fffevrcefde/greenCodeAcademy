import io
import os
import re
import pytest

# Configure a disposable SQLite database before importing app.py.
os.environ.setdefault('SECRET_KEY', 'unit-test-secret-key-unique-and-long-enough-123456789')
os.environ.setdefault('DATABASE_URL', 'sqlite:///:memory:')
os.environ.setdefault('PUBLIC_BASE_URL', 'http://localhost:5000')
os.environ.setdefault('SESSION_COOKIE_SECURE', 'false')
os.environ.setdefault('REQUIRE_EMAIL_VERIFICATION', 'false')

from app import (
    app, db, User, Material, MaterialOpen, PracticeCompletion,
    AdminAccount, EmailVerification, LoginAttempt, AdminAccount,
    issue_user_token, student_session_valid,
)


@pytest.fixture(autouse=True)
def isolated_db():
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=True,
                      REQUIRE_EMAIL_VERIFICATION=False,
                      PUBLIC_BASE_URL='http://localhost:5000')
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()
    yield
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client():
    return app.test_client()


def csrf(client, page='/login'):
    response = client.get(page)
    assert response.status_code == 200, (page, response.status_code)
    match = re.search(rb'name="csrf_token"\s+value="([^"]+)"', response.data)
    assert match, f'Missing CSRF token for {page}'
    signed = match.group(1).decode()
    from itsdangerous import URLSafeTimedSerializer
    decoded = URLSafeTimedSerializer(app.secret_key, salt='wtf-csrf-token').loads(signed)
    with client.session_transaction() as sess:
        raw = sess.get('csrf_token')
    assert decoded == raw, f'GET {page}: HTML token and cookie session diverged: {decoded[:8]} vs {str(raw)[:8]}'
    return signed


def add_user(name='student'):
    user = User(username=name, email=f'{name}@example.test')
    user.set_password('TestStrongPassword123')
    db.session.add(user)
    db.session.commit()
    return user


def add_admin():
    admin = AdminAccount(id=1, username='siteadmin')
    admin.set_password('AdminStrongPassword123')
    db.session.add(admin)
    db.session.commit()
    return admin


def student_login(client, name='student'):
    return client.post('/login', data={
        'csrf_token': csrf(client),
        'username': name, 'password': 'TestStrongPassword123'
    }, follow_redirects=False)


def admin_login(client):
    return client.post('/admin/login', data={
        'csrf_token': csrf(client, '/admin/login'),
        'username': 'siteadmin', 'password': 'AdminStrongPassword123'
    }, follow_redirects=False)


def test_pages_render_without_500(client):
    for path in ['/', '/login', '/register', '/admin/login', '/materials',
                 '/theory', '/practice', '/programming_languages', '/contact',
                 '/forgot-password', '/resend-verification', '/search']:
        assert client.get(path).status_code == 200, path


def test_admin_access_isolated(client):
    assert client.get('/admin').status_code == 302
    assert '/admin/login' in client.get('/admin').headers['Location']
    with app.app_context():
        add_user()
    student_login(client)
    assert client.get('/admin').status_code == 302
    with app.app_context():
        add_admin()
    admin_response = admin_login(client)
    assert admin_response.status_code == 302, admin_response.data.decode()[:1000]
    assert client.get('/admin').status_code == 200
    assert client.get('/admin').headers['Cache-Control'] == 'no-store'


def test_admin_bad_password_and_throttle(client):
    with app.app_context():
        add_admin()
    for _ in range(5):
        response = client.post('/admin/login', data={
            'csrf_token': csrf(client, '/admin/login'),
            'username': 'siteadmin', 'password': 'wrong'
        })
        assert response.status_code == 401
    response = client.post('/admin/login', data={
        'csrf_token': csrf(client, '/admin/login'),
        'username': 'siteadmin', 'password': 'AdminStrongPassword123'
    })
    assert response.status_code == 429


def test_admin_logout_and_old_sessions_revoked(client):
    with app.app_context():
        admin = add_admin()
    assert admin_login(client).status_code == 302
    with app.app_context():
        admin = db.session.get(AdminAccount, 1)
        admin.set_password('AnotherVeryStrongPassword123')
        db.session.commit()
    assert client.get('/admin').status_code == 302


def test_csrf_missing_is_rejected(client):
    assert client.post('/admin/login', data={
        'username': 'siteadmin', 'password': 'x'
    }).status_code == 400
    assert client.post('/register', data={'username': 'student'}).status_code == 400


def test_admin_can_upload_and_delete_with_associated_records(client):
    with app.app_context():
        add_admin()
        add_user()
    assert admin_login(client).status_code == 302
    token = csrf(client, '/admin')
    response = client.post('/admin', data={
        'csrf_token': token, 'title': 'Training test',
        'mat_type': 'practice', 'language': 'python',
        'file': (io.BytesIO(b'Hello world'), 'training.txt')
    }, content_type='multipart/form-data')
    assert response.status_code == 302
    with app.app_context():
        material = Material.query.filter_by(title='Training test').one()
        mid = material.id
        user = User.query.filter_by(username='student').one()
        db.session.add(MaterialOpen(user_id=user.id, material_id=mid))
        db.session.add(PracticeCompletion(user_id=user.id, material_id=mid))
        db.session.commit()
    assert client.get(f'/material/{mid}/view').data == b'Hello world'
    response = client.post(f'/material/{mid}/delete', data={
        'csrf_token': csrf(client, '/admin')
    })
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Material, mid) is None
        assert MaterialOpen.query.filter_by(material_id=mid).count() == 0
        assert PracticeCompletion.query.filter_by(material_id=mid).count() == 0


def test_upload_rejects_executable_and_fake_pdf(client):
    with app.app_context():
        add_admin()
    admin_login(client)
    for filename, data in [('evil.html', b'<script>x</script>'),
                           ('bad.pdf', b'not a pdf')]:
        token = csrf(client, '/admin')
        response = client.post('/admin', data={
            'csrf_token': token, 'title': 'Nope',
            'mat_type': 'theory', 'language': 'python',
            'file': (io.BytesIO(data), filename)
        }, content_type='multipart/form-data')
        assert response.status_code in (302, 400)
    with app.app_context():
        assert Material.query.count() == 0


def test_student_registration_login_progress_and_logout(client):
    response = client.post('/register', data={
        'csrf_token': csrf(client, '/register'), 'username': 'newstudent',
        'email': 'newstudent@example.test', 'password': 'TestStrongPassword123',
        'confirm': 'TestStrongPassword123'
    })
    assert response.status_code == 302
    assert student_login(client, 'newstudent').status_code == 302
    with app.app_context():
        m = Material(title='Python practice', language='python',
                     type='practice', file_name='practice.txt', file_data=b'hi')
        db.session.add(m)
        db.session.commit()
        mid = m.id
    assert client.get('/profile').status_code == 200
    token = csrf(client, f'/material/{mid}')
    assert client.post(f'/material/{mid}/complete',
                       data={'csrf_token': token}).status_code == 302
    assert b'100%' in client.get('/profile').data
    assert client.post(f'/material/{mid}/complete',
                       data={'csrf_token': csrf(client, f'/material/{mid}')}).status_code == 302
    assert b'0%' in client.get('/profile').data
    assert client.post('/logout', data={'csrf_token': csrf(client, '/profile')}).status_code == 302
    assert '/login' in client.get('/profile').headers['Location']


def test_profile_password_change_revokes_other_session(client):
    other = app.test_client()
    with app.app_context():
        add_user()
    student_login(client)
    student_login(other)
    response = client.post('/profile', data={
        'csrf_token': csrf(client, '/profile'),
        'full_name': 'Learner',
        'new_password': 'OtherStrongPassword123',
        'confirm': 'OtherStrongPassword123',
        'current_password': 'TestStrongPassword123'
    })
    assert response.status_code == 302
    assert client.get('/profile').status_code == 200
    assert other.get('/profile').status_code == 302


def test_password_reset_token_is_single_use(client):
    with app.app_context():
        user = add_user()
        token = issue_user_token(user, 'reset-password')
    assert client.get('/reset-password/' + token).status_code == 200
    response = client.post('/reset-password/' + token, data={
        'csrf_token': csrf(client, '/reset-password/' + token),
        'password': 'NewStrongPassword123',
        'confirm': 'NewStrongPassword123'
    })
    assert response.status_code == 302
    assert client.get('/reset-password/' + token).status_code == 302


def test_pending_email_requires_verification(client):
    with app.app_context():
        user = add_user()
        db.session.add(EmailVerification(user_id=user.id))
        db.session.commit()
        token = issue_user_token(user, 'verify-email')
    response = student_login(client)
    assert response.status_code == 302
    assert '/resend-verification' in response.headers['Location']
    assert client.get('/verify-email/' + token).status_code == 302
    assert student_login(client).status_code == 302
    assert client.get('/profile').status_code == 200


def test_search_xss_escaped_and_no_results(client):
    with app.app_context():
        db.session.add(Material(title='<script>alert(1)</script>',
                                file_name='test.txt', file_data=b'x',
                                type='theory', language='python'))
        db.session.commit()
    response = client.get('/search?q=alert')
    assert response.status_code == 200
    assert b'&lt;script&gt;' in response.data
    assert b'<script>' not in response.data
    assert client.get('/search').status_code == 200


def test_material_view_never_executes_html(client):
    with app.app_context():
        m = Material(title='unsafe', file_name='payload.html',
                     file_data=b'<script>alert(1)</script>',
                     type='theory', language='python')
        db.session.add(m)
        db.session.commit()
        mid = m.id
    response = client.get(f'/material/{mid}/view')
    assert response.status_code == 302


def test_contact_without_smtp_handles_failure(client):
    response = client.post('/contact', data={
        'csrf_token': csrf(client, '/contact'),
        'name': 'Test', 'email': 'student@example.test', 'message': 'Hello'
    })
    assert response.status_code == 302


def test_all_templates_compile():
    with app.app_context():
        for name in app.jinja_env.list_templates():
            app.jinja_env.get_template(name)


def test_register_rejects_weak_password(client):
    r = client.post('/register', data={
        'csrf_token': csrf(client, '/register'),
        'username': 'student', 'email': 'student@example.test',
        'password': 'short', 'confirm': 'short'
    })
    assert r.status_code == 400
    with app.app_context():
        assert User.query.count() == 0
