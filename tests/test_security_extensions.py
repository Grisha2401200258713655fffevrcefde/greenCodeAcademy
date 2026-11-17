"""Security regression tests: MFA, antivirus, SMTP, backups."""
import io
import os
import sqlite3
import socket
import struct
import threading
from unittest.mock import patch

import pyotp
import pytest
from cryptography.fernet import Fernet
from flask_mail import Message

from app import app, db, AdminAccount, AdminSecondFactor, Material, mail
from security_features import (
    encrypt_totp, decrypt_totp, match_totp_timecode, scan_upload_with_clamd
)
from scripts.backup_sqlite import backup_sqlite
from test_app import csrf, add_admin, admin_login


def test_totp_encrypt_valid_verify_and_replay():
    secret = pyotp.random_base32()
    key = Fernet.generate_key().decode()
    encrypted = encrypt_totp(secret, key)
    assert encrypted != secret.encode()
    assert decrypt_totp(encrypted, key) == secret
    code = pyotp.TOTP(secret).now()
    timestep = match_totp_timecode(secret, code)
    assert isinstance(timestep, int)
    assert match_totp_timecode(secret, code, timestep) is None
    assert match_totp_timecode(secret, 'abcdef') is None


def test_admin_password_then_mfa(client):
    key = Fernet.generate_key().decode()
    secret = pyotp.random_base32()
    previous = app.config.get('MFA_ENCRYPTION_KEY', '')
    app.config['MFA_ENCRYPTION_KEY'] = key
    try:
        with app.app_context():
            add_admin()
            db.session.add(AdminSecondFactor(
                admin_id=1, encrypted_secret=encrypt_totp(secret, key),
                last_timecode=-1))
            db.session.commit()
        start = admin_login(client)
        assert start.status_code == 302
        assert '/admin/verify' in start.headers['Location']
        assert client.get('/admin').status_code == 302
        bad = client.post('/admin/verify', data={
            'csrf_token': csrf(client, '/admin/verify'), 'code': 'bad'
        })
        assert bad.status_code == 401
        code = pyotp.TOTP(secret).now()
        good = client.post('/admin/verify', data={
            'csrf_token': csrf(client, '/admin/verify'), 'code': code
        })
        assert good.status_code == 302
        assert client.get('/admin').status_code == 200
        client.post('/admin/logout', data={'csrf_token': csrf(client, '/admin')})
        assert '/admin/verify' in admin_login(client).headers['Location']
        reused = client.post('/admin/verify', data={
            'csrf_token': csrf(client, '/admin/verify'), 'code': code
        })
        assert reused.status_code == 401
    finally:
        app.config['MFA_ENCRYPTION_KEY'] = previous


def test_clamd_fails_closed_if_unavailable():
    with pytest.raises((OSError, RuntimeError)):
        scan_upload_with_clamd(b'hello', '/tmp/non-existent-clamd-test-socket')


@pytest.mark.parametrize('verdict,expected', [
    (b'stream: OK\0', True),
    (b'stream: Eicar-Test-Signature FOUND\0', False),
    (b'stream: ERROR\0', False),
])
def test_clamd_stream_protocol(tmp_path, verdict, expected):
    path = str(tmp_path / 'clamd.sock')
    ready = threading.Event()
    results = []
    def fake_clamd():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(path)
            server.listen(1)
            ready.set()
            connection, _ = server.accept()
            with connection:
                def exact(n):
                    chunks = bytearray()
                    while len(chunks) < n:
                        part = connection.recv(n - len(chunks))
                        if not part:
                            raise AssertionError('Unexpected EOF')
                        chunks.extend(part)
                    return bytes(chunks)
                assert exact(10) == b'zINSTREAM\0'
                data = bytearray()
                while True:
                    length = struct.unpack('>I', exact(4))[0]
                    if length == 0:
                        break
                    data.extend(exact(length))
                results.append(bytes(data))
                connection.sendall(verdict)
    thread = threading.Thread(target=fake_clamd, daemon=True)
    thread.start()
    assert ready.wait(5)
    clean, response = scan_upload_with_clamd(b'abc' * 30000, path)
    thread.join(5)
    assert clean is expected
    assert results == [b'abc' * 30000]


def test_admin_upload_denied_if_av_unavailable(client):
    with app.app_context():
        add_admin()
    assert admin_login(client).status_code == 302
    old = app.config.get('UPLOAD_ANTIVIRUS_REQUIRED')
    app.config['UPLOAD_ANTIVIRUS_REQUIRED'] = True
    try:
        with patch('app.scan_upload_with_clamd', side_effect=ConnectionRefusedError):
            response = client.post('/admin', data={
                'csrf_token': csrf(client, '/admin'),
                'title': 'Unscanned', 'mat_type': 'theory',
                'language': 'python',
                'file': (io.BytesIO(b'example'), 'example.txt'),
            }, content_type='multipart/form-data')
        assert response.status_code == 302
        with app.app_context():
            assert Material.query.count() == 0
    finally:
        app.config['UPLOAD_ANTIVIRUS_REQUIRED'] = old


def test_admin_upload_accepts_only_clean_scanned_content(client):
    with app.app_context():
        add_admin()
    assert admin_login(client).status_code == 302
    old = app.config.get('UPLOAD_ANTIVIRUS_REQUIRED')
    app.config['UPLOAD_ANTIVIRUS_REQUIRED'] = True
    try:
        with patch('app.scan_upload_with_clamd', return_value=(True, 'stream: OK')) as scanner:
            response = client.post('/admin', data={
                'csrf_token': csrf(client, '/admin'),
                'title': 'Safe', 'mat_type': 'theory',
                'language': 'python',
                'file': (io.BytesIO(b'example'), 'example.txt'),
            }, content_type='multipart/form-data')
            assert scanner.call_count == 1
        assert response.status_code == 302
        with app.app_context():
            assert Material.query.count() == 1
    finally:
        app.config['UPLOAD_ANTIVIRUS_REQUIRED'] = old


def test_smtp_message_is_captured_without_external_delivery(client):
    old = {key: app.config.get(key) for key in [
        'MAIL_SUPPRESS_SEND', 'MAIL_USERNAME', 'MAIL_PASSWORD',
        'MAIL_DEFAULT_SENDER', 'CONTACT_RECIPIENT']}
    app.config.update(MAIL_SUPPRESS_SEND=True, MAIL_USERNAME='noreply@example.test',
                      MAIL_PASSWORD='local-only', MAIL_DEFAULT_SENDER='noreply@example.test',
                      CONTACT_RECIPIENT='support@example.test')
    try:
        with mail.record_messages() as outbox:
            result = client.post('/contact', data={
                'csrf_token': csrf(client, '/contact'),
                'name': 'Student', 'email': 'student@example.test',
                'message': 'A test message',
            })
            assert result.status_code == 302
            assert len(outbox) == 1
            assert outbox[0].recipients == ['support@example.test']
            assert 'A test message' in outbox[0].body
    finally:
        app.config.update(old)


def test_sqlite_backup_can_be_restored(tmp_path):
    source = tmp_path / 'academy.sqlite3'
    with sqlite3.connect(source) as conn:
        conn.execute('CREATE TABLE lessons (id INTEGER PRIMARY KEY, title TEXT)')
        conn.execute("INSERT INTO lessons (title) VALUES ('Python lesson')")
    backup = backup_sqlite(source, tmp_path / 'backups')
    assert backup.exists()
    assert backup.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(backup) as restored:
        data = restored.execute('SELECT id, title FROM lessons').fetchall()
    assert data == [(1, 'Python lesson')]
    with sqlite3.connect(source) as unchanged:
        assert unchanged.execute('SELECT count(*) FROM lessons').fetchone() == (1,)


def test_requiring_mfa_blocks_password_only(client):
    old = app.config.get('REQUIRE_ADMIN_MFA')
    app.config['REQUIRE_ADMIN_MFA'] = True
    try:
        with app.app_context():
            add_admin()
        assert admin_login(client).status_code == 403
        assert client.get('/admin').status_code == 302
    finally:
        app.config['REQUIRE_ADMIN_MFA'] = old
