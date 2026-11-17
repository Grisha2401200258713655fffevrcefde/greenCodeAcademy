"""PostgreSQL integration smoke tests. Runs ONLY against a dedicated academy_ci DB."""
import os
import uuid
from urllib.parse import urlsplit

import pytest

url = os.getenv("TEST_POSTGRES_URL")
if not url:
    pytest.skip("No dedicated PostgreSQL test URL configured", allow_module_level=True)
parsed = urlsplit(url.replace("postgresql+psycopg://", "postgresql://", 1))
if parsed.path != "/academy_ci" or parsed.hostname not in ("localhost", "127.0.0.1", "postgres"):
    raise RuntimeError("Refusing to run PostgreSQL tests outside dedicated academy_ci")

os.environ["DATABASE_URL"] = url

from app import app, db, User, Material, PracticeCompletion, AdminAccount


def test_postgres_schema_and_foreign_keys():
    with app.app_context():
        assert db.engine.dialect.name == "postgresql"
        db.create_all()
        suffix = uuid.uuid4().hex[:12]
        user = User(username=f"pg{suffix}", email=f"pg{suffix}@example.test")
        user.set_password("PasswordForTest2026")
        material = Material(title="PG smoke " + suffix, type="practice",
                            language="python", file_name="smoke.txt", file_data=b"ok")
        db.session.add_all([user, material])
        db.session.commit()
        try:
            db.session.add(PracticeCompletion(user_id=user.id, material_id=material.id))
            db.session.commit()
            db.session.expire_all()
            assert User.query.filter_by(username=f"pg{suffix}").count() == 1
            assert Material.query.filter_by(title="PG smoke " + suffix).count() == 1
            assert PracticeCompletion.query.filter_by(user_id=user.id).count() == 1
        finally:
            PracticeCompletion.query.filter_by(user_id=user.id).delete()
            db.session.delete(material)
            db.session.delete(user)
            db.session.commit()


def test_postgres_admin_hash_login():
    with app.app_context():
        suffix = uuid.uuid4().hex[:12]
        admin = AdminAccount(username=f"admin{suffix}")
        admin.set_password("AnotherTestPassword2026")
        db.session.add(admin)
        db.session.commit()
        admin_id = admin.id
        try:
            db.session.expire_all()
            restored = db.session.get(AdminAccount, admin_id)
            assert restored.check_password("AnotherTestPassword2026")
            assert not restored.check_password("wrong-password")
        finally:
            db.session.delete(db.session.get(AdminAccount, admin_id))
            db.session.commit()
