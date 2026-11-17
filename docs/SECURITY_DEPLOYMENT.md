# Green Code Academy — безопасное развёртывание

Изменения выполняйте сначала на staging-копии. Не публикуйте реальные секреты, пароли, ключи TOTP и дампы БД.

## 1. Резервная копия и восстановление

Для PostgreSQL задайте PGHOST, PGPORT, PGUSER, PGDATABASE и PGPASSWORD либо настройте защищённый .pgpass. Пароль не должен оказаться в аргументах команды.

    umask 077
    python scripts/backup_postgres.py /var/backups/greencodeacademy

Скрипт вызывает pg_dump в custom-формате, проверяет архив через pg_restore --list и сохраняет файл с правами 0600. На staging создайте ОТДЕЛЬНУЮ пустую базу для восстановления:

    createdb academy_restore_test
    pg_restore --no-owner --no-privileges --exit-on-error --dbname=academy_restore_test /var/backups/greencodeacademy/NAME.dump
    psql -d academy_restore_test -c 'SELECT count(*) FROM "user";'
    psql -d academy_restore_test -c 'SELECT count(*) FROM material;'

Не используйте --clean на рабочей базе. Для SQLite: python scripts/backup_sqlite.py instance/academy.db /secure/backups.

## 2. Production ENV

Создайте /etc/greencodeacademy.env с правами 0600. Сгенерируйте секреты на сервере:

    python -c "import secrets; print(secrets.token_urlsafe(48))"
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Обязательные параметры: APP_ENV=production, SECRET_KEY, MFA_ENCRYPTION_KEY, PUBLIC_BASE_URL=https://YOUR_DOMAIN, DATABASE_URL, SESSION_COOKIE_SECURE=true, REQUIRE_ADMIN_MFA=true, UPLOAD_ANTIVIRUS_REQUIRED=true, CLAMAV_SOCKET=/run/clamav/clamd.ctl, MAIL_* и CONTACT_RECIPIENT. Для новых студентов рекомендуется REQUIRE_EMAIL_VERIFICATION=true.

Смените пароль PostgreSQL, ранее опубликованный в старом config.py, если он применялся. Не меняйте SECRET_KEY без плана: старые сессии и ссылки сброса перестанут работать.

## 3. ClamAV

Установите clamav и clamav-daemon, обновите сигнатуры, проверьте доступ сервисного пользователя к UNIX-сокету. Не открывайте clamd в интернет. В режиме production при отсутствии сканера или обнаружении угрозы загрузка и импорт документов отклоняются. Сканирование не гарантирует отсутствие вредоносного содержимого, поэтому обрабатывайте документы в изоляции.

## 4. Администратор, TOTP

    flask --app app set-admin-login YOUR_ADMIN_USERNAME
    flask --app app setup-admin-mfa

Пароль администратора вводится скрытно. Настройка TOTP выводит секрет для приложения-аутентификатора, проверяет шестизначный код и аннулирует прежние административные сессии. Не публикуйте секрет. В production вход только по паролю запрещён; сохраните резервный способ доступа к защищённой консоли и ключу MFA_ENCRYPTION_KEY.

## 5. HTTPS

В каталоге deploy находятся Caddyfile.example и academy.service.example. Замените YOUR_DOMAIN и пути, создайте отдельного системного пользователя, оставьте Gunicorn только на 127.0.0.1:8000. Разрешите интернет-доступ к 80/443 только на reverse proxy. Проверьте публичный TLS и DNS фактически; наличие HSTS не подтверждает правильность сертификата.

## 6. SMTP

Укажите реальные MAIL_SERVER, MAIL_PORT, MAIL_USE_SSL/MAIL_USE_TLS, MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER, CONTACT_RECIPIENT. Отправьте тестовое письмо на собственный адрес:

    flask --app app send-test-email your-mail@example.com

CI проверяет составление email без реальной сетевой доставки. Настоящую доставку нужно подтвердить на сервере.

## 7. Контроль перед публикацией

    flask --app app production-check
    python -m pytest -q

Команда production-check проверяет БД, конфигурацию HTTPS/cookie, учётную запись администратора, MFA, подключение ClamAV и настройки SMTP. Она не меняет пользователей и не отправляет письма. После её прохождения проверьте браузером вход, загрузку, скачивание и восстановление настоящей базы на staging.

CI тестирует SQLite и отдельный PostgreSQL academy_ci, но не реальный production. Для будущих изменений существующих таблиц потребуются версионные миграции Alembic/Flask-Migrate. Без проверки реальных домена, почты, сертификатов, антивируса и восстановления production нельзя считать полностью проверенным.

Изменения GitHub не делают репозиторий приватным; видимость отдельно меняет владелец.
