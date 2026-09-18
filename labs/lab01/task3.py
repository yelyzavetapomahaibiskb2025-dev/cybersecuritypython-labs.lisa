import csv
import hashlib
import json
import os
import sys
from datetime import datetime
from functools import wraps

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import STUDENT_NAME, VARIANT_NUMBER  # type: ignore # noqa: E402

DATA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data")
)
CSV_FILE_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_FILE_PATH = os.path.join(DATA_DIR, "log.json")

MIN_PASSWORD_LENGTH = 9
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"  # '00015'


class ValidationError(Exception):
    """Виняток невідповідності пароля мінімальним критеріям."""

    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує шістнадцятковий хеш за алгоритмом SHA-1."""
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль має бути не коротшим за {MIN_PASSWORD_LENGTH} символів."
        )

    payload = (password + salt).encode("utf-8")
    return hashlib.sha1(payload).hexdigest()


def log_event(func):
    """Декоратор логування результатів автентифікації у JSON-файл."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        username = kwargs.get(
            "username", args[0] if len(args) > 0 else "unknown"
        )
        status = "failure"
        try:
            auth_ok = func(*args, **kwargs)
            status = "success" if auth_ok else "failure"
            return auth_ok
        except Exception:
            status = "failure"
            raise
        finally:
            entry = {
                "event": "login",
                "user": username,
                "result": status,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": [str(a) for a in args],
                "kwargs": {k: str(v) for k, v in kwargs.items()},
            }
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                logs = []
                if (
                    os.path.exists(LOG_FILE_PATH)
                    and os.path.getsize(LOG_FILE_PATH) > 0
                ):
                    with open(LOG_FILE_PATH, mode="r", encoding="utf-8") as f:
                        logs = json.load(f)
                logs.append(entry)
                with open(LOG_FILE_PATH, mode="w", encoding="utf-8") as f:
                    json.dump(logs, f, ensure_ascii=False, indent=2)
            except (IOError, PermissionError) as log_err:
                print(f"[Логування] Помилка запису файлу: {log_err}")

    return wrapper


USERS_TO_REGISTER = (
    ("alice_sec", "P@ssword123"),
    ("bob_admin", "AdminVault9#"),
    ("charlie_q", "Quantum_Gate8"),
    ("diana_dev", "DianaSecure#7"),
    ("eve_tester", "AuditTest_10"),
    ("frank_net", "Network#Pass1"),
    ("grace_sim", "Simulate@2026"),
    ("heidi_audit", "AuditSafety!1"),
    ("ivan_crypto", "CryptoGuard#9"),
    ("judy_analyst", "AnalystSafe#7"),
)


def create_user(username: str, password: str) -> tuple:
    """Створює запис користувача з обчисленим хешем."""
    pwd_hash = generate_hash(password, salt=PERSONAL_SALT)
    return (username, pwd_hash)


def create_users(users_list: tuple):
    """Створює каталог data/ та зберігає облікові записи у CSV-файл."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CSV_FILE_PATH, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for user, pwd in users_list:
            writer.writerow(create_user(user, pwd))


def read_users_db() -> list:
    """Зчитує дані користувачів з файлу CSV."""
    if not os.path.exists(CSV_FILE_PATH):
        raise FileNotFoundError(f"Файл {CSV_FILE_PATH} відсутній.")
    db = []
    with open(CSV_FILE_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if row:
                db.append((row[0], row[1]))
    return db


@log_event
def login(username: str, password: str, users_db: list) -> bool:
    """Виконує перевірку облікових даних користувача."""
    if not username or not password:
        raise ValueError("Логін та пароль є обов'язковими полями.")

    target_hash = generate_hash(password, salt=PERSONAL_SALT)
    for u, h in users_db:
        if u == username and h == target_hash:
            return True
    return False


def run_task3():
    """Запуск процедури реєстрації, читання та автентифікації."""
    print("=" * 60)
    print(f"Завдання 3 | {STUDENT_NAME} (Варіант {VARIANT_NUMBER})")
    print(f"Сіль: '{PERSONAL_SALT}' | Алгоритм: SHA-1 | Мін. довжина: {MIN_PASSWORD_LENGTH}")
    print("=" * 60)

    try:
        create_users(USERS_TO_REGISTER)
        print("База users.csv успішно згенерована.")

        users_db = read_users_db()
        print("\nВміст бази даних (CSV):")
        print(f"{'Логін':<16} | {'Хеш SHA-1'}")
        print("-" * 60)
        for u, h in users_db:
            print(f"{u:<16} | {h}")

        print("\nТестування функції автентифікації:")
        test_attempts = [
            ("alice_sec", "P@ssword123"),
            ("bob_admin", "WrongPass999"),
            ("unknown_user", "P@ssword123"),
            ("diana_dev", "short"),
        ]

        for u, p in test_attempts:
            try:
                is_valid = login(u, p, users_db)
                verdict = "ALLOW (Успішний вхід)" if is_valid else "DENY (Невірні дані)"
                print(f"user={u:<16} -> {verdict}")
            except ValidationError as ve:
                print(f"user={u:<16} -> DENY [ValidationError: {ve}]")
            except ValueError as ve:
                print(f"user={u:<16} -> DENY [ValueError: {ve}]")

    except (FileNotFoundError, PermissionError, IOError) as file_err:
        print(f"Помилка файлової системи: {file_err}")
    print()


if __name__ == "__main__":
    run_task3()