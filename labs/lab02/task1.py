import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

# Іменована константа кількості ітерацій для PBKDF2
PBKDF2_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900  # 15 хвилин


class User:
    """Клас, що описує базового користувача системи."""

    def __init__(self, username: str, email: str, role: str, active: bool = True):
        self.username = username
        self._email = ""
        self.email = email  # Використання property для валідації
        self.role = role
        self.active = active
        self.__password_hash: bytes = b""
        self.__password_salt: bytes = b""

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str):
        # Спрощена перевірка формату email за методичкою
        pattern = r"^[a-zA-Z][a-zA-Z0-9_.]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний формат email: {value}")
        self._email = value

    def set_password(self, password: str):
        """Встановлення пароля з використанням PBKDF2 та випадкової солі."""
        if len(password) < 6:
            raise ValueError("Пароль занадто короткий (мінімум 6 символів).")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        """Безпечна перевірка пароля через hmac.compare_digest."""
        if not self.__password_hash or not self.__password_salt:
            return False
        eval_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(self.__password_hash, eval_hash)

    def deactivate(self):
        self.active = False

    def __str__(self) -> str:
        return (
            f"User(username='{self.username}', email='{self.email}',"
            f" role='{self.role}', active={self.active})"
        )


class Admin(User):
    """Клас адміністратора (наслідування від User) із підтримкою прав доступу."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "Admin",
        active: bool = True,
        permissions: list[str] | None = None,
    ):
        super().__init__(username, email, role, active)
        # Уникнення змінюваного аргументу за замовчуванням
        self._permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str):
        self._permissions.add(permission)

    def revoke_permission(self, permission: str):
        self._permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self._permissions

    def __str__(self) -> str:
        perms = ", ".join(sorted(self._permissions))
        return f"Admin(username='{self.username}', permissions=[{perms}])"


class Session:
    """Клас для керування сеансом користувача в UTC."""

    def __init__(self, ip: str):
        self.ip = ip
        now = datetime.now(timezone.utc)
        self.login_time = now
        self.last_activity = now

    def touch(self):
        """Оновлює час останньої активності сеансу."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Timeout має бути позитивним числом.")
        elapsed = (datetime.now(timezone.utc) - self.last_activity).total_seconds()
        return elapsed <= timeout_sec


@dataclass
class AuditRecord:
    """Запис журналу аудиту (реалізовано через @dataclass)."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал подій безпеки."""

    def __init__(self):
        self.records: list[AuditRecord] = []

    def add_log(self, username: str, action: str):
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc), username=username, action=action
        )
        self.records.append(record)

    def show_all(self):
        for r in self.records:
            print(
                f"[{r.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}]"
                f" User: {r.username} -> Action: {r.action}"
            )


class UserAccount:
    """Клас на основі композиції, що об'єднує User, Session та AuditLog."""

    def __init__(self, user: User):
        self.user = user
        self.session: Session | None = None
        self.audit_log = AuditLog()

    def login(self, password: str, ip: str) -> bool:
        if not self.user.active:
            self.audit_log.add_log(self.user.username, "login_failure_inactive")
            return False

        if self.user.check_password(password):
            self.session = Session(ip)
            self.audit_log.add_log(self.user.username, "login_success")
            return True
        else:
            self.audit_log.add_log(self.user.username, "login_failure")
            return False

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        if self.session.is_active(SESSION_TIMEOUT_SEC):
            self.session.touch()  # Подовження сеансу при валідній перевірці
            return True
        else:
            self.session = None  # Закінчився таймаут
            return False

    def logout(self):
        if self.session:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str):
        """Спеціальний метод для доступу до атрибутів через індексатор."""
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit":
            return self.audit_log
        raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key: str, value):
        """Спеціальний метод для зміни дозволених атрибутів."""
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення має бути екземпляром класу User.")
            self.user = value
        else:
            raise KeyError(f"Зміна ключа '{key}' заборонена або не підтримується.")
