import sys

from labs.lab02.task1 import Admin, User, UserAccount


def demo():
    print("=== ДЕМОНСТРАЦІЯ РОБОТИ СИСТЕМИ (Завдання 1) ===")

    # 1. Створення користувача та налаштування пароля
    u = User("alex_sec", "alex.sec@company.ua", "Developer")
    u.set_password("SecurePass123!")
    account = UserAccount(u)

    # 2. Перевірка невдалих і успішних спроб входу
    print("\n1. Тестування аутентифікації:")
    account.login("WrongPassword", "192.168.1.50")
    print(f"Статус аутентифікації (невірний пароль): {account.is_authenticated()}")

    account.login("SecurePass123!", "192.168.1.50")
    print(f"Статус аутентифікації (вірний пароль): {account.is_authenticated()}")

    # 3. Зміна email з валідацією
    print("\n2. Тестування валідації email:")
    try:
        account["user"].email = "invalid-email"
    except ValueError as e:
        print(f"Очікувана помилка при валідації email: {e}")
    account["user"].email = "alex.new@company.ua"
    print(f"Успішно змінено email на: {account['user'].email}")

    # 4. Перевірка прав адміністратора (наслідування)
    print("\n3. Тестування прав адміністратора:")
    admin = Admin("root_admin", "admin@corp.ua", permissions=["READ_LOGS"])
    admin.grant_permission("EXECUTE_SUDO")
    print(admin)
    print(f"Має право EXECUTE_SUDO: {admin.has_permission('EXECUTE_SUDO')}")

    # 5. Вихід із системи та аудит
    print("\n4. Журнал подій AuditLog:")
    account.logout()
    account.audit_log.show_all()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo()
    else:
        print("Використовуйте: python -m labs.lab02.main demo")
