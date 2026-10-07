import os
import random
import sys
from collections import Counter

# Додавання кореня проєкту до шляхів пошуку модулів
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import STUDENT_NAME, VARIANT_NUMBER  # type: ignore

PASSWORDS = [
    "IoT@S3curity",
    "standard",
    "Blockchain@Pr0tect",
    "typical123",
    "AI@Cybersec",
    "normal",
    "Quantum@Crypt0",
    "general123",
    "Edge@S3curity",
    "common",
]

CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "standard",
    "typical123",
    "normal",
    "general123",
    "common",
    "guest",
}


def evaluate_password(pwd: str, counts: Counter) -> str:
    """Оцінює рівень надійності окремого пароля."""
    min_len = CRITERIA["min_length"]
    if pwd in FORBIDDEN_PASSWORDS or len(pwd) < min_len:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_special = any(not c.isalnum() for c in pwd)

    all_criteria_met = has_digit and has_upper and has_special

    if all_criteria_met:
        if len(pwd) >= min_len + 4 and counts[pwd] == 1:
            return "Дуже сильний"
        return "Сильний"

    active_groups = sum([has_digit, has_upper, has_lower, has_special])
    if active_groups > 1:
        return "Середній"
    if active_groups == 1:
        return "Слабкий"

    return "Заборонений"


def run_task1():
    """Запуск аналізу стійкості паролів."""
    print("=" * 60)
    print(f"Завдання 1 | {STUDENT_NAME} (Варіант {VARIANT_NUMBER})")
    print("=" * 60)

    working_passwords = PASSWORDS.copy()
    duplicate_indices = [
        random.randint(0, len(working_passwords) - 1) for _ in range(3)
    ]
    for idx in duplicate_indices:
        working_passwords.append(working_passwords[idx])

    counts = Counter(working_passwords)

    header = f"{'№':<4} | {'Пароль':<24} | {'Довжина':<8} | {'Оцінка'}"
    print(header)
    print("-" * len(header))
    for i, pwd in enumerate(working_passwords, start=1):
        score = evaluate_password(pwd, counts)
        print(f"{i:<4} | {pwd:<24} | {len(pwd):<8} | {score}")
    print()


if __name__ == "__main__":
    run_task1()
