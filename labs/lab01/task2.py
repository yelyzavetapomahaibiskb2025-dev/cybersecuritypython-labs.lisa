import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import STUDENT_NAME, VARIANT_NUMBER  # type: ignore

USERS = {
    "quantum_researcher": {
        "role": "quantum_security",
        "clearance": 4,
        "department": "Quantum Research",
        "active": True,
    },
    "post_quantum_dev": {
        "role": "pq_cryptographer",
        "clearance": 4,
        "department": "Post-Quantum",
        "active": True,
    },
    "network_security": {
        "role": "network_security",
        "clearance": 3,
        "department": "Network Security",
        "active": True,
    },
    "crypto_intern": {
        "role": "crypto_intern",
        "clearance": 1,
        "department": "Internship",
        "active": True,
    },
    "quantum_sim": {
        "role": "simulator",
        "clearance": 2,
        "department": "Simulation",
        "active": False,
    },
}

RESOURCES = [
    ("quantum_algorithms", 4),
    ("pq_implementations", 4),
    ("network_protocols", 3),
    ("learning_materials", 1),
    ("quantum_keys", 4),
    ("educational_content", 1),
    ("hybrid_systems", 3),
    ("quantum_computers", 4),
    ("crypto_libraries", 2),
    ("tutorials", 1),
]

SECURITY_LEVELS = (
    "Educational",
    "Research",
    "Classified Research",
    "Quantum Secure",
)

BLOCKED_USERS = {"quantum_sim", "quantum_attack", "algorithm_theft"}


def check_access(username: str, resource_level: int) -> str:
    """Перевіряє права доступу користувача до ресурсу."""
    if username not in USERS:
        return "DENY (User not found)"
    if username in BLOCKED_USERS:
        return "DENY (User is blocked)"

    account = USERS[username]
    if not account.get("active", False):
        return "DENY (Account inactive)"
    if account["clearance"] >= resource_level:
        return "ALLOW"
    return "DENY (Insufficient clearance)"


def run_task2():
    """Запуск системи контролю доступу."""
    print("=" * 60)
    print(f"Завдання 2 | {STUDENT_NAME} (Варіант {VARIANT_NUMBER})")
    print("=" * 60)

    print("Список усіх ресурсів системи:")
    for res_name, lvl in RESOURCES:
        text_level = SECURITY_LEVELS[lvl - 1]
        print(f"  • {res_name:<22}: {text_level} (Рівень {lvl})")

    print("\nРезультати перевірки доступу:")
    users_to_test = list(USERS.keys()) + ["quantum_attack", "external_intruder"]
    for u in users_to_test:
        for res_name, res_lvl in RESOURCES:
            decision = check_access(u, res_lvl)
            print(f"user={u:<20} resource={res_name:<20} -> {decision}")
    print()


if __name__ == "__main__":
    run_task2()
