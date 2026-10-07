"""Модуль для запуску всіх завдань."""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

from task1 import run_task1
from task2 import run_task2
from task3 import run_task3

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER  # type: ignore


def main() -> None:
    """Головна функція, яка по черзі запускає всі 3 завдання."""
    print("#" * 70)
    print("ЛАБОРАТОРНА РОБОТА №1")
    print(
        f"Студентка: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}"
    )
    print("#" * 70)

    print("\n\n>>> Запуск завдання 1 <<<")
    run_task1()

    print("\n\n>>> Запуск завдання 2 <<<")
    run_task2()

    print("\n\n>>> Запуск завдання 3 <<<")
    run_task3()

    print("\n" + "#" * 70)
    print("Усі завдання успішно виконано")
    print("#" * 70)


if __name__ == "__main__":
    main()
