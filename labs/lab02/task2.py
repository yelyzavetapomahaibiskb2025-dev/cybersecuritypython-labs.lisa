import argparse
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path


def setup_logger(log_level: str) -> logging.Logger:
  """Налаштування структурованого логування."""
  numeric_level = getattr(logging, log_level.upper(), logging.INFO)
  logger = logging.getLogger("SudoAuditor")
  logger.setLevel(numeric_level)
  if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
  return logger


def load_alert_commands(alert_path: str | None) -> list[str]:
  """Завантаження списку потенційно небезпечних команд з файлу або дефолтний список."""
  default_alerts = [
      "chmod 777",
      "chmod -R 777",
      "nc",
      "nmap",
      "dd",
      "/etc/shadow",
  ]
  if not alert_path:
    return default_alerts

  path = Path(alert_path)
  if path.exists():
    try:
      with open(path, "r", encoding="utf-8") as f:
        lines = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]
        return lines if lines else default_alerts
    except (OSError, UnicodeError) as e:
      print(f"[WARNING] Помилка читання файлу загроз {alert_path}: {e}")
  return default_alerts


def audit_logs(
    entries: list[dict], alert_keywords: list[str], logger: logging.Logger
) -> dict:
  """2, 3, 4 пункти завдання: аналіз, виявлення root та небезпечних команд, підрахунок Counter."""
  total_commands = len(entries)
  root_executions = 0
  suspicious_executions = []

  user_command_counter = Counter()
  user_high_risk_counter = Counter()

  for entry in entries:
    user = entry["user"]
    target = entry["target_user"]
    cmd = entry["command"]
    tty = entry["tty"]

    user_command_counter[user] += 1

    # Виявлення спроб виконання від імені root
    if target.lower() == "root":
      root_executions += 1

    # Пошук небезпечних команд
    cmd_lower = cmd.lower()
    is_suspicious = any(kw.lower() in cmd_lower for kw in alert_keywords)

    if is_suspicious:
      user_high_risk_counter[user] += 1
      logger.warning(
          f"[ALERT] User '{user}' executed: 'sudo {cmd}' on TTY={tty}"
      )
      suspicious_executions.append({
          "user": user,
          "tty": tty,
          "target_user": target,
          "command": cmd,
          "timestamp": entry["timestamp"],
      })

  report = {
      "total_commands": total_commands,
      "root_executions": root_executions,
      "suspicious_count": len(suspicious_executions),
      "suspicious_executions": suspicious_executions,
      "top_users": user_command_counter.most_common(),
      "high_risk_users": dict(user_high_risk_counter),
  }
  return report


def main():
  parser = argparse.ArgumentParser(
      description="Аудитор логів використання привілейованих команд (Sudo)"
  )
  parser.add_argument(
      "--sudo-log",
      default="labs/lab02/data/data_v15/sudo.log",
      help="Шлях до файлу sudo.log",
  )
  parser.add_argument(
      "--alert-commands",
      default="labs/lab02/data/data_v15/alert_commands.txt",
      help="Шлях до файлу зі списком небезпечних команд",
  )
  parser.add_argument(
      "--outjson",
      default="labs/lab02/data/data_v15/sudo_audit_report.json",
      help="Шлях для збереження JSON звіту",
  )
  parser.add_argument(
      "--log-level",
      default="INFO",
      choices=["DEBUG", "INFO", "WARNING", "ERROR"],
      help="Рівень логування",
  )

  args = parser.parse_args()
  logger = setup_logger(args.log_level)

  logger.info(f"Parsing sudo usage logs from {args.sudo_log}...")
  alert_keywords = load_alert_commands(args.alert_commands)
  entries = parse_sudo_logs(args.sudo_log, logger)
  logger.info(f"Processed {len(entries):,} privileged execution entries.")

  report = audit_logs(entries, alert_keywords, logger)

  # Виведення результатів згідно з прикладом у методичці
  print("\n=== Privileged Execution Summary ===")
  print(f"Total Sudo Commands : {report['total_commands']:,}")
  print(f"Root Executions : {report['root_executions']:,}")

  print("\n=== Suspicious / High-Risk Command Executions ===")
  if report["suspicious_executions"]:
    for susp in report["suspicious_executions"]:
      print(
          f"[ALERT] User '{susp['user']}' executed: 'sudo {susp['command']}'"
          f" on TTY={susp['tty']}"
      )
  else:
    print("Підозрілих команд не виявлено.")

  print("\n=== Top Sudo Users ===")
  for i, (user, count) in enumerate(report["top_users"][:5], 1):
    high_risk = report["high_risk_users"].get(user, 0)
    hr_str = f" (High risk commands: {high_risk})" if high_risk > 0 else ""
    print(f"{i}. {user} : {count} commands{hr_str}")

  # Збереження у JSON-файл
  out_path = Path(args.outjson)
  try:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
      json.dump(report, f, indent=4, ensure_ascii=False)
    logger.info(f"Privileged command audit saved to {out_path}")
  except OSError as e:
    logger.error(f"Помилка збереження JSON: {e}")

def parse_sudo_logs(log_path: str, logger: logging.Logger) -> list[dict]:
    """1. Парсинг рядків логу sudo за допомогою регулярних виразів re."""
    path = Path(log_path)
    if not path.exists():
        logger.error(f"Файл логу не знайдено: {log_path}")
        return []

    # Виправлений регулярний вираз під реальний формат sudo.log
    pattern = re.compile(
        r"^(?P<timestamp>\S+)\s+"
        r"\S+\s+"
        r"sudo:\s+"
        r"(?P<user>[^:]+?)\s*:\s*"
        r"TTY=(?P<tty>\S+)\s*;\s*"
        r"(?P<pwd>[^;]+?)\s*;\s*"
        r"USER=(?P<target>[^;]+?)\s*;\s*"
        r"COMMAND=(?P<command>.*)$"
    )

    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = pattern.match(line)
            if match:
                data = match.groupdict()
                entries.append({
                    "timestamp": data["timestamp"],
                    "user": data["user"].strip(),
                    "tty": data["tty"],
                    "pwd": data["pwd"],
                    "target_user": data["target"].strip(),
                    "command": data["command"],
                })
    return entries

if __name__ == "__main__":
  main()