# generate.py
import csv
import json
import random
import socket
import sys
from datetime import datetime
from pathlib import Path
import time

OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

CSV_FILE = OUTPUT_DIR / "events.csv"
RAW_LOG = OUTPUT_DIR / "raw_events.log"

# Configure seu coletor syslog (opcional)
SYSLOG_HOST = "192.168.1.100"   # substitua pelo IP do seu Wazuh/Graylog ou deixer None para não enviar
SYSLOG_PORT = 514

HOSTNAME = socket.gethostname()

EVENT_TEMPLATES = [
    ("invalid_login", "An account failed to log on.", {"failure_reason": "Bad password", "account_name": "user{n}"}),
    ("successful_login", "An account logged on.", {"account_name": "user{n}"}),
    ("process_exec", "A suspicious process was executed.", {"process": "powershell.exe -nop -w hidden -c ...", "account_name": "svc_{n}"}),
    ("file_creation", "A sensitive file was created.", {"file":"C:\\secret\\data{n}.txt", "account_name":"user{n}"}),
    ("network_conn", "Outbound connection to unusual IP.", {"dest_ip":"10.23.45.{n}", "process":"chrome.exe"}),
    ("account_lockout", "Account locked out.", {"account_name":"user{n}", "failure_reason":"Too many failed attempts"}),
]

def send_syslog(message: str):
    if not SYSLOG_HOST:
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # RFC 5424-like simple message
        sysmsg = f"<14>1 {datetime.utcnow().isoformat()}Z {HOSTNAME} app - - - {message}"
        sock.sendto(sysmsg.encode('utf-8'), (SYSLOG_HOST, SYSLOG_PORT))
    except Exception as e:
        print("Erro enviando syslog:", e)
    finally:
        sock.close()

def random_event(n=0):
    t, msg, extras = random.choice(EVENT_TEMPLATES)
    timestamp = datetime.now().isoformat()
    # format extras with n
    extras_f = {k: (v.format(n=n) if isinstance(v, str) else v) for k, v in extras.items()}
    event = {
        "id": f"{int(time.time()*1000)}{random.randint(0,999)}",
        "timestamp": timestamp,
        "host": HOSTNAME,
        "type": t,
        "message": msg,
    }
    event.update(extras_f)
    return event

def append_csv(event):
    header = ["id","timestamp","host","type","message","account_name","failure_reason","process","file","dest_ip"]
    file_exists = CSV_FILE.exists()
    with open(CSV_FILE, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)
        if not file_exists:
            writer.writeheader()
        writer.writerow({
            "id": event.get("id"),
            "timestamp": event.get("timestamp"),
            "host": event.get("host"),
            "type": event.get("type"),
            "message": event.get("message"),
            "account_name": event.get("account_name",""),
            "failure_reason": event.get("failure_reason",""),
            "process": event.get("process",""),
            "file": event.get("file",""),
            "dest_ip": event.get("dest_ip",""),
        })

def append_raw_log(event):
    with open(RAW_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")

def main(num=5, sleep=0):
    for i in range(num):
        ev = random_event(n=i)
        line = json.dumps(ev, ensure_ascii=False)
        print("Gerando evento:", line)
        append_raw_log(ev)
        append_csv(ev)
        send_syslog(line)
        if sleep:
            time.sleep(sleep)

if __name__ == "__main__":
    # parâmetros: number_of_events sleep_seconds
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    s = float(sys.argv[2]) if len(sys.argv) > 2 else 0
    main(num=n, sleep=s)
