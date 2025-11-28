# parser_extract.py
import csv
import json
from pathlib import Path
import re

OUTPUT_DIR = Path(__file__).parent / "output"
CSV_FILE = OUTPUT_DIR / "events.csv"
EXTRACT_CSV = OUTPUT_DIR / "extracted_accounts.csv"

def parse_row(row):
    # Prefer explicit columns; if message text has the info, use regex fallback
    account = row.get("account_name") or ""
    reason = row.get("failure_reason") or ""

    # Fallback: tentar extrair de message (ex.: "An account failed to log on. Account Name: foo. Failure Reason: bar")
    msg = row.get("message", "")
    m_acc = re.search(r"Account Name[:=]\s*([^\.,;\n]+)", msg, re.I)
    m_fail = re.search(r"Failure Reason[:=]\s*([^\.,;\n]+)", msg, re.I)
    if not account and m_acc:
        account = m_acc.group(1).strip()
    if not reason and m_fail:
        reason = m_fail.group(1).strip()
    return account.strip(), reason.strip()

def main():
    with open(CSV_FILE, newline="", encoding="utf-8") as fh, \
         open(EXTRACT_CSV, "w", newline="", encoding="utf-8") as outfh:
        reader = csv.DictReader(fh)
        writer = csv.writer(outfh)
        writer.writerow(["timestamp","account_name","failure_reason","event_id"])
        for r in reader:
            acc, fail = parse_row(r)
            if acc or fail:
                writer.writerow([r.get("timestamp",""), acc, fail, r.get("id","")])
    print("Arquivo gerado:", EXTRACT_CSV)

if __name__ == "__main__":
    main()
