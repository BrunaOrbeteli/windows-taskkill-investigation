import win32evtlog
import datetime
import psutil
import re

# ===== CONFIG =====
HOURS_BACK = 6
EVENT_LOG = "Security"
TASKKILL_NAME = "taskkill.exe"

start_time = datetime.datetime.now() - datetime.timedelta(hours=HOURS_BACK)

server = 'localhost'
logtype = EVENT_LOG

handle = win32evtlog.OpenEventLog(server, logtype)
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

print(f"\n[+] Investigando execuções de taskkill nas últimas {HOURS_BACK} horas...\n")

while True:
    events = win32evtlog.ReadEventLog(handle, flags, 0)
    if not events:
        break

    for event in events:
        # Event ID 4688 = Process Creation
        if event.EventID != 4688:
            continue

        if event.TimeGenerated < start_time:
            continue

        try:
            inserts = event.StringInserts
            if not inserts or len(inserts) < 12:
                continue

            account_name = inserts[1]
            new_process = inserts[5]
            command_line = inserts[8]
            creator_process = inserts[11]
            machine = event.ComputerName
            time = event.TimeGenerated

            if TASKKILL_NAME.lower() in new_process.lower():
                print("=" * 60)
                print(f"🖥️ Máquina: {machine}")
                print(f"👤 Usuário: {account_name}")
                print(f"🕒 Horário: {time}")
                print(f"🧨 Processo criado: {new_process}")
                print(f"📜 Command Line: {command_line}")
                print(f"🧬 Processo pai: {creator_process}")

                # Extração mais robusta do alvo do taskkill
                target = "N/A"

                pid_match = re.search(r"/pid\s+(\d+)", command_line, re.IGNORECASE)
                im_match = re.search(r"/im\s+([^\s]+)", command_line, re.IGNORECASE)

                if pid_match:
                    target = f"PID {pid_match.group(1)}"
                elif im_match:
                    target = f"Imagem {im_match.group(1)}"

                print(f"🎯 Processo alvo: {target}")

        except Exception:
            # Silencioso por ser best-effort hunting
            continue

# ===== CONEXÕES EXTERNAS (best effort) =====
print("\n[+] Verificando conexões externas ativas no momento:\n")

for conn in psutil.net_connections(kind='inet'):
    if conn.raddr and conn.pid:
        ip = conn.raddr.ip
        if not ip.startswith(("10.", "192.168.", "172.")):
            print("🌐 Conexão externa detectada:")
            print(f"   PID local: {conn.pid}")
            print(f"   Destino: {ip}:{conn.raddr.port}")