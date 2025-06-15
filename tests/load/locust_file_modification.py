from locust import User, task, between, events
from locust.exception import StopUser
from elasticsearch import Elasticsearch
from datetime import datetime, timezone
import threading
import paramiko
import time
from config.config import ELK_URL, ELASTIC_AUTH, SSH_USERNAME, SSH_PASSWORD

TARGET_IP = "192.168.0.15"
LOG_FILE = "/var/log/test_app.log"
RULE_IDS = ["5501"]
LOG_COUNT = 10000

es = Elasticsearch(ELK_URL, basic_auth=ELASTIC_AUTH, verify_certs=False)

test_start_time = None
ssh_client = None
alerts_found = 0
raw_logs_found = 0
total_logs_sent = 0
lock = threading.Lock()


def create_ssh_client():
    for attempt in range(3):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                TARGET_IP,
                port=22,
                username=SSH_USERNAME,
                password=SSH_PASSWORD,
                timeout=10
            )
            return ssh
        except Exception as e:
            print(f"[!] Попытка {attempt + 1}: SSH не удалось — {e}")
            time.sleep(1)
        finally:
            if ssh and not ssh.get_transport():
                ssh.close()
    raise Exception("Не удалось установить SSH после 3 попыток")


def ssh_execute_command(client, command):
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=5)
        exit_status = stdout.channel.recv_exit_status()
        error = stderr.read().decode("utf-8")
        if exit_status != 0 and "password" not in error.lower():
            raise Exception(f"Ошибка выполнения: {error}")
        return stdout.read().decode("utf-8")
    except Exception as e:
        raise Exception(f"Ошибка SSH-команды: {e}")


@events.test_start.add_listener
def on_test_start(**kwargs):
    global test_start_time, ssh_client
    test_start_time = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    print(f"[+] Тест начат: {test_start_time}")

    try:
        ssh_client = create_ssh_client()
        ssh_execute_command(ssh_client, f"echo {SSH_PASSWORD} | sudo -S touch {LOG_FILE}")
        ssh_execute_command(ssh_client, f"echo {SSH_PASSWORD} | sudo -S chmod 644 {LOG_FILE}")
        print(f"[+] Лог-файл {LOG_FILE} создан на агенте")
    except Exception as e:
        print(f"[-] Ошибка подготовки: {e}")


@events.test_stop.add_listener
def on_test_stop(**kwargs):
    global ssh_client, alerts_found, raw_logs_found, total_logs_sent
    end_time = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    print(f"[+] Тест завершён: {end_time}")

    if ssh_client:
        try:
            ssh_execute_command(ssh_client, f"echo {SSH_PASSWORD} | sudo -S rm -f {LOG_FILE}")
            print(f"[+] Лог-файл удалён с агента")
        except Exception as e:
            print(f"[-] Ошибка очистки: {e}")
        finally:
            ssh_client.close()
            ssh_client = None

    print("[*] Ждём 20 секунд для обработки логов...")
    time.sleep(20)

    alert_query = {
        "query": {
            "bool": {
                "must": [
                    {"terms": {"rule.id": RULE_IDS}},
                    {"term": {"agent.ip": TARGET_IP}}
                ],
                "filter": {
                    "range": {"@timestamp": {"gte": test_start_time, "lte": end_time}}
                }
            }
        },
        "size": 10000
    }

    try:
        response = es.search(index="filebeat-*", body=alert_query)
        alerts_found = len(response["hits"]["hits"])
        print(f"[+] Найдено алертов: {alerts_found}")
    except Exception as e:
        print(f"[-] Ошибка запроса алертов: {e}")

    raw_log_query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"agent.ip": TARGET_IP}},
                    {"match_phrase": {"log.file.path": LOG_FILE}}
                ],
                "filter": {
                    "range": {"@timestamp": {"gte": test_start_time, "lte": end_time}}
                }
            }
        },
        "size": 100
    }

    try:
        response = es.search(index="filebeat-*", body=raw_log_query)
        raw_logs_found = len(response["hits"]["hits"])
        print(f"[+] Найдено сырых логов: {raw_logs_found}")
    except Exception as e:
        print(f"[-] Ошибка запроса сырых логов: {e}")

    print("Отчет о нагрузке:")
    print(f"Отправлено логов: {total_logs_sent}")
    print(f"Найдено алертов: {alerts_found} ({(alerts_found / total_logs_sent) * 100:.1f}%)")
    print(f"Найдено сырых логов: {raw_logs_found} ({(raw_logs_found / total_logs_sent) * 100:.1f}%)")


class WazuhLoadTest(User):
    wait_time = between(0.0, 0.001)

    def on_start(self):
        self.sent_logs = 0

    @task
    def send_log_entry(self):
        global ssh_client, total_logs_sent
        if self.sent_logs >= LOG_COUNT:
            raise StopUser()

        try:
            test_id = "load_test"
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            log_message = f"[{test_id}] Flood event {self.sent_logs} at {timestamp}"

            ssh_execute_command(
                ssh_client,
                f"echo {SSH_PASSWORD} | sudo -S sh -c \"echo '{log_message}' >> {LOG_FILE}\""
            )

            with lock:
                total_logs_sent += 1
            self.sent_logs += 1

            self.environment.events.request.fire(
                request_type="SSH",
                name="write_log",
                response_time=0,
                response_length=len(log_message),
                exception=None
            )

        except Exception as e:
            print(f"[-] Ошибка отправки лога {self.sent_logs}: {e}")
            self.environment.events.request.fire(
                request_type="SSH",
                name="write_log",
                response_time=0,
                response_length=0,
                exception=e
            )
