import time
import pytest
import requests
from datetime import datetime, timedelta
import paramiko
from requests.auth import HTTPBasicAuth

SERVER_IP = "192.168.0.10"
SSH_USERNAME = "user"
SSH_PASSWORD = "user1234"
ELASTIC_URL = "http://192.168.0.14:9200"
ELASTIC_USER = "elastic"
ELASTIC_PASS = "WLS5gHvR=+zJxq0YUAy9"
AGENT_NAME = "WazuhServer"
INDEX = "*filebeat*"


@pytest.fixture(scope="module")
def ssh_client():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(SERVER_IP, username=SSH_USERNAME, password=SSH_PASSWORD)
    yield client
    client.close()


def test_filebeat_stop_log_loss(ssh_client):
    t0 = datetime.utcnow()
    print(f"[INFO] Начало теста: {t0.isoformat()}Z")

    before_count = get_log_count(AGENT_NAME, t0 - timedelta(minutes=1), t0)
    print(f"[INFO] Логов ДО остановки Filebeat: {before_count}")

    stop_cmd = f"echo {SSH_PASSWORD} | sudo -S systemctl stop filebeat"
    ssh_client.exec_command(stop_cmd)
    print("[INFO] Filebeat остановлен")

    time.sleep(60)

    t1 = datetime.utcnow()
    print(f"[INFO] Время после ожидания: {t1.isoformat()}Z")

    during_stop_count = get_log_count(AGENT_NAME, t0, t1)
    print(f"[INFO] Логов ВО ВРЕМЯ остановки Filebeat: {during_stop_count}")

    start_cmd = f"echo {SSH_PASSWORD} | sudo -S systemctl start filebeat"
    ssh_client.exec_command(start_cmd)
    print("[INFO] Filebeat запущен обратно")

    assert during_stop_count < 5, (
        f"Ожидалось <5 логов во время остановки Filebeat, получено: {during_stop_count}"
    )


def get_log_count(agent_name, start_time, end_time):
    gte = start_time.isoformat() + "Z"
    lte = end_time.isoformat() + "Z"

    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"host.name": agent_name}},
                    {"range": {"@timestamp": {"gte": gte, "lte": lte}}}
                ]
            }
        }
    }

    url = f"{ELASTIC_URL}/{INDEX}/_count"
    response = requests.post(
        url,
        json=query,
        auth=HTTPBasicAuth(ELASTIC_USER, ELASTIC_PASS),
        headers={"Content-Type": "application/json"}
    )

    print(f"[DEBUG] Запрос к Elasticsearch: {query}")
    print(f"[DEBUG] Ответ: {response.status_code} — {response.text}")

    if response.status_code != 200:
        raise Exception(f"Ошибка запроса к Elasticsearch: {response.text}")

    return response.json().get("count", 0)
