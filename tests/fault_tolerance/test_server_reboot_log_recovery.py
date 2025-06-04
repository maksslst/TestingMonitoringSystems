import time
import pytest
import requests
import paramiko
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth

AGENT_IP = "192.168.0.15"
MANAGER_IP = "192.168.0.10"
SSH_USERNAME = "user"
SSH_PASSWORD = "user1234"
ELASTIC_URL = "http://192.168.0.14:9200"
ELASTIC_USER = "elastic"
ELASTIC_PASS = "WLS5gHvR=+zJxq0YUAy9"
AGENT_NAME = "WazuhAgent"
INDEX = "*filebeat*"


def wait_for_service_active(ssh_client, service_name, timeout=180, interval=5):
    end_time = time.time() + timeout
    while time.time() < end_time:
        stdin, stdout, stderr = ssh_client.exec_command(f"systemctl is-active {service_name}")
        status = stdout.read().decode().strip()
        if status == "active":
            print(f"[INFO] {service_name} активен")
            return
        time.sleep(interval)
    raise TimeoutError(f"{service_name} не активен")


def get_log_count_by_agent(agent_name, start_time, end_time):
    gte = start_time.isoformat() + "Z"
    lte = end_time.isoformat() + "Z"

    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"agent.name": agent_name}},
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

    print(f"[DEBUG] Elasticsearch: {response.status_code} - {response.text}")

    if response.status_code != 200:
        raise Exception(f"Elasticsearch error: {response.text}")

    return response.json().get("count", 0)


def connect_ssh(host):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=SSH_USERNAME, password=SSH_PASSWORD)
    return ssh


def test_wazuh_restart_log_recovery_by_agentname_only():
    print("[STEP 1] Подключение к агенту и фиксация времени ДО перезапуска")
    t0 = datetime.utcnow()

    ssh_agent = connect_ssh(AGENT_IP)
    ssh_agent.exec_command('logger "Тест лог до перезапуска Wazuh"')
    ssh_agent.close()

    time.sleep(10)

    logs_before = get_log_count_by_agent(AGENT_NAME, t0 - timedelta(minutes=2), t0 + timedelta(minutes=1))
    print(f"[INFO] Кол-во логов от агента ДО перезапуска: {logs_before}")

    print("[STEP 2] Перезапуск менеджера Wazuh")
    ssh_manager = connect_ssh(MANAGER_IP)
    wait_for_service_active(ssh_manager, "wazuh-manager")
    ssh_manager.exec_command("sudo systemctl restart wazuh-manager")
    wait_for_service_active(ssh_manager, "wazuh-manager")
    ssh_manager.close()

    print("[STEP 3] Генерация логов ПОСЛЕ перезапуска")
    ssh_agent = connect_ssh(AGENT_IP)
    ssh_agent.exec_command('logger "Тест лог после перезапуска Wazuh"')
    ssh_agent.close()

    time.sleep(60)
    t1 = datetime.utcnow()

    logs_after = get_log_count_by_agent(AGENT_NAME, t0, t1 + timedelta(seconds=30))
    print(f"[INFO] Кол-во логов от агента ПОСЛЕ перезапуска: {logs_after}")

    assert logs_before > 0, "Логи ДО перезапуска не поступают!"
    assert logs_after > 0, "Логи ПОСЛЕ перезапуска не поступают!"
