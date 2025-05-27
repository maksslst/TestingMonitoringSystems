import paramiko
import time
import pytest
from elasticsearch import Elasticsearch

TARGET_IP = "192.168.0.13"
ELASTICSEARCH_URL = "https://192.168.0.14:9200"
WAZUH_INDEX = "wazuh-*"
ELASTICSEARCH_USER = "elastic"
ELASTICSEARCH_PASSWORD = "WLS5gHvR=+zJxq0YUAy9"
RULE_ID = "550"
SUDO_PASSWORD = "kali"

# Подключение к Elasticsearch
es = Elasticsearch(
    ["https://192.168.0.14:9200"],
    basic_auth=("elastic", "WLS5gHvR=+zJxq0YUAy9"),
    verify_certs=False
)


@pytest.mark.parametrize("target_ip", [TARGET_IP])
def test_config_change_detection(target_ip):
    print("[+] Вносим изменения в конфигурацию агента...")

    ssh = paramiko.SSHClient()

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(target_ip, username="kali", password="kali")

    command = "echo '#test' | sudo tee -a /etc/ossec.conf"

    stdin, stdout, stderr = ssh.exec_command(command, get_pty=True)

    stdin.write(f"{SUDO_PASSWORD}\n")
    stdin.flush()
    stdout_str = stdout.read().decode()
    stderr_str = stderr.read().decode()

    print("stdout:", stdout_str)
    print("stderr:", stderr_str)
    ssh.close()

    time.sleep(30)

    print("[+] Проверяем событие в Kibana...")

    query = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"rule.id": RULE_ID}},
                    {"range": {"@timestamp": {"gte": "now-1m"}}},
                ]
            }
        }
    }

    response = es.search(index=WAZUH_INDEX, body=query)

    # Проверка наличия события
    assert response['hits']['total']['value'] > 0, f"Событие с rule.id {RULE_ID} не найдено"

    print("[+] Тест прошел успешно: Событие зафиксировано.")
