import time
import socket
import paramiko
import pytest
from elasticsearch import Elasticsearch
from config.config import WAZUH_AGENT, OSSEC_AGENT, ELK_URL, WAZUH_INDEX, ELASTIC_AUTH, SSH_PORT, ATTEMPT_COUNT, \
    BRUTEFORCE_RULE_IDS

es = Elasticsearch(
    ELK_URL,
    basic_auth=ELASTIC_AUTH,
    verify_certs=False
)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"[-] Ошибка при определении локального IP: {str(e)}")
        return "127.0.0.1"


@pytest.fixture
def target_ip(request):
    target_ip = request.config.getoption("--target-ip")
    if target_ip:
        print(target_ip)
        return target_ip
    return [WAZUH_AGENT, OSSEC_AGENT]


def test_multiple_failed_ssh_logins(target_ip):
    if isinstance(target_ip, list):
        pytest.skip("Тест требует одного IP-адреса через --target-ip или по умолчанию")

    source_ip = get_local_ip()
    print(f"[+] Симулируем {ATTEMPT_COUNT} неудачных попыток входа по SSH на {target_ip} с {source_ip}...")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    username = "invaliduser"
    password = "wrong_password"

    try:
        for i in range(ATTEMPT_COUNT):
            print(f"[DEBUG] Попытка {i + 1}/{ATTEMPT_COUNT}: Подключение к {target_ip}")
            try:
                ssh.connect(
                    target_ip,
                    port=SSH_PORT,
                    username=username,
                    password=password,
                    timeout=10,
                    allow_agent=False,
                    look_for_keys=False
                )
                raise AssertionError(f"Удалось войти на {target_ip} с неверным паролем!")
            except paramiko.AuthenticationException:
                print(f"[+] Попытка {i + 1}/{ATTEMPT_COUNT}: Неудачный вход (ожидаемо).")
            except Exception as e:
                print(f"[-] Ошибка при попытке {i + 1}: {str(e)}")
                raise
            time.sleep(2)
    finally:
        ssh.close()

    print("[+] Ожидаем 60 секунд для обработки событий Wazuh/OSSEC через Filebeat и ELK...")
    time.sleep(60)

    print(f"[+] Проверяем события с rule.id: {BRUTEFORCE_RULE_IDS} в Elasticsearch...")
    try:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"rule.id": BRUTEFORCE_RULE_IDS}},
                        {"range": {"rule.level": {"gte": 5}}},
                        {"term": {"data.srcip": source_ip}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }

        response = es.search(index=WAZUH_INDEX, body=query, size=10)
        hits = response["hits"]["total"]["value"]
        print(f"[+] Найдено {hits} событий с rule.id {BRUTEFORCE_RULE_IDS} и уровнем >= 5")

        for hit in response["hits"]["hits"]:
            print("[DEBUG] Событие:", hit["_source"])

        assert hits >= 1, f"Ожидалось минимум 1 событие с rule.id {BRUTEFORCE_RULE_IDS}, найдено {hits}"

        print(f"[+] Тест пройден: найдено {hits} событий для {target_ip}")

    except Exception as e:
        print(f"[-] Ошибка Elasticsearch: {str(e)}")
        raise
