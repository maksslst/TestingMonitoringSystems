import time
import paramiko
import pytest
from elasticsearch import Elasticsearch

TARGET_IP = '192.168.0.13'
SSH_PORT = 22
ATTEMPT_COUNT = 5 
USERNAME = "invaliduser"
WAZUH_INDEX = "wazuh-*"
WRONG_PASSWORD = "wrong_password"  
RULE_IDS = ["5710", "5712"]  
ELASTICSEARCH_URL = 'http://192.168.0.14:9200'

es = Elasticsearch(
    ELASTICSEARCH_URL,
    basic_auth=("elastic", "WLS5gHvR=+zJxq0YUAy9"),
    verify_certs=False 
)


@pytest.mark.parametrize("target_ip", [TARGET_IP])
def test_multiple_failed_ssh_logins(target_ip):
    print(f"[+] Симулируем {ATTEMPT_COUNT} неудачных попыток входа по SSH на {target_ip} с пользователем {USERNAME}...")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        for i in range(ATTEMPT_COUNT):
            try:
                print(f"[DEBUG] Попытка {i + 1}/{ATTEMPT_COUNT}: Используем пароль '{WRONG_PASSWORD}'")
                ssh.connect(
                    target_ip,
                    port=SSH_PORT,
                    username=USERNAME,
                    password=WRONG_PASSWORD,
                    timeout=10,
                    allow_agent=False, 
                    look_for_keys=False,
                    disabled_algorithms={'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']},
                    gss_auth=False  
                )
                print(f"[!] Попытка {i + 1}/{ATTEMPT_COUNT}: Успешный вход (не ожидалось!)")
                raise AssertionError("Удалось войти с неправильным паролем или несуществующим пользователем!")
            except paramiko.AuthenticationException:
                print(f"[+] Попытка {i + 1}/{ATTEMPT_COUNT}: Неудачный вход (ожидаемый результат).")
            except Exception as e:
                print(f"[-] Ошибка при попытке {i + 1}: {str(e)}")
                raise
            time.sleep(2)

    except Exception as e:
        print(f"[-] Ошибка SSH: {str(e)}")
        raise
    finally:
        ssh.close()

    print("[+] Ожидаем 100 секунд для появления событий в Elasticsearch через Wazuh, Filebeat и Logstash...")
    time.sleep(100)

    print("[+] Проверяем события с rule.id: 5710, 5712 в Elasticsearch...")
    try:
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"terms": {"rule.id": RULE_IDS}},
                        {"range": {"rule.level": {"gte": 7}}},
                        {"range": {"@timestamp": {"gte": "now-15m"}}},
                        {"term": {"log_type": "syslog"}}
                    ]
                }
            }
        }
        response = es.search(index=WAZUH_INDEX, body=query, size=10)
        hits = response['hits']['total']['value']
        print(f"[+] Найдено {hits} событий с rule.id 5710 или 5712 и уровнем тревоги >= 7")

        for hit in response['hits']['hits']:
            print("Событие:", hit['_source'])

        assert hits >= 1, f"Ожидалось минимум 1 событие с rule.id 5712 и уровнем >= 7, найдено {hits}"

        print(f"[+] Найдено {hits} событий. Тест пройден успешно!")

    except Exception as e:
        print(f"[-] Ошибка Elasticsearch: {str(e)}")
        raise