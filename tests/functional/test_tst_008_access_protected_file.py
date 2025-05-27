import time
import paramiko
import pytest
from elasticsearch import Elasticsearch

TARGET_IP = '192.168.0.13'
SUDO_PASSWORD = 'kali'
RULE_ID = "100001"
WAZUH_INDEX = "filebeat-*"
ELASTICSEARCH_URL = 'http://192.168.0.14:9200'

es = Elasticsearch(
    ELASTICSEARCH_URL,
    basic_auth=("elastic", "WLS5gHvR=+zJxq0YUAy9")
)


@pytest.mark.parametrize("target_ip", [TARGET_IP])
def test_privilege_escalation(target_ip):
    print("[+] Подключаемся по SSH и выполняем команду для доступа к /etc/shadow...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(target_ip, username="kali", password="kali", timeout=10)
        command = "sudo -S cat /etc/shadow"
        stdin, stdout, stderr = ssh.exec_command(command, get_pty=True)
        stdin.write(f"{SUDO_PASSWORD}\n")
        stdin.flush()
        stdout_str = stdout.read().decode()
        stderr_str = stderr.read().decode()
        print("stdout:", stdout_str)
        print("stderr:", stderr_str)

        if "Permission denied" in stderr_str and not stdout_str:
            print("[!] Команда завершилась с ошибкой 'Permission denied', но это нормально для теста.")

    except Exception as e:
        print(f"[-] Ошибка SSH: {str(e)}")
        raise
    finally:
        ssh.close()

    print("[+] Ожидаем 600 секунд для появления события в Elasticsearch через Filebeat и Logstash...")
    time.sleep(30)

    print("[+] Проверяем событие в Elasticsearch...")
    try:
        # Упрощенный запрос для поиска события
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"rule.id": RULE_ID}},
                        {"range": {"rule.level": {"gte": 10}}},
                        {"range": {"@timestamp": {"gte": "now-15m"}}},
                        {"term": {"log_type": "wazuh"}}
                    ]
                }
            }
        }
        response = es.search(index=WAZUH_INDEX, body=query, size=10)
        hits = response['hits']['total']['value']
        print(f"[+] Найдено {hits} событий с rule.id={RULE_ID} и уровнем тревоги >= 10")

        # Выводим детали событий для отладки
        for hit in response['hits']['hits']:
            print("Событие:", hit['_source'])

        assert hits > 0, f"Событие с rule.id {RULE_ID} не найдено или уровень тревоги < 10"

        # Проверяем описание события
        for hit in response['hits']['hits']:
            description = hit['_source'].get('rule', {}).get('description', '')
            assert "privilege escalation" in description.lower() or "unauthorized access" in description.lower(), \
                f"Описание события не соответствует ожидаемому: {description}"

        print(f"[+] Найдено {hits} событий. Тест пройден успешно!")

    except Exception as e:
        print(f"[-] Ошибка Elasticsearch: {str(e)}")
        raise