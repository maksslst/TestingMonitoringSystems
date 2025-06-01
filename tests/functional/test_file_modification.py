import json
import paramiko
import pytest
from elasticsearch import Elasticsearch
import time
from config.config import ELK_URL, ELASTIC_AUTH, SSH_USERNAME, SSH_PASSWORD

FILE_MOD_RULE_IDS = ["550"]  # Syscheck rule: 550 (file modified)

es = Elasticsearch(ELK_URL, basic_auth=ELASTIC_AUTH, verify_certs=False)


def pytest_addoption(parser):
    parser.addoption("--target-ip", action="store", default=None)


@pytest.fixture
def target_ip(request):
    return request.config.getoption("--target-ip") or "192.168.0.16"


def ssh_execute_command(client, command):
    """Выполнить команду через SSH и вернуть вывод."""
    stdin, stdout, stderr = client.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    output = stdout.read().decode("utf-8")
    error = stderr.read().decode("utf-8")
    if exit_status != 0 and "password" not in error.lower():
        raise Exception(f"Command failed: {error}")
    return output


def test_file_modification(target_ip):
    """
    Test modifying /etc/passwd on target_ip and verifying syscheck alert in ELK.
    """
    # Подключение по SSH
    print(f"[+] Connecting to {target_ip}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            target_ip,
            port=22,
            username=SSH_USERNAME,
            password=SSH_PASSWORD,
            timeout=10,
            allow_agent=False,
            look_for_keys=False
        )
        print(f"[+] Connected to {target_ip} via SSH")

        # Создаём резервную копию /etc/passwd
        ssh_execute_command(ssh, f"echo {SSH_PASSWORD} | sudo -S cp /etc/passwd /tmp/passwd.bak")
        print("[+] Created backup of /etc/passwd")

        # Записываем время начала теста
        start_time = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

        # Модифицируем /etc/passwd
        ssh_execute_command(
            ssh,
            f"echo {SSH_PASSWORD} | sudo -S sh -c \"echo 'testuser:x:9999:9999:Test User:/home/testuser:/bin/bash' >> /etc/passwd\""
        )
        print("[+] Modified /etc/passwd")

        # Ждём обработки syscheck и Filebeat (3 минуты)
        time.sleep(180)

        # Записываем время окончания
        end_time = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

        # Проверяем алерт в ELK
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"rule.id": FILE_MOD_RULE_IDS}},
                        {"term": {"syscheck.path": "/etc/passwd"}},  # Поле из лога
                        {"term": {"agent.ip": target_ip}}  # Поле из лога
                    ],
                    "filter": {
                        "range": {
                            "@timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }
                    }
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        response = es.search(index="filebeat-*", body=query, size=1)
        hits = response["hits"]["hits"]
        if not hits:
            raise AssertionError(
                f"No syscheck alerts found for /etc/passwd on {target_ip}. Query: {json.dumps(query, indent=2)}")
        print(f"[+] Found {len(hits)} syscheck alert for /etc/passwd: {hits[0]['_source']}")

    finally:
        # Восстанавливаем /etc/passwd и перезапускаем агент
        try:
            if ssh.get_transport() and ssh.get_transport().is_active():
                ssh_execute_command(ssh, f"echo {SSH_PASSWORD} | sudo -S mv /tmp/passwd.bak /etc/passwd")
                ssh_execute_command(ssh, f"echo {SSH_PASSWORD} | sudo -S systemctl restart wazuh-agent")
                print("[+] Restored /etc/passwd and restarted agent")
        except Exception as e:
            print(f"[-] Failed to restore /etc/passwd: {e}")
        finally:
            ssh.close()
            print("[+] SSH connection closed")
