import pytest
import paramiko
import time
from elasticsearch import Elasticsearch
from config.config import ELK_URL, ELASTIC_AUTH, SSH_USERNAME, SSH_PASSWORD

TARGET_IP = "192.168.0.15"
LOG_FILE = "/var/log/test_app.log"
RULE_IDS = ["550"]
es = Elasticsearch(ELK_URL, basic_auth=ELASTIC_AUTH, verify_certs=False)


@pytest.fixture(scope="module")
def ssh_client():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for attempt in range(3):
        try:
            ssh.connect(
                TARGET_IP,
                port=22,
                username=SSH_USERNAME,
                password=SSH_PASSWORD,
                timeout=10
            )
            yield ssh
            break
        except Exception as e:
            print(f"[-] SSH connection attempt {attempt + 1} failed: {e}")
            time.sleep(1)
        finally:
            if ssh and not ssh.get_transport():
                ssh.close()
    else:
        pytest.fail("Failed to connect to SSH after 3 attempts")
    ssh.close()


@pytest.fixture(scope="module")
def setup_log_file(ssh_client):
    test_start_time = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    print(f"[+] Test started at {test_start_time}")
    try:
        ssh_execute_command(ssh_client, f"echo {SSH_PASSWORD} | sudo -S touch {LOG_FILE}")
        ssh_execute_command(ssh_client, f"echo {SSH_PASSWORD} | sudo -S chmod 644 {LOG_FILE}")
        ssh_execute_command(ssh_client, f"echo {SSH_PASSWORD} | sudo -S chown root:root {LOG_FILE}")
        print(f"[+] Created {LOG_FILE}")
        yield test_start_time
        ssh_execute_command(ssh_client, f"echo {SSH_PASSWORD} | sudo -S rm -f {LOG_FILE}")
        ssh_execute_command(ssh_client, f"echo {SSH_PASSWORD} | sudo -S /var/ossec/bin/ossec-control restart")
        print(f"[+] Removed {LOG_FILE}, restarted Wazuh")
    except Exception as e:
        pytest.fail(f"Setup/Cleanup failed: {e}")


def ssh_execute_command(client, command):
    stdin, stdout, stderr = client.exec_command(command, timeout=5)
    exit_status = stdout.channel.recv_exit_status()
    error = stderr.read().decode("utf-8")
    if exit_status != 0 and "password" not in error.lower():
        raise Exception(f"Command failed: {error}")
    return stdout.read().decode("utf-8")


def test_log_trace(setup_log_file, ssh_client):
    test_start_time = setup_log_file
    end_time = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

    # Генерация 5 событий
    for i in range(5):
        ssh_execute_command(
            ssh_client,
            f"echo {SSH_PASSWORD} | sudo -S sh -c \"echo 'Test event {i} at $(date)' >> {LOG_FILE}\""
        )
        print(f"[+] Generated event {i + 1}")
        time.sleep(1)

    time.sleep(10)

    wazuh_log_output = ssh_execute_command(
        ssh_client,
        f"echo {SSH_PASSWORD} | sudo -S cat /var/ossec/logs/ossec.log | grep '{LOG_FILE}'"
    )
    wazuh_logs_found = len(wazuh_log_output.splitlines())
    print(f"[+] Found {wazuh_logs_found} Wazuh log entries")
    assert wazuh_logs_found >= 1, f"Expected Wazuh log entries, found {wazuh_logs_found}"
    for line in wazuh_log_output.splitlines()[:3]:
        print(f"Wazuh log: {line}")

    filebeat_errors = ssh_execute_command(
        ssh_client,
        f"echo {SSH_PASSWORD} | sudo -S cat /var/log/filebeat/filebeat-20250601.ndjson | grep -i error"
    )
    if filebeat_errors:
        print(f"[-] Filebeat errors found: {filebeat_errors}")
    else:
        print("[+] No Filebeat errors found")

    raw_log_query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"agent.ip": TARGET_IP}},
                    {"match": {"log.file.path": LOG_FILE}}
                ],
                "filter": {
                    "range": {
                        "@timestamp": {
                            "gte": test_start_time,
                            "lte": end_time,
                            "format": "strict_date_optional_time"
                        }
                    }
                }
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 10
    }
    try:
        response = es.search(index="filebeat-*", body=raw_log_query)
        raw_logs_found = len(response["hits"]["hits"])
        print(f"[+] Found {raw_logs_found} raw logs in Elasticsearch")
        assert raw_logs_found >= 1, f"Expected 1–5 raw logs, found {raw_logs_found}"
        for hit in response["hits"]["hits"]:
            print(
                f"Raw log: {hit['_source'].get('message', 'No message')} (Path: {hit['_source']['log']['file']['path']})")
    except Exception as e:
        print(f"[-] Raw log query failed: {e}")
        pytest.fail(f"Raw log query failed: {e}")

    alert_query = {
        "query": {
            "bool": {
                "must": [
                    {"terms": {"rule.id": RULE_IDS}},
                    {"term": {"agent.ip": TARGET_IP}},
                    {"term": {"syscheck.path": LOG_FILE}}
                ],
                "filter": {
                    "range": {
                        "@timestamp": {
                            "gte": test_start_time,
                            "lte": end_time,
                            "format": "strict_date_optional_time"
                        }
                    }
                }
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 10
    }
    try:
        response = es.search(index="filebeat-*", body=alert_query)
        alerts_found = len(response["hits"]["hits"])
        print(f"[+] Found {alerts_found} alerts in Elasticsearch")
        assert alerts_found >= 1, f"Expected 1–5 alerts, found {alerts_found}"
        for hit in response["hits"]["hits"]:
            print(f"Alert: {hit['_source']['rule']['description']} (Path: {hit['_source']['syscheck']['path']})")
    except Exception as e:
        print(f"[-] Alert query failed: {e}")
        pytest.fail(f"Alert query failed: {e}")

    print(f"[+] Test completed successfully")
