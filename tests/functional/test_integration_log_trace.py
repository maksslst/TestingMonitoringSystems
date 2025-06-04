import pytest
import paramiko
import time
from elasticsearch import Elasticsearch
from config.config import ELK_URL, ELASTIC_AUTH, SSH_USERNAME, SSH_PASSWORD

TARGET_IP = "192.168.0.15"
LOG_FILE = "/var/log/test_app.log"
RULE_IDS = ["5402"]
INDEX_PATTERN = "filebeat-*"
MAX_WAIT_SECONDS = 60
WAIT_INTERVAL_SECONDS = 10

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
            print(f"[+] SSH connected to {TARGET_IP}")
            yield ssh
            break
        except Exception as e:
            print(f"[-] SSH connection attempt {attempt + 1} failed: {e}")
            time.sleep(2)
    else:
        pytest.fail("Failed to establish SSH connection after 3 attempts")
    ssh.close()
    print(f"[+] SSH connection closed for {TARGET_IP}")


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
    stdin, stdout, stderr = client.exec_command(command, timeout=10)
    exit_status = stdout.channel.recv_exit_status()
    error = stderr.read().decode("utf-8")
    if exit_status != 0 and "password" not in error.lower():
        raise Exception(f"Command failed: {error}")
    return stdout.read().decode("utf-8")


def wait_for_elasticsearch_alerts(test_start_time, end_time):
    for _ in range(int(MAX_WAIT_SECONDS / WAIT_INTERVAL_SECONDS)):
        buffer_start = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 300))
        alert_query = {
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"rule.id": RULE_IDS}},
                        {"term": {"agent.ip": TARGET_IP}},
                        {"wildcard": {"data.command": "*Test event*"}}
                    ],
                    "filter": {
                        "range": {
                            "@timestamp": {
                                "gte": buffer_start,
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
            response = es.search(index=INDEX_PATTERN, body=alert_query)
            alerts_found = len(response["hits"]["hits"])
            if alerts_found >= 1:
                print(f"[+] Found {alerts_found} alerts in Elasticsearch")
                for hit in response["hits"]["hits"]:
                    print(
                        f"Alert: {hit['_source']['rule']['description']} (Command: {hit['_source']['data']['command']})")
                return alerts_found
        except Exception as e:
            print(f"[-] Alert query attempt failed: {e}")
        time.sleep(WAIT_INTERVAL_SECONDS)
    print(f"[-] Found 0 alerts in Elasticsearch after {MAX_WAIT_SECONDS} seconds")
    return 0


def test_log_trace(setup_log_file, ssh_client):
    test_start_time = setup_log_file
    end_time = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

    for i in range(5):
        ssh_execute_command(
            ssh_client,
            f"echo {SSH_PASSWORD} | sudo -S sh -c \"echo 'Test event {i} at $(date)' >> {LOG_FILE}\""
        )
        print(f"[+] Generated event {i + 1}")
        time.sleep(1)

    log_content = ssh_execute_command(ssh_client, f"cat {LOG_FILE}")
    print(f"[+] Contents of {LOG_FILE}:\n{log_content}")
    assert log_content.strip(), f"File {LOG_FILE} is empty"

    wazuh_log = ssh_execute_command(ssh_client,
                                    f"echo {SSH_PASSWORD} | sudo -S cat /var/ossec/logs/ossec.log | grep -i 'sudo'")
    print(f"[+] Wazuh log entries with 'sudo':\n{wazuh_log}")

    alerts_found = wait_for_elasticsearch_alerts(test_start_time, end_time)
    assert alerts_found >= 1, f"Expected at least 1 alert for sudo commands, found {alerts_found}"

    filebeat_errors = ssh_execute_command(
        ssh_client,
        f"echo {SSH_PASSWORD} | sudo -S cat /var/log/filebeat/filebeat-* | grep -i error"
    )
    if filebeat_errors:
        print(f"[-] Filebeat errors found: {filebeat_errors}")
        pytest.fail("Filebeat encountered errors during log processing")
    else:
        print("[+] No Filebeat errors found")

    print("[+] Test completed successfully")
