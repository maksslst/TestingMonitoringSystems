import paramiko
import pytest
from elasticsearch import Elasticsearch
import time
import json
from config.config import ELK_URL, ELASTIC_AUTH, SSH_USERNAME, SSH_PASSWORD

USER_MOD_RULE_IDS = ["550", "5901"]  # Syscheck (550) or user addition (5901)

es = Elasticsearch(ELK_URL, basic_auth=ELASTIC_AUTH, verify_certs=False)

def pytest_addoption(parser):
    parser.addoption("--target-ip", action="store", default=None)

@pytest.fixture
def target_ip(request):
    return request.config.getoption("--target-ip") or "192.168.0.15"

def ssh_execute_command(client, command):
    """Execute SSH command and return output."""
    stdin, stdout, stderr = client.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    output = stdout.read().decode("utf-8")
    error = stderr.read().decode("utf-8")
    if exit_status != 0 and "password" not in error.lower() and "already exists" not in error.lower():
        raise Exception(f"Command failed: {error}")
    return output

def test_user_addition_ossec(target_ip):
    """
    Test adding a user via useradd on OSSEC agent and verifying alert in ELK.
    """
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

        # Check OSSEC status
        output = ssh_execute_command(ssh, "sudo /var/ossec/bin/ossec-control status")
        print(f"[+] OSSEC status: {output}")

        # Backup system files
        ssh_execute_command(ssh, f"echo {SSH_PASSWORD} | sudo -S cp /etc/passwd /tmp/passwd.bak")
        ssh_execute_command(ssh, f"echo {SSH_PASSWORD} | sudo -S cp /etc/shadow /tmp/shadow.bak")
        ssh_execute_command(ssh, f"echo {SSH_PASSWORD} | sudo -S cp /etc/group /tmp/group.bak")
        print(f"[+] Backed up /etc/passwd, /etc/shadow, /etc/group")

        # Record start time
        start_time = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

        # Add user
        ssh_execute_command(
            ssh,
            f"echo {SSH_PASSWORD} | sudo -S useradd -m -s /bin/bash testuser"
        )
        print(f"[+] Added user testuser")

        # Wait for syscheck and Filebeat (3 minutes)
        time.sleep(180)

        # Record end time
        end_time = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

        # Check alert in ELK
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"rule.id": USER_MOD_RULE_IDS}},
                        {"term": {"agent.ip": target_ip}}
                    ],
                    "should": [
                        {"term": {"syscheck.path": "/etc/passwd"}},
                        {"match": {"full_log": "testuser"}}
                    ],
                    "minimum_should_match": 1,
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
        try:
            response = es.search(index="filebeat-*", body=query, size=1)
            hits = response["hits"]["hits"]
            if not hits:
                raise AssertionError(f"No user addition alerts found for {target_ip}. Query: {json.dumps(query, indent=2)}")
            print(f"[+] Found {len(hits)} alert: {hits[0]['_source']}")
        except Exception as e:
            print(f"[-] ELK query failed: {e}")
            raise

    finally:
        try:
            if ssh.get_transport() and ssh.get_transport().is_active():
                ssh_execute_command(ssh, f"echo {SSH_PASSWORD} | sudo -S userdel -r testuser")
                ssh_execute_command(ssh, f"echo {SSH_PASSWORD} | sudo -S mv /tmp/passwd.bak /etc/passwd")
                ssh_execute_command(ssh, f"echo {SSH_PASSWORD} | sudo -S mv /tmp/shadow.bak /etc/shadow")
                ssh_execute_command(ssh, f"echo {SSH_PASSWORD} | sudo -S mv /tmp/group.bak /etc/group")
                ssh_execute_command(ssh, f"echo {SSH_PASSWORD} | sudo -S /var/ossec/bin/ossec-control restart")
                print(f"[+] Removed testuser, restored files, restarted OSSEC")
        except Exception as e:
            print(f"[-] Cleanup failed: {e}")
        finally:
            ssh.close()
            print(f"[+] SSH closed")