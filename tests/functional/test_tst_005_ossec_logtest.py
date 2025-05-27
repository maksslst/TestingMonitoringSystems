import subprocess
import time
import requests
import pytest

KIBANA_URL = "http://192.168.0.14:5601"
KIBANA_ALERTS_INDEX = "wazuh-*"

TEST_LOG = "May 23 14:00:00 sshd[1234]: Failed password for root from 192.168.0.1"

EXPECTED_RULE_ID = 5715


def check_event_in_kibana(rule_id):
    query = {
        "query": {
            "match": {
                "rule.id": rule_id
            }
        }
    }

    response = requests.get(f"{KIBANA_URL}/elasticsearch/{KIBANA_ALERTS_INDEX}/_search", json=query)

    if response.status_code == 200:
        hits = response.json().get('hits', {}).get('hits', [])
        return len(hits) > 0
    return False


def test_ossec_logtest():
    process = subprocess.Popen(
        ["/var/ossec/bin/ossec-logtest"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    process.stdin.write(TEST_LOG + "\n")
    process.stdin.flush()

    time.sleep(2)

    process.stdin.close()

    output = process.stdout.read()
    error = process.stderr.read()

    if process.returncode != 0:
        print(f"Ошибка при выполнении ossec-logtest: {error}")
        pytest.fail("ossec-logtest failed")

    if f"rule.id: {EXPECTED_RULE_ID}" not in output:
        pytest.fail(f"Правило с ID {EXPECTED_RULE_ID} не сработало. Вывод: {output}")

    print("Правило сработало успешно, проверяем Kibana...")

    if check_event_in_kibana(EXPECTED_RULE_ID):
        print("Событие зафиксировано в Kibana.")
    else:
        pytest.fail(f"Событие с rule.id {EXPECTED_RULE_ID} не найдено в Kibana.")


if __name__ == "__main__":
    test_ossec_logtest()
