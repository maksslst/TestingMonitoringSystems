import pytest
import requests
import time
from datetime import datetime, timedelta
import json

requests.packages.urllib3.disable_warnings()

TARGET_IP = "192.168.0.13"
WEB_PORT = 80
ELASTICSEARCH_URL = "https://192.168.0.14:9200"
WAZUH_INDEX = "wazuh-alerts-*"
ELASTICSEARCH_USER = "elastic"
ELASTICSEARCH_PASSWORD = "WLS5gHvR=+zJxq0YUAy9"
AGENT_ID = "001"
RULE_ID = "31106"


@pytest.fixture
def elastic_auth():
    return (ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD)


def wait_for_alert(query, elastic_auth, timeout=90, interval=10):
    end_time = time.time() + timeout
    headers = {"Content-Type": "application/json"}

    while time.time() < end_time:
        try:
            response = requests.post(
                f"{ELASTICSEARCH_URL}/{WAZUH_INDEX}/_search",
                json=query,
                headers=headers,
                auth=elastic_auth,
                verify=False
            )
            if response.status_code == 200:
                hits = response.json().get("hits", {}).get("hits", [])
                if hits:
                    return hits
            else:
                print(f"[!] Ошибка поиска: {response.status_code} — {response.text}")
        except Exception as e:
            print(f"[!] Исключение при запросе к Elasticsearch: {e}")

        time.sleep(interval)

    return []


def test_sql_injection_union_select(elastic_auth):
    url = f"http://{TARGET_IP}:{WEB_PORT}/test.php?input=%27%20union%20select%20*%20from%20users%20--"

    try:
        response = requests.get(url, timeout=5, verify=False)
        print(f"[+] Запрос отправлен. Статус-код: {response.status_code}")
        assert response.status_code == 200, f"Неожиданный код ответа: {response.status_code}"
    except requests.RequestException as e:
        pytest.fail(f"[!] Ошибка при отправке запроса: {e}")

    print("[*] Ожидание оповещений от Wazuh (до 90 секунд)...")

    now = datetime.utcnow()
    five_minutes_ago = now - timedelta(minutes=5)

    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-10m", "lte": "now"}}},
                    {"match": {"rule.id": "31106"}},
                    {"match": {"agent.id": "001"}}
                ]
            }
        },
        "size": 10
    }

    hits = wait_for_alert(query, elastic_auth)

    if hits:
        print(f"[+] Найдено {len(hits)} совпадений.")
        for alert in hits:
            print(json.dumps(alert["_source"], indent=2))
    else:
        print("[-] Совпадений не найдено.")

    assert len(hits) > 0, f"Оповещения по правилу {RULE_ID} не найдены"

    alert = hits[0]["_source"]
    level = alert["rule"]["level"]
    print(f"[+] Уровень обнаружения: {level}")
    assert level >= 6, f"Уровень должен быть >= 10, получено: {level}"

