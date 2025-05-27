import pytest
import subprocess
import requests
import time
from datetime import datetime, timedelta

requests.packages.urllib3.disable_warnings()

TARGET_IP = "192.168.0.13"
ELASTICSEARCH_URL = "https://192.168.0.14:9200"
WAZUH_INDEX = "wazuh-*"
ELASTICSEARCH_USER = "elastic"
ELASTICSEARCH_PASSWORD = "WLS5gHvR=+zJxq0YUAy9"


@pytest.fixture
def elastic_auth():
    return (ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD)


def wait_for_alert(query, elastic_auth, timeout=120):
    start_time = time.time()
    while time.time() - start_time < timeout:
        es_headers = {"Content-Type": "application/json"}
        search_response = requests.post(
            f"{ELASTICSEARCH_URL}/{WAZUH_INDEX}/_search",
            json=query,
            headers=es_headers,
            auth=elastic_auth,
            verify=False
        )
        if search_response.status_code == 200:
            hits = search_response.json()["hits"]["hits"]
            if len(hits) > 0:
                return hits
        time.sleep(5)
    return []


def test_port_scan_detection(elastic_auth):
    print(f"[+] Выполняем базовое сканирование: nmap -p 1-1000 {TARGET_IP}")
    try:
        subprocess.run(["nmap", "-p", "1-1000", TARGET_IP], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        pytest.fail(f"[!] Ошибка при выполнении nmap -p 1-1000: {e.stderr}")

    print("[*] Ожидание оповещений от Wazuh (до 120 секунд)...")
    now = datetime.utcnow()
    ten_minutes_ago = now - timedelta(minutes=10)
    query_basic = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": ten_minutes_ago.isoformat(), "lte": now.isoformat()}}},
                    {"match": {"agent.id": "001"}},
                    {"match_phrase": {"rule.groups": "portscan"}}
                ]
            }
        },
        "size": 10
    }
    hits_basic = wait_for_alert(query_basic, elastic_auth)
    if hits_basic:
        print(f"[+] Найдено {len(hits_basic)} совпадений для базового сканирования.")
        for alert in hits_basic:
            print(f"Alert (Basic Scan): {alert['_source']}")
    else:
        print("[-] Совпадений не найдено для базового сканирования.")
    assert len(hits_basic) > 0, "Оповещения о базовом порсканировании не найдены"

    print(f"[+] Выполняем агрессивное сканирование: nmap -A {TARGET_IP}")
    try:
        subprocess.run(["nmap", "-A", TARGET_IP], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        pytest.fail(f"[!] Ошибка при выполнении nmap -A: {e.stderr}")

    print("[*] Ожидание оповещений от Wazuh (до 120 секунд)...")
    query_aggressive = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": ten_minutes_ago.isoformat(), "lte": now.isoformat()}}},
                    {"match": {"agent.id": "001"}},
                    {"match_phrase": {"rule.groups": "portscan"}}
                ]
            }
        },
        "size": 10
    }
    hits_aggressive = wait_for_alert(query_aggressive, elastic_auth)
    if hits_aggressive:
        print(f"[+] Найдено {len(hits_aggressive)} совпадений для агрессивного сканирования.")
        for alert in hits_aggressive:
            print(f"Alert (Aggressive Scan): {alert['_source']}")
    else:
        print("[-] Совпадений не найдено для агрессивного сканирования.")
    assert len(hits_aggressive) > 0, "Оповещения об агрессивном порсканировании не найдены"

    basic_levels = [hit["_source"]["rule"]["level"] for hit in hits_basic]
    aggressive_levels = [hit["_source"]["rule"]["level"] for hit in hits_aggressive]
    print(f"Уровни тревоги для базового сканирования: {basic_levels}")
    print(f"Уровни тревоги для агрессивного сканирования: {aggressive_levels}")

    max_basic_level = max(basic_levels) if basic_levels else 0
    max_aggressive_level = max(aggressive_levels) if aggressive_levels else 0
    print(f"Максимальный уровень базового сканирования: {max_basic_level}")
    print(f"Максимальный уровень агрессивного сканирования: {max_aggressive_level}")
    assert max_aggressive_level >= max_basic_level, (
        f"Агрессивное сканирование должно иметь уровень тревоги >= базового: "
        f"{max_aggressive_level} < {max_basic_level}"
    )
