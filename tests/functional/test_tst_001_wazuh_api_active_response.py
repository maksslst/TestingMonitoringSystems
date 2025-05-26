import pytest
import requests
import time
from datetime import datetime, timedelta

requests.packages.urllib3.disable_warnings()

# Конфигурация Wazuh
WAZUH_API_URL = "http://192.168.0.10:55000"
WAZUH_API_USER = "wazuh"
WAZUH_API_PASSWORD = "wazuh"

# Конфигурация Elasticsearch
ELASTICSEARCH_URL = "https://192.168.0.14:9200"
WAZUH_INDEX = "wazuh-*"
ELASTICSEARCH_USER = "elastic"
ELASTICSEARCH_PASSWORD = "WLS5gHvR=+zJxq0YUAy9"

@pytest.fixture
def get_token():
    url = f"{WAZUH_API_URL}/security/user/authenticate?raw=true"
    try:
        response = requests.post(url, auth=(WAZUH_API_USER, WAZUH_API_PASSWORD), verify=False)
        response.raise_for_status()  # Бросить исключение для 4xx/5xx ошибок
        assert response.text.startswith("eyJ"), f"Expected JWT token, got {response.text}"
        return response.text
    except requests.exceptions.HTTPError as e:
        pytest.fail(f"HTTP Error: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        pytest.fail(f"An error occurred: {str(e)}")

@pytest.fixture
def elastic_auth():
    return (ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD)

def test_wazuh_api_active_response(get_token):
    url = f"{WAZUH_API_URL}/agents/001/active-response"
    headers = {
        "Authorization": f"Bearer {get_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "command": "firewall-drop"
    }

    response = requests.post(url, json=payload, headers=headers, verify=False)  # Изменили метод на POST
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    json_resp = response.json()
    assert "message" in json_resp and "Command sent" in json_resp["message"], \
        f"Expected message 'Command sent', got: {json_resp}"

def test_wazuh_api_active_response_logs_present(elastic_auth, get_token):
    url = f"{WAZUH_API_URL}/agents/001/active-response"
    headers = {
        "Authorization": f"Bearer {get_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "command": "firewall-drop"
    }

    response = requests.post(url, json=payload, headers=headers, verify=False)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

    start_time = time.time()
    logs_found = False
    while time.time() - start_time < 60:  # Максимум 60 секунд
        now = datetime.utcnow()
        five_minutes_ago = now - timedelta(minutes=5)

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": five_minutes_ago.isoformat(), "lte": now.isoformat()}}},
                        {"match_phrase": {"rule.description": "Test rule for Active Response (firewall-drop)"}}
                    ]
                }
            },
            "size": 5
        }

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
                logs_found = True
                break
        time.sleep(5)

    assert logs_found, "No logs found for active response in Elasticsearch"
