import os
import urllib3
from opensearchpy import OpenSearch
from dotenv import load_dotenv

urllib3.disable_warnings()
load_dotenv()

client = OpenSearch(
    hosts=[{'host': '192.168.56.105', 'port': 9200}],
    http_auth=(os.getenv('OS_USER', 'admin'), os.getenv('OS_PASSWORD')),
    use_ssl=True, verify_certs=False, ssl_show_warn=False
)

try:
    info = client.info()
    print(f"Connected to: {info['cluster_name']}")
    print(f"Version: {info['version']['number']}")
    count = client.count(index='wazuh-alerts-*')['count']
    print(f"Total alerts in index: {count}")
except Exception as e:
    print(f"Connection failed: {e}")
