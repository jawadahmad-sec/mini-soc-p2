import os
import urllib3
from collections import defaultdict
from opensearchpy import OpenSearch
from dotenv import load_dotenv

urllib3.disable_warnings()
load_dotenv()

# --- CONFIG ---
CORRELATION_WINDOW_SECONDS = 120
MIN_ALERTS_FOR_INCIDENT = 2
CRITICAL_LEVEL_THRESHOLD = 10

# --- CONNECT ---
client = OpenSearch(
    hosts=[{'host': '192.168.56.105', 'port': 9200}],
    http_auth=(os.getenv('OS_USER', 'admin'), os.getenv('OS_PASSWORD')),
    use_ssl=True, verify_certs=False, ssl_show_warn=False
)

# --- FETCH RECENT ALERTS ---
def fetch_recent_alerts(minutes=20):
    query = {
        "size": 200,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"timestamp": {"gte": f"now-{minutes}m", "lte": "now"}}}
    }
    response = client.search(index='wazuh-alerts-*', body=query)
    return [hit['_source'] for hit in response['hits']['hits']]

# --- EXTRACT FIELDS ---
def extract_fields(alert):
    rule = alert.get('rule', {})
    data = alert.get('data', {})
    agent = alert.get('agent', {})
    
    src_ip = data.get('srcip') or data.get('src_ip') or alert.get('src_ip') or 'unknown'
    
    return {
        'timestamp': alert.get('timestamp'),
        'src_ip': src_ip,
        'rule_id': rule.get('id'),
        'rule_desc': rule.get('description'),
        'level': int(rule.get('level', 0)),
        'agent_name': agent.get('name', 'unknown_host'),
        'agent_id': agent.get('id', 'unknown_id'),
        'mitre_id': rule.get('mitre', {}).get('id', []),
        'mitre_technique': rule.get('mitre', {}).get('technique', [])
    }

# --- ENTITY-AWARE GROUPING KEY ---
def get_entity_key(alert):
    ip = alert['src_ip']
    agent_id = alert['agent_id']
    host_name = alert['agent_name']
    
    if ip not in ['127.0.0.1', 'unknown', '::1', '']:
        return f"IP_{ip}"
    if agent_id and agent_id != 'unknown_id':
        return f"AGENT_{agent_id}"
    return f"HOST_{host_name}"

# --- CORRELATION ---
def correlate(alerts):
    groups = defaultdict(list)
    for raw in alerts:
        a = extract_fields(raw)
        groups[get_entity_key(a)].append(a)
    
    incidents = []
    for entity, group in groups.items():
        if len(group) >= MIN_ALERTS_FOR_INCIDENT or max(a['level'] for a in group) >= CRITICAL_LEVEL_THRESHOLD:
            incidents.append({
                'entity': entity,
                'alert_count': len(group),
                'alerts': group,
                'risk_score': calculate_risk(group)
            })
    incidents.sort(key=lambda x: x['risk_score'], reverse=True)
    return incidents

# --- RISK SCORING ---
def calculate_risk(alerts):
    base = sum(a['level'] for a in alerts) * 2
    volume_bonus = len(alerts) * 3
    mitre_bonus = sum(5 for a in alerts if a['mitre_id'])
    return min(base + volume_bonus + mitre_bonus, 100)

# --- MAIN ---
if __name__ == "__main__":
    print("Fetching alerts from last 20 minutes...\n")
    raw_alerts = fetch_recent_alerts(minutes=20)
    print(f"Raw alerts fetched: {len(raw_alerts)}\n")
    
    incidents = correlate(raw_alerts)
    print(f"Correlated incidents: {len(incidents)}\n")
    print("=" * 60)
    
    for i, inc in enumerate(incidents, 1):
        print(f"\n🔴 INCIDENT #{i}")
        print(f"   Entity:       {inc['entity']}")
        print(f"   Alerts:       {inc['alert_count']}")
        print(f"   Risk Score:   {inc['risk_score']}/100")
        print(f"   Attack chain:")
        for a in inc['alerts'][:5]:
            print(f"     • [{a['level']}] {a['rule_desc']} ({a['agent_name']})")
