import sys
import json
import os
import requests
import yaml
import urllib3
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline as windows_pipeline
from sigma.processing.resolver import ProcessingPipelineResolver

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def convert_sigma(rule_path):
    resolver = ProcessingPipelineResolver()
    resolver.add_pipeline_class(windows_pipeline())
    resolver.add_pipeline_class(sysmon_pipeline())
    resolved = resolver.resolve(resolver.pipelines)
    backend = LuceneBackend(processing_pipeline=resolved)
    rules = SigmaCollection.load_ruleset([rule_path])
    result = backend.convert(rules)
    return result[0] if result else None


def load_rule_metadata(rule_path):
    with open(rule_path, "r") as f:
        return yaml.safe_load(f)


def deploy_to_kibana(rule_path):
    elastic_url = os.environ["ELASTIC_URL"]
    api_key = os.environ["ELASTIC_API_KEY"]

    metadata = load_rule_metadata(rule_path)
    query = convert_sigma(rule_path)

    if not query:
        print(f"FAIL: Could not convert {rule_path}")
        sys.exit(1)

    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "low"
    }

    risk_score_map = {
        "critical": 99,
        "high": 73,
        "medium": 47,
        "low": 21
    }

    rule_severity = severity_map.get(metadata.get("level", "medium"), "medium")
    risk_score = risk_score_map.get(rule_severity, 47)

    tags = []
    for tag in metadata.get("tags", []):
        tags.append(str(tag))

    kibana_rule = {
        "type": "query",
        "language": "lucene",
        "query": query,
        "name": metadata.get("title", "Unnamed Rule"),
        "description": metadata.get("description", "No description provided."),
        "severity": rule_severity,
        "risk_score": risk_score,
        "enabled": True,
        "from": "now-15m",
        "interval": "5m",
        "max_signals": 100,
        "tags": tags,
        "references": metadata.get("references", []),
        "author": [metadata.get("author", "1xLoZec")],
        "index": [
            "logs-*",
            "winlogbeat-*",
            ".ds-logs-*",
            "endgame-*",
            "filebeat-*"
        ],
        "rule_id": str(metadata.get("id", "")),
        "false_positives": metadata.get("falsepositives", []),
        "immutable": False,
        "version": 1,
    }

    kibana_base = elastic_url.replace(":9200", ":5601").replace("https://", "http://").replace("https://", "http://")
    url = f"{kibana_base}/api/detection_engine/rules"

    headers = {
        "Authorization": f"ApiKey {api_key}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }

    response = requests.post(url, headers=headers, json=kibana_rule, verify=False)

    if response.status_code in [200, 201]:
        print(f"SUCCESS: Deployed '{metadata.get('title')}' to Kibana")
    elif response.status_code == 409:
        rule_id = metadata.get("id", "")
        put_url = f"{url}?rule_id={rule_id}&overwrite=true"
        response = requests.put(put_url, headers=headers, json=kibana_rule, verify=False)
        if response.status_code in [200, 201]:
            print(f"SUCCESS: Updated '{metadata.get('title')}' in Kibana")
        else:
            print(f"FAIL: Could not update rule: {response.status_code} {response.text}")
            sys.exit(1)
    else:
        print(f"FAIL: Deployment failed with status {response.status_code}: {response.text}")
        sys.exit(1)


if __name__ == "__main__":
    deploy_to_kibana(sys.argv[1])
