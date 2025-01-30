# # reporter.py (enhanced SARIF output)
# import json
# from typing import List, Dict, Any

# class SARIFReporter:
#     def generate_report(self, findings: List[Dict[str, Any]], codebase_path: str) -> str:
#         results = []
        
#         for finding in findings:
#             results.append({
#                 "ruleId": finding["rule_id"],
#                 "level": finding["severity"].lower(),
#                 "message": {
#                     "text": f"{finding['description']} (Found in: {finding['code_snippet'].strip()})"
#                 },
#                 "locations": [{
#                     "physicalLocation": {
#                         "artifactLocation": {
#                             "uri": finding["file"].replace(codebase_path, "").lstrip("/")
#                         },
#                         "region": {
#                             "startLine": finding["line"],
#                             "snippet": {"text": finding["code_snippet"].strip()}
#                         }
#                     }
#                 }],
#                 "codeFlows": [{
#                     "threadFlows": [{
#                         "locations": [
#                             self._create_location(step) 
#                             for step in finding["dataflow"]
#                         ]
#                     }]
#                 }],
#                 "properties": {
#                     "sanitizersUsed": finding["sanitizers"] or "None"
#                 }
#             })
            
#         return json.dumps({
#             "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
#             "version": "2.1.0",
#             "runs": [{
#                 "tool": {
#                     "driver": {
#                         "name": "Advanced SAST Scanner",
#                         "version": "1.1",
#                         "rules": self._create_rules_metadata()
#                     }
#                 },
#                 "results": results
#             }]
#         }, indent=2)

#     def _create_location(self, step):
#         return {
#             "location": {
#                 "physicalLocation": {
#                     "artifactLocation": {"uri": step["file"]},
#                     "region": {
#                         "startLine": step["line"],
#                         "snippet": {"text": step["code"].strip()}
#                     }
#                 },
#                 "message": {"text": step["description"]}
#             }
#         }

#     def _create_rules_metadata(self):
#         return [{
#             "id": "SQLI-001",
#             "name": "SQL Injection",
#             "shortDescription": {"text": "Untrusted data used in SQL query"},
#             "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection"
#         }, {
#             "id": "XSS-001",
#             "name": "Cross-site Scripting",
#             "shortDescription": {"text": "Untrusted data rendered in HTML output"},
#             "helpUri": "https://owasp.org/www-community/attacks/xss/"
#         }]


import json
import logging
logger = logging.getLogger(__name__)


import re
from typing import List, Dict, Any

class SARIFReporter:
    def generate_report(self, findings: List[Dict[str, Any]], codebase_path: str, rules: List[Dict]) -> str:
        """Generate SARIF report with dynamic rule metadata"""
        return json.dumps({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Advanced SAST Scanner",
                        "version": "1.2",
                        "rules": self._create_rule_metadata(rules)
                    }
                },
                "results": [
                    self._create_result(finding, codebase_path)
                    for finding in findings
                ]
            }]
        }, indent=2)

    def _create_rule_metadata(self, rules: List[Dict]) -> List[Dict]:
        """Convert YAML rules to SARIF rule format"""
        return [{
            "id": rule['id'],
            "name": rule['description'],
            "shortDescription": {
                "text": rule['description']
            },
            "fullDescription": {
                "text": f"{rule['description']}. Detects {len(rule['sources'])} sources and {len(rule['sinks'])} sinks."
            },
            "helpUri": f"https://security-rules.info/{rule['id']}",
            "properties": {
                "category": "security",
                "precision": "high",
                "tags": [rule['id'].split('-')[0].upper()]
            }
        } for rule in rules]

    def _create_result(self, finding: Dict, codebase_path: str) -> Dict:
        """Create SARIF result entry with data flow"""
        print(finding)
        return {
            
            "ruleId": finding.get('rule_id', 'GENERIC-001'),
            "level": finding.get('severity', 'warning').lower(),
            "message": {
                "text": f"{finding.get('description', 'Potential vulnerability')} ({finding.get('rule_description', '')})"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": self._relative_path(finding['file'], codebase_path)
                    },
                    "region": {
                        "startLine": finding['line'],
                        "snippet": {
                            "text": finding['code_snippet']
                        }
                    }
                }
            }],
            "codeFlows": [{
                "threadFlows": [{
                    "locations": [
                        self._create_location(step)
                        for step in finding.get('dataflow', [])
                    ]
                }]
            }],
            "properties": {
                "sanitizers": finding.get('sanitizers', []),
                "sources": list(set(
                    src for var in finding.get('tainted_vars', [])
                    for src in var.get('sources', [])
                ))
            }
        }

    def _relative_path(self, absolute_path: str, base_path: str) -> str:
        """Convert absolute path to relative for SARIF reporting"""
        return absolute_path.replace(base_path, '').lstrip('/')

    def _create_location(self, step: Dict) -> Dict:
        """Create SARIF location entry"""
        return {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": step['file']},
                    "region": {
                        "startLine": step['line'],
                        "snippet": {"text": step['code']}
                    }
                },
                "message": {
                    "text": step['description']
                }
            }
        }