# import json
# from typing import List, Dict, Any

# class SARIFReporter:
#     def generate_report(self, findings: List[Dict[str, Any]], codebase_path: str) -> str:
#         results = []
#         for finding in findings:
#             results.append({
#                 "ruleId": finding["rule_id"],
#                 "level": finding["severity"],
#                 "message": {"text": finding["description"]},
#                 "locations": [{
#                     "physicalLocation": {
#                         "artifactLocation": {
#                             "uri": finding["file"].replace(codebase_path, "").lstrip("/")
#                         },
#                         "region": {
#                             "startLine": finding["line"]
#                         }
#                     }
#                 }],
#                 "codeFlows": [{
#                     "threadFlows": [{
#                         "locations": [
#                             {
#                                 "location": {
#                                     "physicalLocation": {
#                                         "artifactLocation": {
#                                             "uri": step["file"].replace(codebase_path, "").lstrip("/")
#                                         },
#                                         "region": {
#                                             "startLine": step["line"]
#                                         }
#                                     }
#                                 }
#                             } for step in finding["dataflow"]
#                         ]
#                     }]
#                 }]
#             })

#         return json.dumps({
#             "version": "2.1.0",
#             "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
#             "runs": [{
#                 "tool": {
#                     "driver": {
#                         "name": "Custom SAST",
#                         "version": "1.0.0"
#                     }
#                 },
#                 "results": results
#             }]
#         }, indent=2)



# reporter.py (enhanced SARIF output)
import json
from typing import List, Dict, Any

class SARIFReporter:
    def generate_report(self, findings: List[Dict[str, Any]], codebase_path: str) -> str:
        results = []
        
        for finding in findings:
            results.append({
                "ruleId": finding["rule_id"],
                "level": finding["severity"].lower(),
                "message": {
                    "text": f"{finding['description']} (Found in: {finding['code_snippet'].strip()})"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding["file"].replace(codebase_path, "").lstrip("/")
                        },
                        "region": {
                            "startLine": finding["line"],
                            "snippet": {"text": finding["code_snippet"].strip()}
                        }
                    }
                }],
                "codeFlows": [{
                    "threadFlows": [{
                        "locations": [
                            self._create_location(step) 
                            for step in finding["dataflow"]
                        ]
                    }]
                }],
                "properties": {
                    "sanitizersUsed": finding["sanitizers"] or "None"
                }
            })
            
        return json.dumps({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Advanced SAST Scanner",
                        "version": "1.1",
                        "rules": self._create_rules_metadata()
                    }
                },
                "results": results
            }]
        }, indent=2)

    def _create_location(self, step):
        return {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": step["file"]},
                    "region": {
                        "startLine": step["line"],
                        "snippet": {"text": step["code"].strip()}
                    }
                },
                "message": {"text": step["description"]}
            }
        }

    def _create_rules_metadata(self):
        return [{
            "id": "SQLI-001",
            "name": "SQL Injection",
            "shortDescription": {"text": "Untrusted data used in SQL query"},
            "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection"
        }, {
            "id": "XSS-001",
            "name": "Cross-site Scripting",
            "shortDescription": {"text": "Untrusted data rendered in HTML output"},
            "helpUri": "https://owasp.org/www-community/attacks/xss/"
        }]