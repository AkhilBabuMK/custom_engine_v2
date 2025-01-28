
# from typing import List, Dict, Any

# class TaintAnalyzer:
#     def __init__(self, symbol_table: Dict, data_flows: List[Dict]):
#         self.symbol_table = symbol_table
#         self.data_flows = data_flows

#     def analyze(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
#         findings = []
#         print(f"Symbol Table: {self.symbol_table}")  # Debug
#         print(f"Data Flows: {self.data_flows}")  # Debug

#         for rule in rules:
#             print(f"Processing rule: {rule['id']}")  # Debug
#             for flow in self.data_flows:
#                 print(f"Checking flow: {flow['function']} against rule: {rule['sinks']}")  # Debug
#                 if self._matches_rule(flow, rule):
#                     findings.append({
#                         "rule_id": rule["id"],
#                         "description": rule["description"],
#                         "severity": rule["severity"],
#                         "file": flow["file"],
#                         "line": flow["line"],
#                         "dataflow": self._get_dataflow(flow),
#                     })
#         return findings

#     def _matches_rule(self, flow: Dict, rule: Dict) -> bool:
#         return flow["function"] in rule["sinks"]

#     def _get_dataflow(self, flow: Dict) -> List[Dict]:
#         return [{
#             "file": flow["file"],
#             "line": flow["line"],
#             "description": f"Data flows to {flow['function']}",
#         }]

# analyzer.py
# from typing import List, Dict, Any

# class TaintAnalyzer:
#     def __init__(self, tainted_vars: Dict, data_flows: List[Dict]):
#         self.tainted_vars = tainted_vars
#         self.data_flows = data_flows

#     def analyze(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
#         findings = []
        
#         for flow in self.data_flows:
#             rule = self._find_matching_rule(flow, rules)
#             if not rule:
#                 continue
                
#             for tainted_var in flow['tainted_vars']:
#                 var_info = self.tainted_vars.get(tainted_var)
#                 if not var_info:
#                     continue
                    
#                 if not self._is_properly_sanitized(var_info, rule):
#                     findings.append(self._create_finding(flow, var_info, rule))
                    
#         return findings

#     def _find_matching_rule(self, flow, rules):
#         for rule in rules:
#             if flow['type'] == 'sql' and 'sqli' in rule['id'].lower():
#                 return rule
#             if flow['type'] == 'xss' and 'xss' in rule['id'].lower():
#                 return rule
#         return None

#     def _is_properly_sanitized(self, var_info, rule):
#         required_sanitizers = set(rule.get('sanitizers', []))
#         applied_sanitizers = var_info['sanitizers']
#         return required_sanitizers.issubset(applied_sanitizers)

#     def _create_finding(self, flow, var_info, rule):
#         return {
#             "rule_id": rule["id"],
#             "description": rule["description"],
#             "severity": rule["severity"],
#             "file": flow["file"],
#             "line": flow["line"],
#             "code_snippet": flow["code"],
#             "dataflow": [
#                 {
#                     "file": loc["file"],
#                     "line": loc["line"],
#                     "description": f"Tainted variable '{var}' originated here",
#                     "code": loc["code"]
#                 } for loc in var_info['locations']
#             ],
#             "sanitizers": list(var_info['sanitizers'])
#         }


# analyzer.py (updated)
# analyzer.py
from typing import List, Dict, Any

# class TaintAnalyzer:
#     def __init__(self, tainted_vars: Dict, data_flows: List[Dict]):
#         self.tainted_vars = tainted_vars
#         self.data_flows = data_flows

#     def analyze(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
#         findings = []
        
#         for flow in self.data_flows:
#             rule = self._find_matching_rule(flow, rules)
#             if not rule:
#                 continue
                
#             for var in flow['tainted_vars']:
#                 var_info = self.tainted_vars.get(var)
#                 if not var_info or self._is_properly_sanitized(var_info, rule):
#                     continue
                    
#                 findings.append({
#                     "rule_id": rule["id"],
#                     "description": f"{rule['description']} - Found '{var}' in {flow['sink']}",
#                     "severity": rule["severity"],
#                     "file": flow["file"],
#                     "line": flow["line"],
#                     "code_snippet": flow["code"],
#                     "dataflow": var_info['locations'],
#                     "sanitizers": list(var_info['sanitizers'])
#                 })
                    
#         return findings

#     def _find_matching_rule(self, flow, rules):
#         for rule in rules:
#             if flow['type'] == 'sql' and 'sqli' in rule['id'].lower():
#                 if flow['sink'] in rule.get('sinks', []):
#                     return rule
#             elif flow['type'] == 'xss' and 'xss' in rule['id'].lower():
#                 if flow['sink'] in rule.get('sinks', []):
#                     return rule
#         return None

#     def _is_properly_sanitized(self, var_info, rule):
#         required = set(rule.get('sanitizers', []))
#         applied = var_info['sanitizers']
#         return required.issubset(applied)

class TaintAnalyzer:
    def __init__(self, tainted_vars: Dict, data_flows: List[Dict]):
        self.tainted_vars = tainted_vars
        self.data_flows = data_flows

    def analyze(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match data flows against security rules"""
        findings = []
        
        for flow in self.data_flows:
            # Check if any rule matches this data flow
            for rule in rules:
                if self._matches_rule(flow, rule):
                    findings.append(flow)
                    break  
        return findings

    def _matches_rule(self, flow: Dict, rule: Dict) -> bool:
        """Check if a data flow matches a security rule"""
        # Check source match
        source_match = any(
            any(source in var_source for source in rule['sources'])
            for var in flow.get('tainted_vars', [])
            for var_source in self.tainted_vars.get(var, {}).get('sources', [])
        )
        
        # Check sink match
        sink_match = any(sink in flow.get('sink', '') for sink in rule['sinks'])
        
        # Check sanitization
        sanitized = len(flow.get('sanitizers', [])) > 0
        
        return source_match and sink_match and not sanitized