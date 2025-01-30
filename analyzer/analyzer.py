
import re
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class TaintAnalyzer:
    def __init__(self, tainted_vars: Dict, data_flows: List[Dict]):
        self.tainted_vars = tainted_vars
        self.data_flows = data_flows
        self.call_graph = {}  # Format: {caller: [callees]}
        self.function_args = {}  # Format: {function_name: [arg_names]}

    def analyze(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhanced analysis with interprocedural tracking"""
        self._build_call_graph()
        self._analyze_function_args()
        
        validated_flows = []
        for flow in self.data_flows:
            if self._is_valid_flow(flow, rules):
                validated_flows.append(self._enrich_flow(flow, rules))
        
        return validated_flows

    def _build_call_graph(self):
        """Stub for call graph analysis - integrate with AST parsing later"""
        # Example structure:
        self.call_graph = {
            'main': ['vulnerable_function', 'safe_function'],
            'vulnerable_function': ['execute_query']
        }

    def _analyze_function_args(self):
        """Stub for argument analysis - integrate with AST parsing later"""
        # Example structure:
        self.function_args = {
            'execute_query': ['query'],
            'render_template': ['content']
        }

    def _is_valid_flow(self, flow: Dict, rules: List[Dict]) -> bool:
        """Check if flow is unsanitized and matches any rule"""
        if self._is_sanitized(flow):
            logger.debug(f"Flow sanitized: {flow['description']}")
            return False
        return self._matches_any_rule(flow, rules)

    def _is_sanitized(self, flow: Dict) -> bool:
        """Check if any tainted variables were sanitized"""
        return any(
            len(self.tainted_vars[var].get('sanitizers', [])) > 0
            for var in flow.get('tainted_vars', [])
        )

    def _matches_any_rule(self, flow: Dict, rules: List[Dict]) -> bool:
        """Match flow against all relevant rules"""
        return any(
            self._matches_rule(flow, rule)
            for rule in rules
            if self._is_relevant_rule(flow, rule)
        )

    def _is_relevant_rule(self, flow: Dict, rule: Dict) -> bool:
        """Check if rule matches vulnerability type and context"""
        rule_type = rule['id'].split('-')[0].lower()
        return rule_type == flow['type']

    def _matches_rule(self, flow: Dict, rule: Dict) -> bool:
        """Detailed rule matching with context awareness"""
        source_match = any(
            any(source in var_sources for source in rule['sources'])
            for var in flow['tainted_vars']
            for var_sources in self.tainted_vars[var]['sources']
        )

        sink_match = any(
            sink in flow['sink'] for sink in rule['sinks']
        )

        context_match = True
        if 'XSS' in rule['id']:
            context_match = self._check_xss_context(flow)
        elif 'SQL' in rule['id']:
            context_match = self._check_sqli_context(flow)

        return source_match and sink_match and context_match

    def _check_xss_context(self, flow: Dict) -> bool:
        """Verify XSS-specific context patterns"""
        return any(
            keyword in flow['code']
            for keyword in ['<script>', 'onload=', 'javascript:']
        )

    def _check_sqli_context(self, flow: Dict) -> bool:
        """Verify SQLi-specific context patterns"""
        return any(
            keyword in flow['code']
            for keyword in ['SELECT', 'INSERT', 'DELETE']
        )

    def _enrich_flow(self, flow: Dict, rules: List[Dict]) -> Dict:
        """Add rule metadata to findings"""
        matched_rule = next(
            (r for r in rules if self._matches_rule(flow, r)),
            None
        )
        
        if matched_rule:
            flow.update({
                'rule_id': matched_rule['id'],
                'severity': matched_rule['severity'],
                'rule_description': matched_rule['description']
            })
        return flow

    def _propagate_taint(self, function_name: str):
        """Propagate taint through function calls (stub implementation)"""
        # Example: If function 'render' is called with tainted argument 'content'
        # and its parameter is 'input', mark 'input' as tainted in 'render'
        if function_name in self.function_args:
            logger.debug(f"Propagating taint to {function_name} arguments")