import os
import yaml
from tree_sitter import Parser, Language
from typing import Dict, List, Any
from tree_sitter import Parser, Language
from typing import Dict, List, Any, Set
import re

import logging
logger = logging.getLogger(__name__)


class ASTIndexer:

    def __init__(self):
            self.tainted_vars = {}
            self.data_flows = []
            self._init_parser()
            self.current_file = ""
            self.all_sources = []
            self.all_sinks = []
            self.all_sanitizers = []
            self.sql_sinks = [
                'execute', 'executemany', 'cursor.execute',
                'sqlalchemy.text', 'raw', 'django.db.connection.cursor'
            ]

    def _init_parser(self):
        try:
            language_path = os.path.join(os.path.expanduser("~/.tree-sitter/parsers"), "python.so")
            self.parser = Parser()
            self.language = Language(language_path, "python")
            self.parser.set_language(self.language)
        except Exception as e:
            raise RuntimeError(f"Parser init failed: {str(e)}")


    def index_project(self, path: str):
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".py"):
                    self.current_file = os.path.join(root, file)
                    self._index_file(self.current_file)


    def _index_file(self, file_path: str):
        with open(file_path, "r") as f:
            code = f.read()
            tree = self.parser.parse(bytes(code, "utf8"))
            self._analyze_ast(tree.root_node, code, file_path)

    def _check_tainted_usage(self, node, code: str):
        """Check if a tainted variable is used in a vulnerable sink context"""
        current_node = node
        # Traverse up the AST to find relevant sink contexts
        while current_node.parent is not None:
            current_node = current_node.parent
            if current_node.type == 'call':
                func_name = self._get_function_name(current_node)
                # Check for SQL sinks
                if func_name in ['execute', 'executemany', 'cursor.execute']:
                    print(f"DEBUG: Tainted variable used in SQL sink: {func_name}")
                    self._track_sql_sink(current_node, code)
                    break
                # Check for XSS sinks
                elif func_name in ['render_template_string', 'Response', 'HTML']:
                    print(f"DEBUG: Tainted variable used in XSS sink: {func_name}")
                    self._track_xss_sink(current_node, code)
                    break
            # Check if the variable is part of a return statement (potential XSS)
            elif current_node.type == 'return_statement':
                print("DEBUG: Tainted variable used in return statement")
                self._track_xss_sink(current_node, code)
                break

    def _analyze_ast(self, node, code: str, file_path: str):
        # Enhanced source detection
        if node.type == 'call':
            full_name = self._get_function_name(node)
            
            # Check against all rule-defined sources
            if any(src in full_name for src in self.all_sources):
                if var_name := self._get_assigned_variable(node.parent):
                    self._mark_tainted(var_name, node, code)
                    logger.debug(f"Marked {var_name} as tainted via source {full_name}")

            # Check against all rule-defined sinks
            if any(sink in full_name for sink in self.all_sinks):
                self._check_sink_usage(node, code)

            # Check for sanitizers
            if full_name in self.all_sanitizers:
                if var_name := self._get_assigned_variable(node.parent):
                    self.tainted_vars[var_name]['sanitized'] = True
                    logger.debug(f"Marked {var_name} as sanitized by {full_name}")

        # Enhanced XSS detection
        elif node.type == 'return_statement':
            self._track_xss_sink(node, code)

        # SQL pattern detection
        elif node.type == 'string':
            if self._detect_sqli_patterns(node.text.decode()):
                self._report_vulnerability(node, code, 'sql')

        # Dangerous string concatenation
        elif node.type == 'binary_operator' and node.text.decode() == '+':
            if self._contains_tainted_data(node):
                logger.debug(f"Tainted data in concatenation at line {node.start_point[0]+1}")

        # Dictionary-style source access
        elif node.type == 'subscript':
            base = node.child_by_field_name('value')
            if base and base.text.decode() in self.all_sources:
                if var_name := self._get_assigned_variable(node.parent):
                    self._mark_tainted(var_name, node, code)
                    logger.debug(f"Marked {var_name} as tainted via subscript")

        # Recursive analysis
        for child in node.children:
            self._analyze_ast(child, code, file_path)

    def _is_xss_sink(self, node, code: str) -> bool:
        """Detect XSS sinks including template strings and HTML output"""
        if node.type == 'return_statement':
            expr = node.child_by_field_name('expression')
            if expr and any(self._contains_tainted_vars(expr.text.decode())):
                return True
        
        if node.type == 'call_expression':
            func_name = self._get_function_name(node)
            return func_name in ['render_template_string', 'Response', 'HTML']
        
        return False

    def _track_sql_sink(self, node, code: str):
        """Enhanced SQLi detection with pattern matching"""
        func_name = self._get_function_name(node)
        if any(sql_sink in func_name for sql_sink in self.sql_sinks):
            args = self._get_call_arguments(node)
            for arg in args:
                if self._contains_tainted_data(arg):
                    query = arg.text.decode()
                    if self._detect_sqli_patterns(query):
                        self.data_flows.append({
                            'type': 'sql',
                            'sink': func_name,
                            'file': self.current_file,
                            'line': node.start_point[0] + 1,
                            'code': code.split('\n')[node.start_point[0]],
                            'tainted_vars': [var for var in self.tainted_vars if var in query],
                            'description': 'Potential SQL injection detected'
                        })

    def _detect_sqli_patterns(self, query: str) -> bool:
        """Heuristic SQLi detection"""
        patterns = [
            r"\b(union|select|insert|update|delete|drop|alter)\b",
            r"--", r";\s*$", r"\d+\s*=\s*\d+"
        ]
        return any(re.search(p, query, re.IGNORECASE) for p in patterns)

    def _track_xss_sink(self, node, code: str):
        """Context-aware XSS detection"""
        try:
            content = None
            if node.type == 'call':
                func_name = self._get_function_name(node)
                args = self._get_call_arguments(node)
                content = ' '.join([arg.text.decode() for arg in args])
            elif node.type == 'return_statement':
                expr = node.child_by_field_name('expression')
                content = expr.text.decode() if expr else ''

            if content and self._detect_xss_context(content):
                tainted_vars = [var for var in self.tainted_vars if var in content]
                if tainted_vars:
                    self.data_flows.append({
                        'type': 'xss',
                        'sink': self._get_function_name(node),
                        'file': self.current_file,
                        'line': node.start_point[0] + 1,
                        'code': code.split('\n')[node.start_point[0]],
                        'tainted_vars': tainted_vars,
                        'description': 'Potential XSS detected in dangerous context'
                    })

        except Exception as e:
            logger.error(f"XSS tracking error: {str(e)}")

    def _detect_xss_context(self, code: str) -> bool:
        """Identify dangerous HTML patterns"""
        patterns = [
            r"<script[^>]*>.*\{.*\}",
            r"on\w+=",
            r"javascript:",
            r"url\([^)]*\{.*\}",
            r"<\w+[^>]*\{.*\}[^>]*>"
        ]
        return any(re.search(p, code) for p in patterns)

    def _analyze_return_statement(self, node, code: str):
        """Analyze return statements with null safety"""
        expr = node.child_by_field_name('expression')
        if expr is None:
            print("DEBUG: Return statement has no expression")
            return
            
        if self._contains_tainted_data(expr):
            print("DEBUG: Found tainted data in return statement")
            self._track_xss_sink(node, code)
    def _track_sanitizer(self, node, code: str):
        if var_name := self._get_assigned_variable(node.parent):
            sanitizer = self._get_function_name(node)
            self.tainted_vars[var_name]['sanitizers'].add(sanitizer)
            print(f"Applied sanitizer {sanitizer} to {var_name}")  # Debug
   

    def _check_sink_usage(self, node, code: str):
        """Analyze sink usage for potential vulnerabilities"""
        args = self._get_call_arguments(node)
        for arg in args:
            if self._contains_tainted_data(arg):
                print(f"DEBUG: Found tainted data in sink usage: {arg}")
                self._report_vulnerability(node, code)

    def _analyze_return_statement(self, node, code: str):
        """Analyze return statements for potential XSS"""
        expr = node.child_by_field_name('expression')
        if expr and self._contains_tainted_data(expr):
            print(f"DEBUG: Found tainted data in return statement")
            self._report_vulnerability(node, code, vulnerability_type='xss')

    def _contains_tainted_data(self, node) -> bool:
        """Check if an AST node contains any tainted variables (including inside f-strings)"""
        if node.type == 'identifier':
            var_name = node.text.decode()
            return var_name in self.tainted_vars and not self.tainted_vars[var_name].get('sanitized', False)
        
        if node.type == 'string' and 'f' in node.text.decode():
            for child in node.children:
                if child.type == 'interpolation' and self._contains_tainted_data(child):
                    return True
        
        if hasattr(node, 'children'):
            return any(self._contains_tainted_data(child) for child in node.children)
        
        return False

    def _get_call_arguments(self, node):
        """Extract arguments from a call expression"""
        args = []
        args_node = node.child_by_field_name('arguments')
        if args_node:
            for child in args_node.children:
                if child.type not in ('(', ')', ','):
                    args.append(child)
        return args

    def _report_vulnerability(self, node, code: str, vulnerability_type='generic'):
        """Enhanced vulnerability reporting"""
        desc_map = {
            'sql': 'Untrusted input in SQL execution',
            'xss': 'Unsanitized user input in HTML output'
        }
        
        self.data_flows.append({
            'type': vulnerability_type,
            'file': self.current_file,
            'line': node.start_point[0] + 1,
            'code': code.split('\n')[node.start_point[0]],
            'description': desc_map.get(vulnerability_type, 'Potential vulnerability detected'),
            'sink': self._get_function_name(node),
            'tainted_vars': [var for var in self.tainted_vars if not self.tainted_vars[var].get('sanitized', False)]
        })
        logger.debug(f"Reported {vulnerability_type} vulnerability at line {node.start_point[0] + 1}")

#-----------------
    def _get_function_name(self, node):
        """Resolve complex call chains like 'db.connection.cursor().execute'"""
        parts = []
        current = node
        
        while current and current.type in ('attribute', 'call', 'identifier'):
            if current.type == 'attribute':
                attr_node = current.child_by_field_name('attribute')
                if attr_node:
                    parts.insert(0, attr_node.text.decode())
                current = current.child_by_field_name('object')
            elif current.type == 'identifier':
                parts.insert(0, current.text.decode())
                break
            else:
                current = current.child_by_field_name('function') if current.type == 'call' else None
        
        return '.'.join(parts)
        
    def _mark_tainted(self, var_name: str, node, code: str):
        print(f"Marking {var_name} as tainted at line {node.start_point[0] + 1}")
        if var_name not in self.tainted_vars:
            self.tainted_vars[var_name] = {
                'sources': set(['user_input']),
                'sanitizers': set(),
                'locations': []
            }
        self.tainted_vars[var_name]['locations'].append({
            'file': self.current_file,
            'line': node.start_point[0] + 1,
            'code': code.split('\n')[node.start_point[0]]
        })

    def _get_assigned_variable(self, node):
        """Get assigned variable name from assignment node"""
        if node and node.type == 'assignment':
            left_node = node.child_by_field_name('left')
            if left_node and left_node.type == 'identifier':
                return left_node.text.decode()
        return None


    def load_rules(self, rules_path: str) -> List[Dict[str, Any]]:
        """Enhanced rule loading with metadata extraction"""
        try:
            with open(rules_path, "r") as f:
                rules_data = yaml.safe_load(f)
                if not rules_data or 'rules' not in rules_data:
                    return []

                processed_rules = []
                for rule in rules_data['rules']:
                    if self._validate_rule(rule):
                        processed_rules.append(rule)
                
                # Populate detection lists
                self.all_sources = list({src for r in processed_rules for src in r['sources']})
                self.all_sinks = list({sink for r in processed_rules for sink in r['sinks']})
                self.all_sanitizers = list({san for r in processed_rules for san in r['sanitizers']})

                return processed_rules
        except Exception as e:
            logger.error(f"Rule loading failed: {str(e)}")
            return []

    def _validate_rule(self, rule: Dict[str, Any]) -> bool:
        """Validate that a rule has all required fields"""
        required_fields = ['id', 'description', 'severity', 'sources', 'sinks']
        return all(field in rule for field in required_fields)

    def _print_node_structure(self, node, indent=0):
        """Helper method to print the full structure of a node"""
        prefix = ' ' * indent
        print(f"{prefix}Type: {node.type}")
        print(f"{prefix}Text: {node.text.decode() if node.text else 'None'}")
        
        # Print fields
        for field in node.fields:
            field_value = node.child_by_field_name(field)
            if field_value:
                print(f"{prefix}Field {field}:")
                self._print_node_structure(field_value, indent + 2)
        
        # Print children
        for child in node.children:
            if child not in [node.child_by_field_name(f) for f in node.fields]:
                print(f"{prefix}Child:")
                self._print_node_structure(child, indent + 2)

    def generate_sarif_findings(self, codebase_path: str) -> List[Dict[str, Any]]:
        """Convert internal data flows to SARIF-compatible findings"""
        findings = []
        
        for flow in self.data_flows:
            # Determine rule metadata based on vulnerability type
            rule_id = "SQLI-001" if flow['type'] == 'sql' else "XSS-001"
            severity = "high"
            
            finding = {
                "rule_id": rule_id,
                "severity": severity,
                "description": flow.get('description', 'Potential security vulnerability'),
                "file": flow['file'],
                "line": flow['line'],
                "code_snippet": flow['code'],
                "dataflow": self._create_dataflow_steps(flow),
                "sanitizers": list(set(
                    sanitizer 
                    for var in flow.get('tainted_vars', []) 
                    for sanitizer in self.tainted_vars.get(var, {}).get('sanitizers', [])
                ))
            }
            
            findings.append(finding)
        
        return findings

    def _create_dataflow_steps(self, flow) -> List[Dict[str, Any]]:
        """Create dataflow steps for SARIF codeFlows section"""
        steps = []
        
        # Add source steps
        for var in flow.get('tainted_vars', []):
            if var in self.tainted_vars:
                for loc in self.tainted_vars[var]['locations']:
                    steps.append({
                        "file": loc['file'],
                        "line": loc['line'],
                        "code": loc['code'],
                        "description": f"Tainted variable '{var}' created from user input"
                    })
        
        # Add sink step
        steps.append({
            "file": flow['file'],
            "line": flow['line'],
            "code": flow['code'],
            "description": f"Potential {flow['type'].upper()} sink: {flow.get('sink', 'unknown')}"
        })
        
        return steps

