import os
import yaml
from tree_sitter import Parser, Language
from typing import Dict, List, Any
from tree_sitter import Parser, Language
from typing import Dict, List, Any, Set

class ASTIndexer:
    def __init__(self):
        self.tainted_vars = {}
        self.data_flows = []
        self._init_parser()
        self.current_file = ""

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

    # def _analyze_ast(self, node, code: str, file_path: str):
    #     print("printing the node type inside the function _analyse_ast:", node.type)
    #     # Track user input sources
    #     if node.type == 'call_expression':
            
    #         func_name = self._get_function_name(node)
    #         print(func_name)
    #         if func_name in ['request.args.get', 'request.form.get']:
    #             if var_name := self._get_assigned_variable(node.parent):
    #                 self._mark_tainted(var_name, node, code)
    #                 print(f"Marked tainted: {var_name}")  # Debug

    #     # Track SQL sinks
    #     if node.type == 'call_expression':
    #         func_name = self._get_function_name(node)
    #         print(func_name)
    #         if func_name in ['execute', 'executemany', 'cursor.execute']:
    #             print(f"Found SQL sink: {func_name}")  # Debug
    #             self._track_sql_sink(node, code)

    #     # Track XSS sinks
    #     if self._is_xss_sink(node, code):
    #         print(f"Found XSS sink")  # Debug
    #         self._track_xss_sink(node, code)

    #     # Track sanitizers
    #     if node.type == 'call_expression':
    #         func_name = self._get_function_name(node)
    #         if func_name in ['escape_string', 'html.escape', 'markupsafe.escape']:
    #             self._track_sanitizer(node, code)

    #     for child in node.children:
    #         self._analyze_ast(child, code, file_path)
    def _analyze_ast(self, node, code: str, file_path: str):
    # Debug logging for function calls
        if node.type == 'call':
            full_name = self._get_function_name(node)
            print(f"DEBUG: Found function call: {full_name}")
            
            # Check for source patterns (e.g., request.args.get)
            if any(source in full_name for source in ['request.args', 'request.form', 'request.values']):
                print(f"DEBUG: Found source pattern: {full_name}")
                if var_name := self._get_assigned_variable(node.parent):
                    self._mark_tainted(var_name, node, code)
                    print(f"DEBUG: Marked variable as tainted: {var_name}")
            
            # Check for sink patterns
            if any(sink in full_name for sink in ['execute', 'html', 'render_template']):
                print(f"DEBUG: Found sink pattern: {full_name}")
                self._check_sink_usage(node, code)
        
        # Check for variable usage
        elif node.type == 'identifier':
            var_name = node.text.decode()
            if var_name in self.tainted_vars:
                print(f"DEBUG: Found usage of tainted variable: {var_name}")
                self._check_tainted_usage(node, code)
        
        # Add specific checks for return statements that might contain tainted data
        elif node.type == 'return_statement':
            print(f"DEBUG: Analyzing return statement")
            self._analyze_return_statement(node, code)
        
        # Traverse child nodes
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
        args_node = node.child_by_field_name('arguments')
        if args_node and args_node.named_children:
            query_node = args_node.named_children[0]
            query_text = query_node.text.decode()
            tainted_vars = [var for var in self.tainted_vars if var in query_text]
            if tainted_vars:
                print(f"Found SQL injection vector: {tainted_vars}")  # Debug
                self.data_flows.append({
                    'type': 'sql',
                    'sink': 'execute',
                    'file': self.current_file,
                    'line': node.start_point[0] + 1,
                    'code': code.split('\n')[node.start_point[0]],
                    'tainted_vars': tainted_vars
                })

    # def _track_xss_sink(self, node, code: str):
    #     if node.type == 'return_statement':
    #         expr = node.child_by_field_name('expression')
    #         content = expr.text.decode()
    #         tainted_vars = [var for var in self.tainted_vars if var in content]
    #         if tainted_vars:
    #             print(f"Found XSS vector: {tainted_vars}")  # Debug
    #             self.data_flows.append({
    #                 'type': 'xss',
    #                 'sink': 'html_output',
    #                 'file': self.current_file,
    #                 'line': node.start_point[0] + 1,
    #                 'code': code.split('\n')[node.start_point[0]],
    #                 'tainted_vars': tainted_vars
    #             })
    def _track_xss_sink(self, node, code: str):
        """Handle XSS sinks with null checks"""
        try:
            if node.type == 'return_statement':
                expr = node.child_by_field_name('expression')
                # Add null check for expression
                if expr is None:
                    print("DEBUG: Return statement has no expression")
                    return
                    
                content = expr.text.decode()  # Now safe
                tainted_vars = [var for var in self.tainted_vars if var in content]
                
                if tainted_vars:
                    print(f"Found XSS vector: {tainted_vars}")
                    self.data_flows.append({
                        'type': 'xss',
                        'sink': 'html_output',
                        'file': self.current_file,
                        'line': node.start_point[0] + 1,
                        'code': code.split('\n')[node.start_point[0]],
                        'tainted_vars': tainted_vars
                    })
                    
        except AttributeError as e:
            print(f"WARNING: Failed to process XSS sink: {str(e)}")

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

    
    # def _get_function_name(self, node):
    #     """Get simple function name from call expression"""
    #     if node.type == 'call_expression':
    #         func_node = node.child_by_field_name('function')
    #         if func_node.type == 'identifier':
    #             return func_node.text.decode()
    #         if func_node.type == 'attribute':
    #             return func_node.child_by_field_name('attribute').text.decode()
    #     return ''
  #----------------   
   

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
        """Check if an AST node contains any tainted variables"""
        if node.type == 'identifier':
            var_name = node.text.decode()
            return var_name in self.tainted_vars
        elif hasattr(node, 'children'):
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
        desc_map = {
        'sql': 'Untrusted input in SQL execution',
        'xss': 'Unsanitized user input in HTML output'
        }
        
        """Report a detected vulnerability"""
        self.data_flows.append({
            'type': vulnerability_type,
            'file': self.current_file,
            'line': node.start_point[0] + 1,
            'code': code.split('\n')[node.start_point[0]],
            'description': f"Potential {vulnerability_type} vulnerability detected",
            'sink': self._get_function_name(node),
            'tainted_vars': list(self.tainted_vars.keys())
        })
        print(f"DEBUG: Reported {vulnerability_type} vulnerability at line {node.start_point[0] + 1}")
#-----------------
 
    def _get_function_name(self, node):
        """Get full function name including chain of attributes"""
        print(f"DEBUG: Analyzing node type: {node.type}")
        
        if node.type == 'call':
            func_node = node.child_by_field_name('function')
            print(f"DEBUG: Function node type: {func_node.type if func_node else 'None'}")
            
            if not func_node:
                return ''
                
            # Handle different types of function calls
            if func_node.type == 'identifier':
                name = func_node.text.decode()
                print(f"DEBUG: Found simple function name: {name}")
                return name
                
            elif func_node.type == 'attribute':
                parts = []
                current = func_node
                
                while current:
                    print(f"DEBUG: Processing node type: {current.type}")
                    
                    if current.type == 'attribute':
                        attr_node = current.child_by_field_name('attribute')
                        obj_node = current.child_by_field_name('object')
                        
                        if attr_node:
                            attr_name = attr_node.text.decode()
                            print(f"DEBUG: Found attribute: {attr_name}")
                            parts.insert(0, attr_name)
                        
                        current = obj_node
                        
                    elif current.type == 'identifier':
                        name = current.text.decode()
                        print(f"DEBUG: Found identifier: {name}")
                        parts.insert(0, name)
                        break
                        
                    else:
                        print(f"DEBUG: Unhandled node type: {current.type}")
                        break
                
                full_name = '.'.join(parts)
                print(f"DEBUG: Constructed full name: {full_name}")
                return full_name
                
            else:
                print(f"DEBUG: Unhandled function node type: {func_node.type}")
                
        return ''
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

    # def load_rules(self, rules_path: str) -> List[Dict[str, Any]]:
    #     with open(rules_path, "r") as f:
    #         return yaml.safe_load(f).get("rules", [])

    #     # rules = yaml.safe_load(open(rules_path))
    #     # print(f"Loaded rules: {rules}")  # Debug output
    #     # return rules

    def load_rules(self, rules_path: str) -> List[Dict[str, Any]]:
        """Load and validate security rules from YAML file"""
        try:
            with open(rules_path, "r") as f:
                rules_data = yaml.safe_load(f)
                print(f"DEBUG: Loaded rules data: {rules_data}")  # Debug output
                
                if not rules_data or 'rules' not in rules_data:
                    print("WARNING: No rules found in rules file")
                    return []
                
                # Validate and process rules
                processed_rules = []
                for rule in rules_data['rules']:
                    if self._validate_rule(rule):
                        processed_rules.append(rule)
                        print(f"DEBUG: Processed valid rule: {rule['id']}")
                    else:
                        print(f"WARNING: Invalid rule found: {rule.get('id', 'unknown')}")
                
                return processed_rules
        except Exception as e:
            print(f"ERROR: Failed to load rules: {str(e)}")
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
