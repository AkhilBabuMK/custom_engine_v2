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
            # Load Python parser
            python_path = os.path.join(
                os.path.expanduser("~/.tree-sitter/parsers"),
                "python.so"
            )
            self.language = Language(python_path, "python")
            self.parser = Parser()
            self.parser.set_language(self.language)
            
            # Load HTML parser
            html_path = os.path.join(
                os.path.expanduser("~/.tree-sitter/parsers"),
                "html.so"
            )
            self.html_language = Language(html_path, "html")
            self.html_parser = Parser()
            self.html_parser.set_language(self.html_language)
            
            # Load JavaScript parser
            js_path = os.path.join(
                os.path.expanduser("~/.tree-sitter/parsers"),
                "javascript.so"
            )
            self.js_language = Language(js_path, "javascript")
            self.js_parser = Parser()
            self.js_parser.set_language(self.js_language)
        
        except Exception as e:
            raise RuntimeError(f"Parser init failed: {str(e)}")
    
    def index_project(self, path: str):
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(('.py', '.html', '.js')):  # Add HTML/JS support
                    self.current_file = os.path.join(root, file)
                    self._index_file(self.current_file)


    # def _index_file(self, file_path: str):
    #     with open(file_path, "r") as f:
    #         code = f.read()
    #         tree = self.parser.parse(bytes(code, "utf8"))
    #         self._analyze_ast(tree.root_node, code, file_path)

    def _index_file(self, file_path: str):
        with open(file_path, "r") as f:
            code = f.read()
            
            if file_path.endswith('.html'):
                tree = self.html_parser.parse(bytes(code, "utf8"))
                self._analyze_html(tree.root_node, code, file_path)
            elif file_path.endswith('.js'):
                tree = self.js_parser.parse(bytes(code, "utf8"))
                self._analyze_js(tree.root_node, code, file_path)
            else:
                tree = self.parser.parse(bytes(code, "utf8"))
                self._analyze_ast(tree.root_node, code, file_path)

    """ - HTML ANALYSIS CODE - """

    def _analyze_html(self, node, code: str, file_path: str):
        """Analyze HTML files for embedded JavaScript and dangerous attributes"""
        if node.type == 'script_element':
            # Extract and analyze embedded JavaScript
            script_content = self._extract_script_content(node, code)
            if script_content:
                js_tree = self.js_parser.parse(bytes(script_content, "utf8"))
                self._analyze_js(js_tree.root_node, script_content, file_path)
        
        #Check for dangerous HTML attributes
        if node.type == 'attribute':
            attr_name = node.child_by_field_name('name')
            if attr_name and attr_name.text.decode() in ['onload', 'onerror', 'onclick','onmouseover', 'href']:
                self._report_xss(node, code, file_path)
        
        if node.type == 'text':
            content = node.text.decode()
            template_vars = re.findall(r'\{\{(\w+)\}\}', content)
            for var in template_vars:
                if var in self.tainted_vars:
                    self._report_xss(node, code, file_path)
        # Recursively analyze child nodes
        for child in node.children:
            self._analyze_html(child, code, file_path)

    def _extract_script_content(self, node, code: str) -> str:
        """Extract JavaScript content from script tags"""
        for child in node.children:
            if child.type in ['raw_text', 'text']:
                return code[child.start_byte:child.end_byte]
        return ""

    """ END OF HTML ANALYSIS """

    """ JAVA SCRIPT ANALYSIS """
    def _analyze_js(self, node, code: str, file_path: str):
        """Analyze JavaScript code for XSS sinks"""
        if node.type == 'member_expression':
            # Detect innerHTML assignments
            object_name = node.child_by_field_name('object').text.decode()
            property_name = node.child_by_field_name('property').text.decode()
            
            if property_name in ['innerHTML', 'outerHTML', 'dangerouslySetInnerHTML']:
                self._report_js_xss(node, code, file_path)
        
        # Detect dangerous APIs
        if node.type == 'call_expression':
            func_name = self._get_js_function_name(node)
            if func_name in ['document.write', 'document.writeln', 'eval','setTimeout', 'setInterval', 'Function']:
                self._report_js_xss(node, code, file_path)
        
        
        
        # Recursively analyze child nodes
        for child in node.children:
            self._analyze_js(child, code, file_path)

    def _get_js_function_name(self, node):
        """Get full function name in JavaScript"""
        if node.type == 'identifier':
            return node.text.decode()
        elif node.type == 'member_expression':
            return f"{node.child_by_field_name('object').text.decode()}.{node.child_by_field_name('property').text.decode()}"
        return ''

    """ END OF JAVASCRIPT ANALYSIS """

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

        #Flask route parametes            
        elif  node.type == 'decorated_definition':
            decorator = node.child_by_field_name('decorator')
            if decorator and 'route' in decorator.text.decode():
                self._analyze_flask_route(node, code, file_path)

        # added source detection for js-specific patterns
        elif node.type == 'member_expression':
            obj = node.child_by_field_name('object')
            prop = node.child_by_field_name('property')
            if obj and prop:
                full_name = f"{obj.text.decode()}.{prop.text.decode()}"
                if full_name in [
                    'window.location.search',
                    'window.location.hash',
                    'document.cookie',
                    'localStorage.getItem'
                ]:
                    if parent := self._find_assignment_target(node):
                        self._mark_tainted(parent.text.decode(), node, code)

        #added template literal analusis
        elif node.type == 'template_string':
            for child in node.children:
                if child.type == 'template_substitution':
                    expr = child.child_by_field_name('value')
                    if self._contains_tainted_data(expr):
                        self._report_js_xss(node.parent, code, file_path)

        # Recursive analysis
        for child in node.children:
            self._analyze_ast(child, code, file_path)

    #promise chain tracking implemented
    def _track_promise_chain(self, node, code: str, file_path: str):
        """Track taint through promise chains"""
        current_node = node
        while current_node:
            if current_node.type == 'call_expression':
                func = current_node.child_by_field_name('function')
                if func and func.text.decode() == 'then':
                    args = self._get_call_arguments(current_node)
                    for arg in args:
                        if arg.type == 'arrow_function':
                            self._analyze_js(arg, code, file_path)
            current_node = current_node.parent

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
    # def _track_sanitizer(self, node, code: str):
    #     if var_name := self._get_assigned_variable(node.parent):
    #         sanitizer = self._get_function_name(node)
    #         self.tainted_vars[var_name]['sanitizers'].add(sanitizer)
    #         print(f"Applied sanitizer {sanitizer} to {var_name}")  # Debug
    def _track_sanitizer(self, node, code: str):
        if var_name := self._get_assigned_variable(node.parent):
            sanitizer = self._get_function_name(node)
            if sanitizer in self.all_sanitizers:
                self.tainted_vars[var_name]['sanitized'] = True
                self.tainted_vars[var_name]['sanitizers'].add(sanitizer)
    

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

    def _analyze_flask_route(self, node, code: str, file_path: str):
        """Analyze Flask route handlers for data flows"""
        func_def = node.child_by_field_name('definition')
        if func_def and func_def.type == 'function_definition':
            func_body = func_def.child_by_field_name('body')
            self._track_route_parameters(func_body, code, file_path)

    def _track_route_parameters(self, node, code: str, file_path: str):
        """Track request parameters in Flask routes"""
        if node.type == 'call':
            func_name = self._get_function_name(node)
            if func_name == 'request.args.get':
                if var_name := self._get_assigned_variable(node.parent):
                    self._mark_tainted(var_name, node, code)
                    logger.debug(f"Marked route param {var_name} as tainted")


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

        if node.type == 'member_expression':
            obj = node.child_by_field_name('object')
            prop = node.child_by_field_name('property')
            return self._contains_tainted_data(obj) or self._contains_tainted_data(prop)

        if node.type == 'template_string':
            return any(self._contains_tainted_data(child) 
                    for child in node.children)
    
        return super()._contains_tainted_data(node)
        
        # return False

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

    def _report_xss(self, node, code: str, file_path: str):
        """Report HTML-based XSS vulnerabilities with context validation"""
        try:
            print("html code is:", code)
            line_number = node.start_point[0] + 1
            code_snippet = code.split('\n')[line_number - 1].strip()
            
            # Get involved variables
            tainted_vars = []
            if node.type == 'attribute':
                attr_value = node.parent.child_by_field_name('value')
                if attr_value:
                    tainted_vars = [var for var in self.tainted_vars 
                                if var in attr_value.text.decode()]
            
            # Verify unsanitized variables
            unsanitized_vars = [
                var for var in tainted_vars
                if not self.tainted_vars[var].get('sanitized', False)
            ]
            unsanitized_vars=""
            # if unsanitized_vars:
            self.data_flows.append({
                'type': 'xss',
                'file': file_path,
                'line': line_number,
                'code': code_snippet,
                'description': f"XSS via unsafe HTML attribute with tainted data: {', '.join(unsanitized_vars)}",
                'sink': 'HTML attribute',
                'tainted_vars': unsanitized_vars
            })

            print(data_flows)
            
        except Exception as e:
            logger.error(f"XSS reporting error: {str(e)}")

    def _report_js_xss(self, node, code: str, file_path: str):
        """Report JavaScript-based XSS vulnerabilities with template literal support and precise data flow tracking"""
        try:
            line_number = node.start_point[0] + 1
            code_snippet = code.split('\n')[line_number - 1].strip()
            
            print(code_snippet)
            tainted_vars = set()
            unsanitized_vars = []
            sink_type = 'unknown'
            description_extras = []

            print(code_snippet)
            # 1. Analyze template literals using AST parsing
            if node.type == 'assignment_expression':
                right_side = node.child_by_field_name('right')
                if right_side and right_side.type == 'template_string':
                    self._analyze_template_literals(right_side, code, tainted_vars)

            # 2. Standard AST-based variable tracking
            current_node = node
            while current_node:
                if current_node.type in ['identifier', 'member_expression']:
                    var_name = self._get_js_identifier_path(current_node)
                    if var_name in self.tainted_vars:
                        tainted_vars.add(var_name)
                current_node = current_node.parent

            # 3. Detect specific sink patterns
            if 'innerHTML' in code_snippet:
                sink_type = 'innerHTML'
            elif 'outerHTML' in code_snippet:
                sink_type = 'outerHTML'
            elif 'document.write' in code_snippet:
                sink_type = 'document.write'
            elif 'eval(' in code_snippet:
                sink_type = 'eval'
            print("sink type is ", sink_type)
            
            # 4. Contextual analysis for template literals
            if '`' in code_snippet and '${' in code_snippet:
                for expr in re.finditer(r'\$\{([^}]+)\}', code_snippet):
                    
                    expr_content = expr.group(1)
                    print("expr_content is :", expr_content)
                    parsed_expr = self.js_parser.parse(bytes(expr_content, 'utf8'))
                    print("parsed_expr is :", parsed_expr)
                    print("type is :",parsed_expr.root_node.type )
                    tainted_vars.update(self._find_tainted_in_expression(parsed_expr.root_node))

            # 5. Sanitization check and final validation
            print("tained_vars are :",tainted_vars)
            # unsanitized_vars = [
            #     var for var in tainted_vars
            #     if var in self.tainted_vars and not self.tainted_vars[var].get('sanitized', False)
            # ]

            # 6. Build comprehensive description
            print("unsanitized _vars :",unsanitized_vars)
            # if unsanitized_vars:
            if sink_type.startswith('document.') or sink_type == 'eval':
                description = f"DOM XSS via {sink_type} with tainted data"
            elif sink_type in ['innerHTML', 'outerHTML']:
                description = f"XSS via {sink_type} assignment"
                if '`' in code_snippet:
                    description += " using template literals"
            else:
                description = "Potential XSS in JavaScript code"

            description += f". Tainted variables: {', '.join(unsanitized_vars)}"

            # 7. Create data flow entry
            self.data_flows.append({
                'type': 'xss',
                'file': file_path,
                'line': line_number,
                'code': code_snippet,
                'description': description,
                'sink': sink_type,
                'tainted_vars': unsanitized_vars,
                'context': {
                    'template_literal': '`' in code_snippet,
                    'promise_chain': 'then(' in code_snippet,
                    'dangerous_api': sink_type in ['eval', 'document.write']
                }
            })

        except Exception as e:
            logger.error(f"JS XSS reporting error: {str(e)}", exc_info=True)

    # Helper methods needed for the implementation:

    def _analyze_template_literals(self, node, code: str, tainted_vars: set):
        """Deep analysis of template literal components"""
        for child in node.children:
            if child.type == 'template_substitution':
                expr_node = child.child_by_field_name('value')
                if expr_node:
                    # Parse the embedded JavaScript expression
                    expr_code = code[expr_node.start_byte:expr_node.end_byte]
                    parsed_expr = self.js_parser.parse(bytes(expr_code, 'utf8'))
                    tainted_vars.update(self._find_tainted_in_expression(parsed_expr.root_node))

    def _find_tainted_in_expression(self, node) -> set:
        """Recursively find tainted variables in JS expression AST"""
        tainted = set()
        if node.type == 'identifier':
            var_name = node.text.decode()
            if var_name in self.tainted_vars:
                tainted.add(var_name)
        elif node.type == 'member_expression':
            object_part = node.child_by_field_name('object')
            property_part = node.child_by_field_name('property')
            obj_name = self._get_js_identifier_path(object_part)
            if obj_name in self.tainted_vars:
                tainted.add(obj_name)
            tainted.update(self._find_tainted_in_expression(property_part))
        elif node.type == "program":
            print(node)
            var_name = node.text.decode()
            print("var name is ", var_name)
            
            tainted.add(var_name)
        
        for child in node.children:
            tainted.update(self._find_tainted_in_expression(child))
        
        return tainted

    def _get_js_identifier_path(self, node) -> str:
        """Resolve full path for member expressions (e.g., 'a.b.c')"""
        parts = []
        while node and node.type in ['member_expression', 'identifier']:
            if node.type == 'member_expression':
                prop = node.child_by_field_name('property')
                parts.append(prop.text.decode() if prop else '?')
                node = node.child_by_field_name('object')
            else:
                parts.append(node.text.decode())
                break
        return '.'.join(reversed(parts))



    def _report_sqli(self, node, code: str):
        """Report SQL injection vulnerabilities with query validation"""
        try:
            line_number = node.start_point[0] + 1
            code_snippet = code.split('\n')[line_number - 1].strip()
            
            # Get raw SQL query text
            query_node = node.child_by_field_name('arguments').named_children[0]
            query_text = query_node.text.decode()
            
            # Find unsanitized variables in query
            unsanitized_vars = [
                var for var in self.tainted_vars
                if var in query_text and 
                not self.tainted_vars[var].get('sanitized', False)
            ]
            
            # Heuristic check for suspicious patterns
            suspicious_patterns = [
                r"\b(union|select|insert|update|delete|drop|alter)\b",
                r";\s*--",
                r"\d+\s*=\s*\d+"
            ]
            
            pattern_found = any(
                re.search(pattern, query_text, re.IGNORECASE) 
                for pattern in suspicious_patterns
            )
            
            if unsanitized_vars and pattern_found:
                self.data_flows.append({
                    'type': 'sql',
                    'file': self.current_file,
                    'line': line_number,
                    'code': code_snippet,
                    'description': f"SQLi detected with tainted variables: {', '.join(unsanitized_vars)}",
                    'sink': self._get_function_name(node),
                    'tainted_vars': unsanitized_vars
                })
                
        except Exception as e:
            logger.error(f"SQLi reporting error: {str(e)}")

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
        # if var_name not in self.tainted_vars:
        #     self.tainted_vars[var_name] = {
        #         'sources': set(['user_input']),
        #         'sanitizers': set(),
        #         'locations': []
        #     }

        if var_name not in self.tainted_vars:
            self.tainted_vars[var_name] = {
                'sources': set(),
                'sanitizers': set(),
                'sanitized': False,  # Track sanitization status
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

