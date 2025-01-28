class ContextScanner:
    def detect_xss(self, code):
        # Identify variables used in HTML contexts (e.g., Jinja templates)
        html_patterns = ["<div>{{", "<script>", "innerHTML="]
        for pattern in html_patterns:
            if pattern in code:
                return self._check_escaping(code)

    def detect_sqli(self, code):
        # Identify raw SQL queries with string formatting
        sql_patterns = ["SELECT * FROM", "WHERE username ="]
        for pattern in sql_patterns:
            if pattern in code and "%s" not in code:
                return True