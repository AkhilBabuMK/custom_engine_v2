from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/")
def vulnerable_page():
    # Source: User-controlled input from query parameter 'data'
    user_input = request.args.get("data", "")

    # Vulnerable Sink: Injecting user input directly into a <script> tag in the DOM
    template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>DOM-Based XSS Example</title>
    </head>
    <body>
        <h1>DOM-Based XSS Example</h1>
        <p>Welcome to the vulnerable page.</p>
        <script>
            // Vulnerable code: Inserting untrusted input into the DOM
            var userData = "{user_input}";
            document.write("User data: " + userData);
        </script>
    </body>
    </html>
    """
    return render_template_string(template)

if __name__ == "__main__":
    app.run(debug=True)
