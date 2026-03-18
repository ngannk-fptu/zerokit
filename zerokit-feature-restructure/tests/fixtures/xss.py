from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q')
    
    # VULNERABILITY: Reflected XSS
    # Line 9 should be flagged
    return f"Results for: {query}"

@app.route('/safe')
def safe():
    query = request.args.get('q')
    import html
    # SAFE: Escaped
    return f"Results for: {html.escape(query)}"
