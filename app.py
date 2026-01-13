from flask import Flask, request, render_template, render_template_string, jsonify, redirect, url_for

from scanner.core import SecurityScanner
import json
from flasgger import Swagger


from admin_bp import admin_bp

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  


app.register_blueprint(admin_bp)

scanner = SecurityScanner()

app.config['SWAGGER'] = {
    'title': 'Security Scanner API',
    'description': 'Ethical web security scanner for HTTPS, SSL, headers, and forms',
    'version': '1.0',
    'uiversion': 3,
    'specs_route': '/apidocs/'
}
swagger = Swagger(app)

HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Scanner</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container { 
            max-width: 600px;
            width: 100%;
            padding: 40px;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { 
            font-size: 32px;
            margin-bottom: 10px;
            color: #333;
            text-align: center;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        input { 
            padding: 15px;
            width: 100%;
            margin: 15px 0;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            transition: border 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button { 
            padding: 15px 30px;
            width: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        button:active {
            transform: translateY(0);
        }
        .links {
            margin-top: 25px;
            text-align: center;
        }
        .links a {
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
            margin: 0 10px;
        }
        .links a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Security Scanner</h1>
        <p class="subtitle">Check if a website is safe or suspicious</p>
        <form action="/scan" method="post">
            <input type="text" name="url" placeholder="https://example.com" required autofocus>
            <button type="submit">🔍 Scan Website</button>
        </form>
        <div class="links">
            <a href="/admin">🔧 Admin Panel</a>
            <a href="/apidocs/">📖 API Docs</a>
        </div>
    </div>
</body>
</html>
"""


@app.route('/')
def home():
    """Home page with scan form."""
    return render_template_string(HOME_TEMPLATE)


@app.route('/scan', methods=['POST'])
def scan():
    """
    Scan a website for security issues.
    ---
    parameters:
      - name: url
        in: formData
        type: string
        required: true
        description: Website URL to scan
    responses:
      200:
        description: Redirect to report page
    """
    url = request.form.get('url')
    if not url:
        return "URL required", 400
    
    if not url.startswith('http'):
        url = 'https://' + url
    
    # Perform scan
    report = scanner.scan(url)
    
    if not report.success:
        return f"Scan failed: {report.error}", 500
    
    # Get verdict
    verdict = report.get_verdict()
    
    # Store in session or pass via URL (for simplicity, using URL)
    import urllib.parse
    data = {
        'url': url,
        'verdict': verdict,
        'raw': report.__dict__
    }
    
    return redirect(url_for('report', data=urllib.parse.quote(json.dumps(data, default=str))))


@app.route('/report')
def report():
    """Display scan report with detailed analysis."""
    import urllib.parse
    from datetime import datetime
    
    data_str = request.args.get('data', '{}')
    
    try:
        data = json.loads(urllib.parse.unquote(data_str))
    except:
        return "Invalid report data", 400
    
    verdict = data.get('verdict', {})
    raw_data = data.get('raw', {})
    
    # Create ScanReport object from raw data for template
    scan_report = type('ScanReport', (), raw_data)()
    
    # Determine verdict class for styling
    verdict_text = verdict.get('verdict', '').upper()
    if 'SUSPICIOUS' in verdict_text:
        verdict_class = 'suspicious'
    elif 'SAFE' in verdict_text:
        verdict_class = 'safe'
    else:
        verdict_class = 'warning'
    
    # Get current timestamp
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Render template with scan_report object
    return render_template('report.html',
        url=data.get('url', 'Unknown'),
        verdict=verdict,
        verdict_class=verdict_class,
        scan_report=scan_report,
        current_time=current_time
    )


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """
    API endpoint to scan a URL and return JSON verdict.
    ---
    parameters:
      - name: url
        in: body
        required: true
        schema:
          type: object
          properties:
            url:
              type: string
              example: https://example.com
    responses:
      200:
        description: Scan results with verdict
    """
    data = request.get_json()
    url = data.get('url') if data else None
    
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    if not url.startswith('http'):
        url = 'https://' + url
    
    report = scanner.scan(url)
    
    if not report.success:
        return jsonify({"error": report.error}), 500
    
    verdict = report.get_verdict()
    
    return jsonify({
        "url": url,
        "verdict": verdict,
        "scan_data": report.__dict__
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)