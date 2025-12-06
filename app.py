from flask import Flask, request, render_template_string, jsonify, redirect, url_for
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

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        .container { 
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            padding: 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-align: center;
        }
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        .header .url {
            font-size: 14px;
            opacity: 0.9;
            word-break: break-all;
        }
        
        .verdict-box {
            padding: 30px;
            text-align: center;
            border-bottom: 2px solid #f0f0f0;
        }
        .verdict-box.suspicious {
            background: #fff5f5;
            border-left: 5px solid #e53e3e;
        }
        .verdict-box.safe {
            background: #f0fff4;
            border-left: 5px solid #38a169;
        }
        .verdict-box.warning {
            background: #fffaf0;
            border-left: 5px solid #dd6b20;
        }
        .verdict-emoji {
            font-size: 64px;
            margin-bottom: 15px;
        }
        .verdict-title {
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .verdict-message {
            font-size: 16px;
            color: #666;
            max-width: 600px;
            margin: 0 auto;
        }
        
        .issue-summary {
            padding: 20px 30px;
            background: #f9f9f9;
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }
        .issue-count {
            text-align: center;
        }
        .issue-count-num {
            font-size: 32px;
            font-weight: bold;
            display: block;
        }
        .issue-count-label {
            font-size: 12px;
            text-transform: uppercase;
            color: #666;
        }
        .critical { color: #e53e3e; }
        .high { color: #dd6b20; }
        .medium { color: #d69e2e; }
        .low { color: #3182ce; }
        
        .issues-section {
            padding: 30px;
        }
        .issue-category {
            margin-bottom: 30px;
        }
        .category-title {
            font-size: 20px;
            font-weight: bold;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }
        .issue-item {
            background: #f9f9f9;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 10px;
            border-left: 4px solid #ccc;
        }
        .issue-item.critical { border-left-color: #e53e3e; background: #fff5f5; }
        .issue-item.high { border-left-color: #dd6b20; background: #fffaf0; }
        .issue-item.medium { border-left-color: #d69e2e; background: #fffff0; }
        .issue-item.low { border-left-color: #3182ce; background: #f0f9ff; }
        
        .issue-type {
            font-weight: bold;
            font-size: 16px;
            margin-bottom: 8px;
        }
        .issue-description {
            color: #555;
            margin-bottom: 8px;
            font-size: 14px;
        }
        .issue-risk {
            color: #666;
            font-size: 13px;
            font-style: italic;
        }
        
        .actions {
            padding: 30px;
            background: #f9f9f9;
            text-align: center;
        }
        .btn {
            display: inline-block;
            padding: 12px 30px;
            margin: 0 10px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: bold;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-secondary {
            background: #e2e8f0;
            color: #4a5568;
        }
        
        .no-issues {
            padding: 40px;
            text-align: center;
            color: #38a169;
            font-size: 18px;
        }
        
        .raw-data {
            padding: 30px;
            background: #f9f9f9;
        }
        .raw-data pre {
            background: #2d3748;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 10px;
            overflow-x: auto;
            font-size: 12px;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Security Report</h1>
            <div class="url">{{ url }}</div>
        </div>
        
        {% if verdict %}
        <div class="verdict-box {{ verdict_class }}">
            <div class="verdict-emoji">{{ verdict.verdict_emoji }}</div>
            <div class="verdict-title">{{ verdict.verdict }}</div>
            <div class="verdict-message">{{ verdict.verdict_message }}</div>
        </div>
        
        {% if verdict.total_issues > 0 %}
        <div class="issue-summary">
            {% if verdict.issue_counts.critical > 0 %}
            <div class="issue-count">
                <span class="issue-count-num critical">{{ verdict.issue_counts.critical }}</span>
                <span class="issue-count-label">Critical</span>
            </div>
            {% endif %}
            {% if verdict.issue_counts.high > 0 %}
            <div class="issue-count">
                <span class="issue-count-num high">{{ verdict.issue_counts.high }}</span>
                <span class="issue-count-label">High</span>
            </div>
            {% endif %}
            {% if verdict.issue_counts.medium > 0 %}
            <div class="issue-count">
                <span class="issue-count-num medium">{{ verdict.issue_counts.medium }}</span>
                <span class="issue-count-label">Medium</span>
            </div>
            {% endif %}
            {% if verdict.issue_counts.low > 0 %}
            <div class="issue-count">
                <span class="issue-count-num low">{{ verdict.issue_counts.low }}</span>
                <span class="issue-count-label">Low</span>
            </div>
            {% endif %}
        </div>
        
        <div class="issues-section">
            {% if verdict.issues.critical %}
            <div class="issue-category">
                <div class="category-title critical">🚨 Critical Issues</div>
                {% for issue in verdict.issues.critical %}
                <div class="issue-item critical">
                    <div class="issue-type">{{ issue.type }}</div>
                    <div class="issue-description">{{ issue.description }}</div>
                    <div class="issue-risk">💀 {{ issue.risk }}</div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            {% if verdict.issues.high %}
            <div class="issue-category">
                <div class="category-title high">🔴 High Severity Issues</div>
                {% for issue in verdict.issues.high %}
                <div class="issue-item high">
                    <div class="issue-type">{{ issue.type }}</div>
                    <div class="issue-description">{{ issue.description }}</div>
                    <div class="issue-risk">⚠️ {{ issue.risk }}</div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            {% if verdict.issues.medium %}
            <div class="issue-category">
                <div class="category-title medium">🟡 Medium Severity Issues</div>
                {% for issue in verdict.issues.medium %}
                <div class="issue-item medium">
                    <div class="issue-type">{{ issue.type }}</div>
                    <div class="issue-description">{{ issue.description }}</div>
                    <div class="issue-risk">ℹ️ {{ issue.risk }}</div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            {% if verdict.issues.low %}
            <div class="issue-category">
                <div class="category-title low">🔵 Low Severity Issues</div>
                {% for issue in verdict.issues.low %}
                <div class="issue-item low">
                    <div class="issue-type">{{ issue.type }}</div>
                    <div class="issue-description">{{ issue.description }}</div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
        </div>
        {% else %}
        <div class="no-issues">
            ✅ No security issues detected! This website appears to be secure.
        </div>
        {% endif %}
        {% endif %}
        
        <div class="actions">
            <a href="/" class="btn btn-primary">Scan Another Site</a>
            <a href="/admin" class="btn btn-secondary">Admin Panel</a>
            <a href="#raw" onclick="document.getElementById('raw-data').style.display='block'; return false;" class="btn btn-secondary">View Raw Data</a>
        </div>
        
        <div id="raw-data" class="raw-data" style="display: none;">
            <h3 style="margin-bottom: 15px;">Raw Technical Data:</h3>
            <pre>{{ raw_data }}</pre>
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
    """Display scan report."""
    import urllib.parse
    data_str = request.args.get('data', '{}')
    
    try:
        data = json.loads(urllib.parse.unquote(data_str))
    except:
        return "Invalid report data", 400
    
    verdict = data.get('verdict', {})
    
    # Determine verdict class for styling
    verdict_text = verdict.get('verdict', '').upper()
    if 'SUSPICIOUS' in verdict_text:
        verdict_class = 'suspicious'
    elif 'SAFE' in verdict_text:
        verdict_class = 'safe'
    else:
        verdict_class = 'warning'
    
    return render_template_string(
        REPORT_TEMPLATE,
        url=data.get('url', 'Unknown'),
        verdict=verdict,
        verdict_class=verdict_class,
        raw_data=json.dumps(data.get('raw', {}), indent=2, default=str)
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