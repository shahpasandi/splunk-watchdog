#!/opt/splunk-watchdog/venv/bin/python3
"""
Splunk Watchdog - Web Dashboard
Features: Fullscreen layout, Linux Auth, Time Filter, Pagination
"""
import configparser
import sqlite3
import crypt
import spwd
from datetime import datetime
from flask import Flask, render_template_string, request
from flask_httpauth import HTTPBasicAuth

CONFIG_PATH = "/opt/splunk-watchdog/config/watchdog.ini"
config = configparser.ConfigParser(interpolation=None)
config.read(CONFIG_PATH)
DB_PATH = config.get('general', 'db_path')

app = Flask(__name__)
auth = HTTPBasicAuth()

# ------------------------------------------------------------
# Authentication using Linux Users (/etc/shadow)
# ------------------------------------------------------------
@auth.verify_password
def verify_password(username, password):
    try:
        shadow_entry = spwd.getspnam(username)
        if shadow_entry:
            return crypt.crypt(password, shadow_entry.sp_pwdp) == shadow_entry.sp_pwdp
    except (KeyError, PermissionError):
        return False
    return False

@auth.error_handler
def auth_error(status):
    return "Access Denied. Please provide valid Linux credentials.", status

# ------------------------------------------------------------
# HTML Template
# ------------------------------------------------------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Splunk Watchdog Dashboard</title>
    <!-- Auto-refresh every 30s, preserving current page and time range -->
    <meta http-equiv="refresh" content="30;url=/?page={{ current_page }}&range={{ current_range }}">
    <style>
        body, html { 
            height: 100%; 
            margin: 0; 
            padding: 0; 
            overflow: hidden; 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: #1e1e2e; 
            color: #cdd6f4; 
            box-sizing: border-box;
        }
        
        .main-wrapper {
            display: flex;
            flex-direction: column;
            height: 100vh;
            padding: 15px;
            box-sizing: border-box;
            gap: 15px;
        }

        .header-container { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            border-bottom: 2px solid #45475a; 
            padding-bottom: 10px; 
            flex-shrink: 0;
        }
        h1 { color: #89b4fa; margin: 0; font-size: 24px; }
        
        .refresh-badge { 
            background: #313244; 
            padding: 6px 12px; 
            border-radius: 20px; 
            font-size: 13px; 
            color: #a6e3a1; 
            border: 1px solid #a6e3a1; 
            font-weight: bold; 
            display: flex; 
            align-items: center; 
            gap: 8px;
        }
        .refresh-dot { 
            height: 8px; width: 8px; 
            background-color: #a6e3a1; 
            border-radius: 50%; 
            animation: pulse 2s infinite; 
        }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }
        
        .summary-grid { 
            display: grid; 
            grid-template-columns: repeat(4, 1fr); 
            gap: 15px; 
            flex-shrink: 0;
        }
        .summary-card { 
            background: #313244; 
            padding: 10px 15px; 
            border-radius: 8px; 
            border-left: 4px solid #89b4fa; 
        }
        .summary-title { font-size: 11px; color: #6c7086; text-transform: uppercase; margin-bottom: 5px; }
        .summary-value { font-size: 20px; font-weight: bold; color: #cdd6f4; }
        
        .grid { 
            display: grid; 
            grid-template-columns: repeat(3, 1fr); 
            gap: 15px; 
            flex-grow: 1; 
            overflow: hidden; 
        }
        
        .card { 
            background: #313244; 
            padding: 15px; 
            border-radius: 8px; 
            display: flex; 
            flex-direction: column; 
            height: 100%;
            box-sizing: border-box;
            overflow: hidden;
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #45475a; 
            padding-bottom: 8px; 
            margin-bottom: 10px;
            flex-shrink: 0;
        }
        .card-header h2 { 
            margin: 0; 
            color: #a6e3a1; 
            font-size: 16px; 
        }
        
        /* Time filter dropdown */
        .filter-select {
            background: #45475a;
            color: #cdd6f4;
            border: 1px solid #6c7086;
            border-radius: 4px;
            padding: 3px 8px;
            font-size: 12px;
            cursor: pointer;
            outline: none;
        }
        .filter-select:hover { background: #585b70; }
        
        .table-container { 
            overflow: auto; 
            flex-grow: 1; 
            border-radius: 4px;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            font-size: 12px; 
            white-space: nowrap; 
        }
        th, td { 
            padding: 6px 8px; 
            text-align: left; 
            border-bottom: 1px solid #45475a; 
        }
        th { 
            color: #89b4fa; 
            position: sticky; 
            top: 0; 
            background: #313244; 
            z-index: 1;
        }
        
        .status-ok { color: #a6e3a1; font-weight: bold; }
        .status-warn { color: #f9e2af; font-weight: bold; }
        .status-fail { color: #f38ba8; font-weight: bold; }
        .status-unknown { color: #6c7086; font-weight: bold; }
        
        .row-warn { background-color: rgba(249, 226, 175, 0.15); }
        .row-fail { background-color: rgba(243, 139, 168, 0.15); }
        
        .progress-container { 
            display: flex; 
            flex-direction: column; 
            justify-content: flex-start;
            height: 100%; 
            padding-top: 5px;
        }
        
        .progress-label { display: flex; justify-content: space-between; margin-bottom: 10px; font-size: 14px; }
        .progress-bar-bg { background: #45475a; border-radius: 6px; height: 30px; overflow: hidden; display: flex; }
        .progress-segment { height: 100%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: bold; color: #1e1e2e; }
        .seg-ok { background: #a6e3a1; }
        .seg-warn { background: #f9e2af; }
        .seg-fail { background: #f38ba8; }
        .seg-unknown { background: #6c7086; color: #cdd6f4;}
        
        .legend { margin-top: 20px; font-size: 13px; line-height: 2; }
        
        .pagination { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-top: 10px; 
            padding-top: 10px; 
            border-top: 1px solid #45475a; 
            flex-shrink: 0;
        }
        .page-info { font-size: 12px; color: #6c7086; }
        .page-btns a { 
            text-decoration: none; 
            background: #45475a; 
            color: #cdd6f4; 
            padding: 4px 10px; 
            border-radius: 4px; 
            font-size: 12px; 
            margin-left: 5px; 
            transition: 0.2s;
        }
        .page-btns a:hover { background: #89b4fa; color: #1e1e2e; }
        .page-btns a.disabled { background: #313244; color: #6c7086; pointer-events: none; }
        
        .no-data { text-align: center; color: #6c7086; padding: 20px; font-style: italic; }
    </style>
</head>
<body>
    <div class="main-wrapper">
        <div class="header-container">
            <h1>Splunk Watchdog Dashboard</h1>
            <div class="refresh-badge">
                <span class="refresh-dot"></span>
                Auto-refresh: Every 30 Seconds
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card" style="border-left-color: #a6e3a1;">
                <div class="summary-title">Total Checks (24h)</div>
                <div class="summary-value">{{ summary.total_24h }}</div>
            </div>
            <div class="summary-card" style="border-left-color: #f38ba8;">
                <div class="summary-title">Issues (24h)</div>
                <div class="summary-value">{{ summary.issues_24h }}</div>
            </div>
            <div class="summary-card" style="border-left-color: #89b4fa;">
                <div class="summary-title">Last Check Run</div>
                <div class="summary-value" style="font-size: 15px;">{{ summary.last_run_time }}</div>
            </div>
            <div class="summary-card" style="border-left-color: #f9e2af;">
                <div class="summary-title">Current Time</div>
                <div class="summary-value" style="font-size: 15px;">{{ last_updated }}</div>
            </div>
        </div>

        <div class="grid">
            <!-- Column 1: Recent Health Checks -->
            <div class="card">
                <div class="card-header">
                    <h2>Recent Health Checks</h2>
                    <select class="filter-select" onchange="window.location.href='/?page=1&range=' + this.value">
                        <option value="1h" {% if current_range == '1h' %}selected{% endif %}>Last 1 Hour</option>
                        <option value="6h" {% if current_range == '6h' %}selected{% endif %}>Last 6 Hours</option>
                        <option value="24h" {% if current_range == '24h' %}selected{% endif %}>Last 24 Hours</option>
                        <option value="7d" {% if current_range == '7d' %}selected{% endif %}>Last 7 Days</option>
                    </select>
                </div>
                <div class="table-container">
                    <table>
                        <thead><tr><th>Time</th><th>Component</th><th>Check</th><th>Status</th></tr></thead>
                        <tbody>
                            {% for check in recent %}
                            <tr>
                                <td>{{ check.time[11:] }}</td>
                                <td>{{ check.component }}</td>
                                <td>{{ check.check_type }}</td>
                                <td class="status-{{ check.status }}">{{ check.status }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                <div class="pagination">
                    <div class="page-info">Page {{ current_page }} of {{ total_pages }}</div>
                    <div class="page-btns">
                        <a href="/?page={{ current_page - 1 }}&range={{ current_range }}" class="{{ 'disabled' if current_page <= 1 else '' }}">«</a>
                        <a href="/?page={{ current_page + 1 }}&range={{ current_range }}" class="{{ 'disabled' if current_page >= total_pages else '' }}">»</a>
                    </div>
                </div>
            </div>

            <!-- Column 2: Issues -->
            <div class="card">
                <div class="card-header">
                    <h2>Issues (Last 24h)</h2>
                </div>
                <div class="table-container">
                    <table>
                        <thead><tr><th>Time</th><th>Comp</th><th>Check</th><th>Details</th></tr></thead>
                        <tbody>
                            {% for issue in issues %}
                            <tr class="{{ 'row-warn' if issue.status == 'warn' else 'row-fail' if issue.status == 'fail' else '' }}">
                                <td>{{ issue.time[5:16] }}</td>
                                <td>{{ issue.component }}</td>
                                <td>{{ issue.check_type }}</td>
                                <td>{{ issue.details }}</td>
                            </tr>
                            {% else %}
                            <tr><td colspan="4" class="no-data">No issues in the last 24h. 🎉</td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Column 3: Component Status -->
            <div class="card">
                <div class="card-header">
                    <h2>Component Status (Last Hour)</h2>
                </div>
                <div class="progress-container">
                    <div class="progress-label"><span>Total Checks:</span> <strong>{{ total_checks }}</strong></div>
                    <div class="progress-bar-bg">
                        {% if chart_values[0] > 0 %}
                        <div class="progress-segment seg-ok" style="width: {{ (chart_values[0] / total_checks * 100) if total_checks > 0 else 0 }}%;" title="OK: {{ chart_values[0] }}"></div>
                        {% endif %}
                        {% if chart_values[1] > 0 %}
                        <div class="progress-segment seg-warn" style="width: {{ (chart_values[1] / total_checks * 100) if total_checks > 0 else 0 }}%;" title="WARN: {{ chart_values[1] }}"></div>
                        {% endif %}
                        {% if chart_values[2] > 0 %}
                        <div class="progress-segment seg-fail" style="width: {{ (chart_values[2] / total_checks * 100) if total_checks > 0 else 0 }}%;" title="FAIL: {{ chart_values[2] }}"></div>
                        {% endif %}
                        {% if chart_values[3] > 0 %}
                        <div class="progress-segment seg-unknown" style="width: {{ (chart_values[3] / total_checks * 100) if total_checks > 0 else 0 }}%;" title="UNKNOWN: {{ chart_values[3] }}"></div>
                        {% endif %}
                    </div>
                    
                    <div class="legend">
                        <div style="display: flex; justify-content: space-between; border-bottom: 1px solid #45475a; padding-bottom: 5px;">
                            <span><span style="color:#a6e3a1;">■</span> OK</span> <strong>{{ chart_values[0] }}</strong>
                        </div>
                        <div style="display: flex; justify-content: space-between; border-bottom: 1px solid #45475a; padding-bottom: 5px;">
                            <span><span style="color:#f9e2af;">■</span> WARN</span> <strong>{{ chart_values[1] }}</strong>
                        </div>
                        <div style="display: flex; justify-content: space-between; border-bottom: 1px solid #45475a; padding-bottom: 5px;">
                            <span><span style="color:#f38ba8;">■</span> FAIL</span> <strong>{{ chart_values[2] }}</strong>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span><span style="color:#6c7086;">■</span> UNKNOWN</span> <strong>{{ chart_values[3] }}</strong>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

def format_time(iso_string):
    try:
        dt = datetime.fromisoformat(iso_string)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return iso_string

@app.route('/')
@auth.login_required
def index():
    page = request.args.get('page', 1, type=int)
    current_range = request.args.get('range', '24h')
    if page < 1: page = 1
    per_page = 15 

    # Map time ranges to SQLite modifiers
    range_map = {
        '1h': '-1 hour',
        '6h': '-6 hours',
        '24h': '-24 hours',
        '7d': '-7 days'
    }
    sql_time_modifier = range_map.get(current_range, '-24 hours')
    time_filter = f"datetime(substr(timestamp, 1, 19)) > datetime('now', '{sql_time_modifier}')"

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Summary Stats
    cursor.execute('''SELECT COUNT(*) FROM health_checks WHERE datetime(substr(timestamp, 1, 19)) > datetime('now', '-24 hours')''')
    total_24h = cursor.fetchone()[0]
    
    cursor.execute('''SELECT COUNT(*) FROM health_checks WHERE status IN ('fail', 'warn') AND datetime(substr(timestamp, 1, 19)) > datetime('now', '-24 hours')''')
    issues_24h = cursor.fetchone()[0]
    
    cursor.execute('''SELECT timestamp FROM health_checks ORDER BY id DESC LIMIT 1''')
    last_run = cursor.fetchone()
    last_run_time = format_time(last_run[0]) if last_run else "N/A"

    # Filtered Recent Checks
    cursor.execute(f'SELECT COUNT(*) FROM health_checks WHERE {time_filter}')
    total_records = cursor.fetchone()[0]
    total_pages = max(1, (total_records + per_page - 1) // per_page)
    
    if page > total_pages: page = total_pages
    offset = (page - 1) * per_page

    cursor.execute(f'''SELECT timestamp, component, check_type, status, details 
                       FROM health_checks 
                       WHERE {time_filter}
                       ORDER BY id DESC LIMIT ? OFFSET ?''', (per_page, offset))
    recent = [{"time": format_time(r[0]), "component": r[1], "check_type": r[2], "status": r[3], "details": r[4]} for r in cursor.fetchall()]

    # Issues (always last 24h)
    cursor.execute('''
        SELECT timestamp, component, check_type, status, details
        FROM health_checks
        WHERE status IN ('fail', 'warn') 
        AND datetime(substr(timestamp, 1, 19)) > datetime('now', '-24 hours')
        ORDER BY id DESC LIMIT 10
    ''')
    issues = [{"time": format_time(r[0]), "component": r[1], "check_type": r[2], "status": r[3], "details": r[4]} for r in cursor.fetchall()]

    # Chart Data (always last 1 hour)
    cursor.execute('''
        SELECT status, COUNT(*) FROM health_checks
        WHERE datetime(substr(timestamp, 1, 19)) > datetime('now', '-1 hour')
        GROUP BY status
    ''')
    chart_data = {r[0]: r[1] for r in cursor.fetchall()}
    
    labels = ['ok', 'warn', 'fail', 'unknown']
    chart_values = [chart_data.get(l, 0) for l in labels]
    total_checks = sum(chart_values)

    conn.close()

    return render_template_string(
        HTML_TEMPLATE,
        last_updated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        recent=recent,
        issues=issues,
        chart_values=chart_values,
        total_checks=total_checks,
        current_page=page,
        total_pages=total_pages,
        current_range=current_range,
        summary={
            "total_24h": total_24h,
            "issues_24h": issues_24h,
            "last_run_time": last_run_time
        }
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
