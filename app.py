from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
import json
from datetime import datetime, timedelta
import random
import os
import csv
import io

app = Flask(__name__)

# Custom Jinja2 filters
def intcomma(value):
    """Format integer with commas"""
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return value

# Register the filter
app.jinja_env.filters['intcomma'] = intcomma

# Load data from files
def load_data():
    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    
    scans_data = []
    threats_data = []
    users_data = []
    policies_data = []
    
    try:
        with open(os.path.join(data_dir, 'sample_scans.json'), 'r') as f:
            scans_data = json.load(f)
    except:
        scans_data = []
    
    try:
        with open(os.path.join(data_dir, 'threats.json'), 'r') as f:
            threats_data = json.load(f)
    except:
        threats_data = []
    
    try:
        with open(os.path.join(data_dir, 'users.json'), 'r') as f:
            users_data = json.load(f)
    except:
        users_data = []
    
    try:
        with open(os.path.join(data_dir, 'policies.json'), 'r') as f:
            policies_data = json.load(f)
    except:
        policies_data = []
    
    return scans_data, threats_data, users_data, policies_data

# Load initial data
SCANS_DATA, THREATS_DATA, USERS_DATA, POLICIES_DATA = load_data()

# Sample alerts for monitoring
SECURITY_ALERTS = [
    {"type": "danger", "icon": "exclamation-triangle", "title": "Critical", 
     "message": "Unauthorized access attempt detected from external IP", "time": "14:32"},
    {"type": "warning", "icon": "exclamation-circle", "title": "Warning", 
     "message": "Policy violation in user documents folder", "time": "14:25"},
    {"type": "info", "icon": "info-circle", "title": "Info", 
     "message": "Full system scan completed successfully", "time": "14:15"},
    {"type": "danger", "icon": "shield-exclamation", "title": "Critical", 
     "message": "Sensitive data transfer to USB device detected", "time": "13:58"},
    {"type": "warning", "icon": "exclamation-circle", "title": "Warning", 
     "message": "Multiple failed login attempts for user admin", "time": "13:45"},
]

# ============ MAIN PAGES ============

@app.route('/')
def index():
    """Main dashboard page"""
    # Calculate statistics
    total_scans = len(SCANS_DATA)
    total_threats = sum(scan['threats_found'] for scan in SCANS_DATA)
    total_users = len(USERS_DATA)
    active_policies = len([p for p in POLICIES_DATA if p['status'] == 'active'])
    
    recent_scans = sorted(SCANS_DATA, key=lambda x: x['start_time'], reverse=True)[:5]
    recent_threats = THREATS_DATA[:5]
    
    return render_template('index.html', 
                         total_scans=total_scans,
                         total_threats=total_threats,
                         total_users=total_users,
                         active_policies=active_policies,
                         recent_scans=recent_scans,
                         recent_threats=recent_threats)

@app.route('/scanner')
def scanner():
    """Content scanner page"""
    return render_template('scanner.html', scans=SCANS_DATA)

@app.route('/monitor')
def monitor():
    """Security monitor page"""
    return render_template('monitor.html', alerts=SECURITY_ALERTS, threats=THREATS_DATA[:10])

@app.route('/alerts')
def alerts():
    """Alerts center page"""
    return render_template('alerts.html', alerts=SECURITY_ALERTS, threats=THREATS_DATA)

@app.route('/policies')
def policies():
    """Policy management page"""
    return render_template('policies.html', policies=POLICIES_DATA)

@app.route('/reports')
def reports():
    """Reports page"""
    return render_template('reports.html')

@app.route('/api-testing')
def api_testing():
    """API testing console"""
    return render_template('api_testing.html')

@app.route('/threats')
def threats():
    """Threat management page"""
    return render_template('threats.html', threats=THREATS_DATA)

@app.route('/users')
def users():
    """User management page"""
    return render_template('users.html', users=USERS_DATA)

# ============ DOCUMENTATION PAGES ============

@app.route('/docs')
def docs_index():
    """Documentation index"""
    return render_template('docs_index.html')

@app.route('/docs/scanner')
def scanner_docs():
    """Scanner documentation"""
    return render_template('scanner_docs.html')

@app.route('/docs/monitor')
def monitor_docs():
    """Monitor documentation"""
    return render_template('monitor_docs.html')

@app.route('/docs/policies')
def policies_docs():
    """Policies documentation"""
    return render_template('policies_docs.html')

@app.route('/docs/dashboard')
def dashboard_docs():
    """Dashboard documentation"""
    return render_template('dashboard_docs.html')

@app.route('/docs/api')
def api_docs():
    """API documentation"""
    return render_template('api_docs.html')

# ============ REPORT GENERATION & DOWNLOAD ============

@app.route('/api/report/generate', methods=['POST'])
def generate_report():
    """Generate and download reports"""
    data = request.json
    report_type = data.get('type', 'daily')
    format_type = data.get('format', 'pdf')
    
    # Generate report content based on type
    if report_type == 'daily':
        content = generate_daily_report()
    elif report_type == 'weekly':
        content = generate_weekly_report()
    elif report_type == 'security':
        content = generate_security_report()
    else:
        content = generate_custom_report(report_type)
    
    # Create filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"dlp_report_{report_type}_{timestamp}"
    
    if format_type == 'csv':
        filename += '.csv'
        # Create CSV response
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['DLP Security Report', report_type, timestamp])
        writer.writerow([])
        
        # Write scans data
        writer.writerow(['SCAN HISTORY'])
        writer.writerow(['ID', 'Name', 'Type', 'Files', 'Threats', 'Severity', 'Date'])
        for scan in SCANS_DATA:
            writer.writerow([
                scan['id'],
                scan['name'],
                scan['type'],
                scan['files_scanned'],
                scan['threats_found'],
                scan['severity'],
                scan['start_time']
            ])
        
        writer.writerow([])
        writer.writerow(['THREATS DETECTED'])
        writer.writerow(['ID', 'Type', 'File', 'Severity', 'Status', 'Date'])
        for threat in THREATS_DATA:
            writer.writerow([
                threat['id'],
                threat['type'],
                threat['file_name'],
                threat['severity'],
                threat['status'],
                threat['date_detected']
            ])
        
        # Prepare response
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
    
    elif format_type == 'json':
        filename += '.json'
        report_data = {
            'report_type': report_type,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_scans': len(SCANS_DATA),
                'total_threats': len(THREATS_DATA),
                'total_users': len(USERS_DATA),
                'active_policies': len([p for p in POLICIES_DATA if p['status'] == 'active'])
            },
            'scans': SCANS_DATA[:10],
            'threats': THREATS_DATA[:10],
            'policies': POLICIES_DATA
        }
        
        return send_file(
            io.BytesIO(json.dumps(report_data, indent=2).encode('utf-8')),
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )
    
    else:  # PDF or other formats (returning text for demo)
        filename += '.txt'
        return send_file(
            io.BytesIO(content.encode('utf-8')),
            mimetype='text/plain',
            as_attachment=True,
            download_name=filename
        )

def generate_daily_report():
    """Generate daily report content"""
    today = datetime.now().strftime('%Y-%m-%d')
    
    report = f"""
    DLP SECURITY SYSTEM - DAILY REPORT
    ===================================
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    
    EXECUTIVE SUMMARY
    -----------------
    Total Scans Today: {len(SCANS_DATA)}
    Total Threats Detected: {sum(scan['threats_found'] for scan in SCANS_DATA)}
    Active Policies: {len([p for p in POLICIES_DATA if p['status'] == 'active'])}
    System Health: Excellent
    
    SCAN ACTIVITIES
    ---------------
    """
    
    for scan in SCANS_DATA:
        report += f"""
    Scan: {scan['name']}
      Type: {scan['type']}
      Files: {scan['files_scanned']:,}
      Threats: {scan['threats_found']}
      Duration: {scan['duration']}
      Status: {scan['status'].upper()}
      Path: {scan['path']}
    """
    
    report += """
    THREAT ANALYSIS
    ---------------
    """
    
    for threat in THREATS_DATA[:10]:
        report += f"""
    Threat: {threat['id']}
      Type: {threat['type']}
      File: {threat['file_name']}
      Severity: {threat['severity'].upper()}
      Status: {threat['status']}
      Action: {threat['action_taken']}
    """
    
    report += """
    RECOMMENDATIONS
    ---------------
    1. Review high severity threats immediately
    2. Update malware signatures
    3. Conduct security awareness training
    4. Review and update policies as needed
    
    --- END OF REPORT ---
    """
    
    return report

def generate_weekly_report():
    """Generate weekly report content"""
    return generate_daily_report() + "\n\nWEEKLY TREND ANALYSIS INCLUDED"

def generate_security_report():
    """Generate security audit report"""
    return generate_daily_report() + "\n\nSECURITY AUDIT DETAILS INCLUDED"

def generate_custom_report(report_type):
    """Generate custom report"""
    return f"Custom report for {report_type}\n\n" + generate_daily_report()

# ============ API ENDPOINTS ============

@app.route('/api/health')
def api_health():
    """System health check"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "services": {
            "scanner": "running",
            "monitor": "running",
            "database": "connected",
            "reporting": "active"
        },
        "statistics": {
            "total_scans": len(SCANS_DATA),
            "total_threats": len(THREATS_DATA),
            "active_users": len([u for u in USERS_DATA if u['status'] == 'active']),
            "active_policies": len([p for p in POLICIES_DATA if p['status'] == 'active'])
        }
    })

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Start a scan"""
    data = request.json
    scan_type = data.get('type', 'quick')
    scan_path = data.get('path', '/')
    
    # Create new scan record
    scan_id = len(SCANS_DATA) + 1
    new_scan = {
        "id": scan_id,
        "name": f"{scan_type.capitalize()} Scan",
        "type": scan_type,
        "start_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "end_time": (datetime.now() + timedelta(minutes=random.randint(5, 60))).strftime('%Y-%m-%d %H:%M:%S'),
        "duration": f"{random.randint(5, 60)}m",
        "files_scanned": random.randint(100, 10000),
        "threats_found": random.randint(0, 20),
        "status": "in_progress",
        "severity": random.choice(["low", "medium", "high", "critical"]),
        "details": {
            "malware_files": random.randint(0, 5),
            "sensitive_data": random.randint(0, 10),
            "policy_violations": random.randint(0, 5),
            "encrypted_files": random.randint(50, 500)
        },
        "path": scan_path,
        "scanned_by": "api_user"
    }
    
    SCANS_DATA.insert(0, new_scan)
    
    return jsonify({
        "scan_id": scan_id,
        "status": "started",
        "message": f"Scan {scan_id} started successfully",
        "estimated_completion": "5-60 minutes",
        "scan_details": new_scan
    })

@app.route('/api/scan/results/<int:scan_id>')
def api_scan_results(scan_id):
    """Get scan results by ID"""
    scan = next((s for s in SCANS_DATA if s['id'] == scan_id), None)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    return jsonify({
        "scan_id": scan_id,
        "status": "completed",
        "timestamp": scan['start_time'],
        "scan_details": scan
    })

@app.route('/api/scan/history')
def api_scan_history():
    """Get scan history"""
    limit = request.args.get('limit', 10, type=int)
    scans = SCANS_DATA[:limit]
    return jsonify(scans)

@app.route('/api/metrics')
def api_metrics():
    """Get system metrics"""
    total_files = sum(scan['files_scanned'] for scan in SCANS_DATA)
    total_threats = sum(scan['threats_found'] for scan in SCANS_DATA)
    
    return jsonify({
        "cpu_usage": random.randint(30, 80),
        "memory_usage": random.randint(40, 90),
        "disk_usage": random.randint(50, 95),
        "network_traffic": random.randint(100, 1000),
        "total_files_scanned": total_files,
        "total_threats_detected": total_threats,
        "threat_detection_rate": round((total_threats / max(total_files, 1)) * 100, 2),
        "scan_success_rate": 98.5,
        "system_health": random.randint(85, 100)
    })

@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    """Get alerts with filtering"""
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')
    limit = request.args.get('limit', 20, type=int)
    
    # Filter threats as alerts
    filtered_threats = THREATS_DATA.copy()
    
    if severity:
        filtered_threats = [t for t in filtered_threats if t['severity'] == severity]
    
    if status:
        filtered_threats = [t for t in filtered_threats if t['status'] == status]
    
    filtered_threats = filtered_threats[:limit]
    
    return jsonify({
        "total": len(filtered_threats),
        "alerts": filtered_threats,
        "filters_applied": {
            "severity": severity,
            "status": status,
            "limit": limit
        }
    })

@app.route('/api/policies')
def api_policies():
    """Get all policies"""
    return jsonify(POLICIES_DATA)

@app.route('/api/users')
def api_users():
    """Get all users"""
    return jsonify(USERS_DATA)

@app.route('/api/threats')
def api_threats():
    """Get all threats"""
    return jsonify(THREATS_DATA)

# ============ STATIC FILES & DOWNLOADS ============

@app.route('/download/<filename>')
def download_file(filename):
    """Serve download files"""
    reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
    return send_from_directory(reports_dir, filename, as_attachment=True)

# ============ ERROR HANDLERS ============

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500

# ============ MAIN ENTRY POINT ============

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 DLP SECURITY SYSTEM WITH DATA INTEGRATION")
    print("=" * 60)
    print("✅ Real data integration from JSON files")
    print("✅ Report generation and download")
    print("✅ Enhanced API endpoints")
    print("✅ Threat management system")
    print("\n🌐 Access Points:")
    print("   Dashboard:     http://localhost:5001")
    print("   Scanner:       http://localhost:5001/scanner")
    print("   Monitor:       http://localhost:5001/monitor")
    print("   Alerts:        http://localhost:5001/alerts")
    print("   Threats:       http://localhost:5001/threats")
    print("   Users:         http://localhost:5001/users")
    print("   Policies:      http://localhost:5001/policies")
    print("   Reports:       http://localhost:5001/reports")
    print("   API Testing:   http://localhost:5001/api-testing")
    print("   Documentation: http://localhost:5001/docs")
    print("\n📊 Data Statistics:")
    print(f"   Total Scans:    {len(SCANS_DATA)}")
    print(f"   Total Threats:  {len(THREATS_DATA)}")
    print(f"   Total Users:    {len(USERS_DATA)}")
    print(f"   Total Policies: {len(POLICIES_DATA)}")
    print("=" * 60)
    
    app.run(debug=True, port=5001)
