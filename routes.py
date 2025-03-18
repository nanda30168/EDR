from flask import Flask, request, jsonify, render_template
from datetime import datetime
from models import db, Log

app = Flask(__name__)
app.config.from_object('config.Config')
db.init_app(app)

def parse_datetime(datetime_str):
    return datetime.fromisoformat(datetime_str)

@app.route('/ingest', methods=['POST'])
def ingest_logs():
    data = request.json
    for item in data:
        log = Log(
            timestamp=parse_datetime(item['timestamp']),
            event_type=item.get('event_type'),
            process_name=item.get('process_name'),
            pid=item.get('pid'),
            ppid=item.get('ppid'),
            user=item.get('user'),
            command_line=item.get('command_line'),
            local_address=item.get('local_address'),
            local_port=item.get('local_port'),
            remote_address=item.get('remote_address'),
            remote_port=item.get('remote_port'),
            file_path=item.get('file_path'),
            file_size=item.get('file_size'),
            last_modified=parse_datetime(item['last_modified']) if item.get('last_modified') else None,
            cpu_usage=item.get('cpu_usage'),
            memory_usage=item.get('memory_usage'),
            disk_usage=item.get('disk_usage'),
            severity=item.get('severity'),
            hostname=item.get('hostname'),
            mitre_technique=item.get('mitre_technique')
        )
        db.session.add(log)
    db.session.commit()
    return jsonify({"status": "success"}), 200

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/logs')
def get_logs():
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    return jsonify([{
        'timestamp': log.timestamp.isoformat(),
        'event_type': log.event_type,
        'process_name': log.process_name,
        'pid': log.pid,
        'ppid': log.ppid,
        'user': log.user,
        'command_line': log.command_line,
        'local_address': log.local_address,
        'local_port': log.local_port,
        'remote_address': log.remote_address,
        'remote_port': log.remote_port,
        'file_path': log.file_path,
        'file_size': log.file_size,
        'last_modified': log.last_modified.isoformat() if log.last_modified else None,
        'cpu_usage': log.cpu_usage,
        'memory_usage': log.memory_usage,
        'disk_usage': log.disk_usage,
        'severity': log.severity,
        'hostname': log.hostname,
        'mitre_technique': log.mitre_technique
    } for log in logs])

@app.route('/view_logs')
def view_logs():
    return render_template('logs.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0')