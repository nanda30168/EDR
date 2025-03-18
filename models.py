from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    process_name = db.Column(db.String(100), nullable=False)
    pid = db.Column(db.Integer, nullable=False)
    ppid = db.Column(db.Integer, nullable=False)
    user = db.Column(db.String(50), nullable=False)
    command_line = db.Column(db.String(200), nullable=False)
    local_address = db.Column(db.String(50), nullable=False)
    local_port = db.Column(db.Integer, nullable=False)
    remote_address = db.Column(db.String(50), nullable=False)
    remote_port = db.Column(db.Integer, nullable=False)
    file_path = db.Column(db.String(200), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    last_modified = db.Column(db.DateTime, nullable=True)
    cpu_usage = db.Column(db.Float, nullable=False)
    memory_usage = db.Column(db.Float, nullable=False)
    disk_usage = db.Column(db.Float, nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    hostname = db.Column(db.String(100), nullable=False)
    mitre_technique = db.Column(db.String(50), nullable=False)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, nullable=False)
    rule_name = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    log_entry = db.Column(db.Text, nullable=False)  # Store JSON as a string
    timestamp = db.Column(db.DateTime, nullable=False)

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    condition = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(50), nullable=False)

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50), default="connected")  # Default status is "connected"