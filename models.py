from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    status = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f'<Agent {self.hostname}>'

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    process_name = db.Column(db.String(255), nullable=True)
    pid = db.Column(db.Integer, nullable=True)
    ppid = db.Column(db.Integer, nullable=True)
    user = db.Column(db.String(255), nullable=True)
    command_line = db.Column(db.String(255), nullable=True)
    local_address = db.Column(db.String(255), nullable=True)
    local_port = db.Column(db.Integer, nullable=True)
    remote_address = db.Column(db.String(255), nullable=True)
    remote_port = db.Column(db.Integer, nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)
    last_modified = db.Column(db.DateTime, nullable=True)
    cpu_usage = db.Column(db.Float, nullable=True)
    memory_usage = db.Column(db.Float, nullable=True)
    disk_usage = db.Column(db.Float, nullable=True)
    severity = db.Column(db.String(50), nullable=True)
    hostname = db.Column(db.String(255), nullable=True)
    mitre_technique = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'<Log {self.id}>'

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, nullable=False)
    rule_name = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    log_entry = db.Column(db.Text, nullable=False)  # Assuming this is a JSON string
    timestamp = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<Alert {self.id}>'

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    condition = db.Column(db.Text, nullable=False)  # Assuming this is a JSON string
    severity = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f'<Rule {self.id}>'