from app import app
from models import Rule, db

# Sample rule data
rule_data = {
    "id": "high_cpu_usage",
    "name": "Block High CPU Usage",
    "description": "Blocks processes consuming more than 80% CPU",
    "condition": {"field": "cpu_usage", "operator": ">", "value": 30},  # JSON object
    "severity": "High"
}

with app.app_context():
    existing_rule = Rule.query.get(rule_data['id'])
    
    if existing_rule:
        # Update existing rule
        existing_rule.name = rule_data['name']
        existing_rule.description = rule_data['description']
        existing_rule.condition = rule_data['condition']
        existing_rule.severity = rule_data['severity']
    else:
        # Insert new rule
        new_rule = Rule(**rule_data)
        db.session.add(new_rule)
    
    db.session.commit()

print("Rule added or updated successfully!")

