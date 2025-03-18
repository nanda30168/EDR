from app import app
from models import Rule

with app.app_context():
    rules = Rule.query.all()
    for rule in rules:
        print(rule.id, rule.name, rule.description, rule.condition, rule.severity)

