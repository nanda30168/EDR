import json
import logging

class RuleEngine:
    def __init__(self, rules, debug=False):
        self.rules = rules  # Rules should be a list of objects with a 'condition' attribute
        self.debug = debug

    def evaluate(self, log_entry):
        alerts = []
        for rule in self.rules:
            condition = json.loads(rule['condition']) if isinstance(rule['condition'], str) else rule['condition']
            if self.debug:
                logging.debug(f"Evaluating rule: {rule['name']} with condition: {condition}")
            if self.evaluate_condition(log_entry, condition):
                logging.debug(f"Rule triggered: {rule['name']}")
                alerts.append(self.create_alert(log_entry, rule))
        return alerts

    def evaluate_condition(self, log_entry, condition):
        """ Evaluates the condition against a log entry """
        for key, value in condition.items():
            if key == "gt":  # Handle greater-than condition
                if key in log_entry and log_entry[key] <= value:
                    return False
            elif log_entry.get(key) != value:
                return False
        return True

    def create_alert(self, log_entry, rule):
        """ Creates an alert based on the log entry and rule """
        return {
            "rule_id": rule['id'],
            "rule_name": rule['name'],
            "severity": rule['severity'],
            "log_entry": log_entry
        }