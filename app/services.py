from .models import Rule, Investigation, Playbook, db
from flask_mail import Mail, Message
from flask import current_app, render_template
import json
import os
from weasyprint import HTML

# Email Setup
mail = Mail()

CRITICALITY = {"Low": 1, "Medium": 2, "High": 3, "Critical": 5} 
FREQUENCY = {"Rare": 1, "Occasional": 2, "Common": 3, "Very Common": 5}

def calculate_economic_score():
    """Loop through all rules, update scores, and send email alerts"""
    rules = Rule.query.all()
    for rule in rules:
        freq_w = FREQUENCY.get(rule.attack_frequency, 1)
        crit_w = CRITICALITY.get(rule.asset_criticality, 1)
        
        # 🚀 NEW: MITRE Weight (Higher MITRE coverage = Better value)
        mitre_w = 1.0
        if rule.mitre_technique and rule.mitre_technique != 'N/A':
            mitre_w = 1.5  # Bonus for having MITRE mapping
        
        # 🚀 NEW: Investigation Time Penalty (Longer investigation = Higher cost)
        # Using maintenance_hours as a proxy for avg investigation time
        time_cost = rule.maintenance_hours * 0.5 
        
        numerator = (freq_w * crit_w * (rule.detection_accuracy / 100)) * 100 * mitre_w
        denominator = (rule.maintenance_hours * 2) + (rule.false_positive_rate * 0.5) + time_cost + 1
        
        rule.score = round(numerator / denominator, 2)

        if rule.score >= 8:
            rule.recommendation = 'Prioritize'
        elif rule.score < 4:
            rule.recommendation = 'Retire'
        else:
            rule.recommendation = 'Monitor'
            
        # EMAIL ALERT
        if rule.recommendation == 'Retire' and not rule.email_sent:
            try:
                msg = Message(
                    subject=f"🚨 SOC Alert: Rule '{rule.name}' Marked for Retirement",
                    recipients=[os.getenv('MAIL_DEFAULT_SENDER')],
                    body=f"""
                    Rule ID: {rule.id}
                    Name: {rule.name}
                    Score: {rule.score}
                    Recommendation: {rule.recommendation}
                    MITRE: {rule.mitre_technique}
                    
                    Action Required: This rule is costing more than its value. Please review and consider deleting it.
                    """
                )
                mail.send(msg)
                rule.email_sent = True
                print(f"📧 Email sent for rule: {rule.name}")
            except Exception as e:
                print(f"Email failed: {e}")
            
    db.session.commit()

def log_investigation(rule_id, analyst_id, steps_list, resolution, time_spent):
    inv = Investigation(
        rule_id=rule_id,
        analyst_id=analyst_id,
        steps=json.dumps(steps_list),  
        resolution=resolution,
        time_spent=time_spent
    )
    db.session.add(inv)
    db.session.commit()
    return inv.id

def parse_siem_json_to_rule(json_data):
    name = json_data.get('rule_name', json_data.get('alert_name', 'Unnamed SIEM Alert'))
    category = json_data.get('category', 'General')
    severity = json_data.get('severity', 'Medium')
    mitre_id = json_data.get('mitre_attack', {}).get('technique_id', 'N/A')
    description = json_data.get('description', 'No details provided')
    priority = json_data.get('priority', 3)

    if severity == 'Critical': asset_criticality = 'Critical'
    elif severity == 'High': asset_criticality = 'High'
    elif severity == 'Medium': asset_criticality = 'Medium'
    else: asset_criticality = 'Low'

    if priority == 1: attack_frequency = 'Very Common'
    elif priority == 2: attack_frequency = 'Common'
    elif priority == 3: attack_frequency = 'Occasional'
    else: attack_frequency = 'Rare'

    if severity == 'Critical':
        detection_accuracy = 98.5; false_positive_rate = 1.5
    elif severity == 'High':
        detection_accuracy = 92.0; false_positive_rate = 5.0
    elif severity == 'Medium':
        detection_accuracy = 85.0; false_positive_rate = 10.0
    else:
        detection_accuracy = 75.0; false_positive_rate = 15.0

    return Rule(
        name=name, category=category, severity=severity, mitre_technique=mitre_id,
        description=description, priority=priority, attack_frequency=attack_frequency,
        asset_criticality=asset_criticality, detection_accuracy=detection_accuracy,
        false_positive_rate=false_positive_rate, maintenance_hours=2.0
    )

def suggest_playbook(category):
    playbooks = Playbook.query.filter_by(category=category).all()
    if playbooks:
        return playbooks[0]
    return None

def create_default_playbooks():
    if Playbook.query.count() == 0:
        p1 = Playbook(name="Ransomware Response", category="Malware/Ransomware", steps=json.dumps(["Isolate host", "Check backups", "Notify CISO"]))
        p2 = Playbook(name="Brute Force Mitigation", category="Authentication", steps=json.dumps(["Block IP on firewall", "Check for lateral movement", "Force password reset"]))
        db.session.add_all([p1, p2])
        db.session.commit()
        print("✅ Default playbooks created.")

# ==========================================================
# 🚀 FUNCTION 1: AI Historical Learning
# ==========================================================
def get_ai_suggestions(rule_name, category):
    past_invs = db.session.query(Investigation).join(Rule).filter(
        Rule.category == category,
        Investigation.resolution == 'True_Positive'
    ).order_by(Investigation.created_at.desc()).limit(5).all()
    
    if not past_invs:
        return None
    
    steps_counter = {}
    for inv in past_invs:
        steps = json.loads(inv.steps)
        for step in steps:
            steps_counter[step] = steps_counter.get(step, 0) + 1
    
    top_steps = sorted(steps_counter.items(), key=lambda x: x[1], reverse=True)[:3]
    return [step for step, count in top_steps]

# ==========================================================
# 🚀 FUNCTION 2: Professional PDF Report Generator
# ==========================================================
def generate_pdf_report(rules):
    html_content = render_template('pdf_report.html', rules=rules)
    pdf = HTML(string=html_content).write_pdf()
    return pdf

# ==========================================================
# 🚀 NEW FUNCTION 3: Adversary Evolution Predictor
# ==========================================================
def predict_attack_impact(mitre_technique, attack_frequency, asset_criticality):
    """
    Adversary Evolution Predictor.
    Calculates what the score WOULD BE if a new technique is added.
    """
    freq_w = FREQUENCY.get(attack_frequency, 1)
    crit_w = CRITICALITY.get(asset_criticality, 1)
    mitre_w = 1.5 if mitre_technique and mitre_technique != 'N/A' else 1.0
    
    # Predict based on standard averages for new rules
    predicted_accuracy = 90.0
    predicted_fp = 5.0
    predicted_maintenance = 2.0
    
    numerator = (freq_w * crit_w * (predicted_accuracy / 100)) * 100 * mitre_w
    denominator = (predicted_maintenance * 2) + (predicted_fp * 0.5) + (predicted_maintenance * 0.5) + 1
    
    predicted_score = round(numerator / denominator, 2)
    
    return {
        "technique": mitre_technique,
        "predicted_score": predicted_score,
        "predicted_recommendation": "Prioritize" if predicted_score >= 8 else "Monitor"
    }