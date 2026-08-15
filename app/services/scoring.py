from app.models import Rule, Investigation
from app.extensions import db, mail
from flask_mail import Message
from flask import current_app
import os
import json
from datetime import datetime, timedelta

CRITICALITY = {"Low": 1, "Medium": 2, "High": 3, "Critical": 5}
FREQUENCY = {"Rare": 1, "Occasional": 2, "Common": 3, "Very Common": 5}

def calculate_economic_score():
    """Calculate economic scores for all rules and send alerts"""
    rules = Rule.query.all()
    
    for rule in rules:
        freq_w = FREQUENCY.get(rule.attack_frequency, 1)
        crit_w = CRITICALITY.get(rule.asset_criticality, 1)
        
        # MITRE Weight (higher MITRE coverage = better value)
        mitre_w = 1.5 if rule.mitre_technique and rule.mitre_technique != 'N/A' else 1.0
        
        # AI Learning: Adjust based on past investigations
        ai_adjustment = calculate_ai_adjustment(rule.id)
        
        # Investigation time penalty
        time_cost = rule.maintenance_hours * 0.5
        
        numerator = (freq_w * crit_w * (rule.detection_accuracy / 100)) * 100 * mitre_w
        denominator = (rule.maintenance_hours * 2) + (rule.false_positive_rate * 0.5) + time_cost + 1
        
        # Apply AI adjustment
        rule.score = round((numerator / denominator) * (1 + ai_adjustment), 2)
        
        # Recommendation logic with AI enhancement
        if rule.score >= 10:
            rule.recommendation = 'Prioritize'
        elif rule.score >= 6:
            rule.recommendation = 'Monitor'
        elif rule.score >= 4:
            rule.recommendation = 'Improve'
        else:
            rule.recommendation = 'Retire'
        
        # Send email alerts for Retire rules
        if rule.recommendation == 'Retire' and not rule.email_sent:
            try:
                send_retire_alert(rule)
                rule.email_sent = True
            except Exception as e:
                print(f"Email failed for rule {rule.name}: {e}")
    
    db.session.commit()

def calculate_ai_adjustment(rule_id):
    """Calculate AI adjustment based on historical data"""
    # Get investigations from last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    investigations = Investigation.query.filter(
        Investigation.rule_id == rule_id,
        Investigation.created_at >= thirty_days_ago
    ).all()
    
    if not investigations:
        return 0.0
    
    # Calculate success rate
    true_positives = sum(1 for inv in investigations if inv.resolution == 'True_Positive')
    success_rate = true_positives / len(investigations) if investigations else 0
    
    # Calculate average investigation time
    avg_time = sum(inv.time_spent for inv in investigations) / len(investigations) if investigations else 0
    
    # AI Adjustment Logic
    if success_rate > 0.8 and avg_time < 20:
        return 0.2  # Boost score for efficient, accurate rules
    elif success_rate < 0.3:
        return -0.2  # Penalize low accuracy rules
    elif avg_time > 60:
        return -0.1  # Penalize time-consuming rules
    else:
        return 0.05

def send_retire_alert(rule):
    """Send email alert when a rule is marked for retirement"""
    try:
        msg = Message(
            subject=f"🚨 SOC Alert: Rule '{rule.name}' Marked for Retirement",
            recipients=[current_app.config.get('MAIL_DEFAULT_SENDER')],
            html=f"""
            <h2>Rule Retirement Alert</h2>
            <p><strong>Rule:</strong> {rule.name}</p>
            <p><strong>ID:</strong> #{rule.id}</p>
            <p><strong>Score:</strong> {rule.score}</p>
            <p><strong>Recommendation:</strong> {rule.recommendation}</p>
            <p><strong>MITRE Technique:</strong> {rule.mitre_technique}</p>
            <p><strong>Category:</strong> {rule.category}</p>
            <hr>
            <p><strong>Action Required:</strong> This rule is costing more than its value. Please review and consider deleting it.</p>
            <p><strong>AI Suggestion:</strong> Based on historical data, this rule has low ROI. Consider replacing with a more effective detection method.</p>
            """
        )
        mail.send(msg)
    except Exception as e:
        print(f"Email failed: {e}")

def get_ai_insights(rule_id):
    """Get AI insights for a specific rule"""
    rule = Rule.query.get(rule_id)
    if not rule:
        return {"error": "Rule not found"}
    
    investigations = Investigation.query.filter_by(rule_id=rule_id).all()
    
    if not investigations:
        return {
            "insights": ["No historical data available for this rule."],
            "suggestions": ["Log investigations to enable AI learning."],
            "total_investigations": 0,
            "resolution_stats": {},
            "avg_time": 0
        }
    
    # Analyze patterns
    resolutions = {}
    total_time = 0
    steps_used = {}
    
    for inv in investigations:
        resolutions[inv.resolution] = resolutions.get(inv.resolution, 0) + 1
        total_time += inv.time_spent
        
        if inv.steps:
            try:
                steps = json.loads(inv.steps)
                for step in steps:
                    steps_used[step] = steps_used.get(step, 0) + 1
            except:
                pass
    
    # Generate insights
    insights = []
    suggestions = []
    
    # Resolution analysis
    if resolutions.get('True_Positive', 0) > resolutions.get('False_Positive', 0):
        insights.append("✅ This rule has a good True Positive rate.")
    else:
        insights.append("⚠️ This rule has a high False Positive rate. Consider tuning.")
        suggestions.append("Review and adjust detection logic to reduce False Positives.")
    
    # Time analysis
    avg_time = total_time / len(investigations) if investigations else 0
    if avg_time > 30:
        insights.append(f"⏱️ Average investigation time is {avg_time:.1f} minutes.")
        suggestions.append("Consider automating parts of this investigation.")
    else:
        insights.append(f"✅ Fast investigation time: {avg_time:.1f} minutes average.")
    
    # Most used steps
    if steps_used:
        top_steps = sorted(steps_used.items(), key=lambda x: x[1], reverse=True)[:3]
        insights.append(f"📋 Most used steps: {', '.join([s[0] for s in top_steps])}")
    
    return {
        "insights": insights,
        "suggestions": suggestions,
        "total_investigations": len(investigations),
        "resolution_stats": resolutions,
        "avg_time": round(avg_time, 1)
    }

# ==========================================================
# 🚀 Attack Frequency Auto-Update
# ==========================================================

def update_attack_frequency():
    """
    Automatically update attack frequency based on recent investigations.
    This helps keep rule frequency metrics current without manual intervention.
    """
    rules = Rule.query.all()
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    
    updated_count = 0
    for rule in rules:
        # Count investigations in last 30 days as proxy for alerts
        recent_investigations = Investigation.query.filter(
            Investigation.rule_id == rule.id,
            Investigation.created_at >= thirty_days_ago
        ).count()
        
        # Determine new frequency based on activity
        old_frequency = rule.attack_frequency
        
        if recent_investigations >= 20:
            new_frequency = 'Very Common'
        elif recent_investigations >= 10:
            new_frequency = 'Common'
        elif recent_investigations >= 3:
            new_frequency = 'Occasional'
        else:
            new_frequency = 'Rare'
        
        # Update if changed
        if new_frequency != old_frequency:
            rule.attack_frequency = new_frequency
            updated_count += 1
    
    db.session.commit()
    print(f"✅ Updated attack frequencies for {updated_count} rules out of {len(rules)}")
    return updated_count

# ==========================================================
# 🚀 MITRE ATT&CK Coverage Statistics
# ==========================================================

def get_mitre_coverage_stats():
    """
    Get MITRE ATT&CK coverage statistics for the detection portfolio.
    Identifies gaps in coverage and provides recommendations.
    """
    all_rules = Rule.query.all()
    
    # Collect covered techniques
    covered_techniques = set()
    rules_by_technique = {}
    
    for rule in all_rules:
        if rule.mitre_technique and rule.mitre_technique != 'N/A':
            covered_techniques.add(rule.mitre_technique)
            if rule.mitre_technique not in rules_by_technique:
                rules_by_technique[rule.mitre_technique] = []
            rules_by_technique[rule.mitre_technique].append(rule.name)
    
    # Common MITRE techniques that should be covered
    common_techniques = {
        'T1110': {'name': 'Brute Force', 'tactic': 'Credential Access', 'priority': 'High'},
        'T1046': {'name': 'Network Service Scanning', 'tactic': 'Discovery', 'priority': 'Medium'},
        'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': 'Execution', 'priority': 'High'},
        'T1078': {'name': 'Valid Accounts', 'tactic': 'Defense Evasion', 'priority': 'High'},
        'T1087': {'name': 'Account Discovery', 'tactic': 'Discovery', 'priority': 'Medium'},
        'T1133': {'name': 'External Remote Services', 'tactic': 'Persistence', 'priority': 'High'},
        'T1190': {'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'priority': 'Critical'},
        'T1210': {'name': 'Exploitation of Remote Services', 'tactic': 'Lateral Movement', 'priority': 'High'},
        'T1550': {'name': 'Use Alternate Authentication Material', 'tactic': 'Lateral Movement', 'priority': 'Medium'},
        'T1562': {'name': 'Impair Defenses', 'tactic': 'Defense Evasion', 'priority': 'High'},
        'T1566': {'name': 'Phishing', 'tactic': 'Initial Access', 'priority': 'Critical'},
        'T1574': {'name': 'Hijack Execution Flow', 'tactic': 'Persistence', 'priority': 'Medium'},
        'T1585': {'name': 'Establish Accounts', 'tactic': 'Resource Development', 'priority': 'Medium'},
        'T1588': {'name': 'Obtain Capabilities', 'tactic': 'Resource Development', 'priority': 'Medium'},
        'T1589': {'name': 'Gather Victim Identity Information', 'tactic': 'Reconnaissance', 'priority': 'Medium'},
        'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact', 'priority': 'Critical'},
        'T1048': {'name': 'Exfiltration Over Alternative Protocol', 'tactic': 'Exfiltration', 'priority': 'High'},
        'T1572': {'name': 'Protocol Tunneling', 'tactic': 'Command and Control', 'priority': 'Medium'},
        'T1071': {'name': 'Application Layer Protocol', 'tactic': 'Command and Control', 'priority': 'Medium'},
        'T1204': {'name': 'User Execution', 'tactic': 'Execution', 'priority': 'High'},
    }
    
    # Find missing techniques with priority
    missing_techniques = []
    for tech_id, tech_info in common_techniques.items():
        if tech_id not in covered_techniques:
            missing_techniques.append({
                'technique_id': tech_id,
                'name': tech_info['name'],
                'tactic': tech_info['tactic'],
                'priority': tech_info['priority'],
                'suggested_rule_name': f"Detect {tech_info['name']} Activity",
                'suggested_category': tech_info['tactic']
            })
    
    # Sort missing by priority (Critical -> High -> Medium)
    priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    missing_techniques.sort(key=lambda x: priority_order.get(x['priority'], 3))
    
    # Calculate coverage statistics
    total_common = len(common_techniques)
    covered_count = len(covered_techniques.intersection(set(common_techniques.keys())))
    coverage_percentage = round((covered_count / total_common) * 100, 1) if total_common > 0 else 0
    
    # Group by tactic
    tactics_coverage = {}
    for tech_id, tech_info in common_techniques.items():
        tactic = tech_info['tactic']
        if tactic not in tactics_coverage:
            tactics_coverage[tactic] = {'total': 0, 'covered': 0}
        tactics_coverage[tactic]['total'] += 1
        if tech_id in covered_techniques:
            tactics_coverage[tactic]['covered'] += 1
    
    # Calculate tactic coverage percentages
    for tactic, data in tactics_coverage.items():
        data['percentage'] = round((data['covered'] / data['total']) * 100, 1) if data['total'] > 0 else 0
    
    return {
        'covered_count': covered_count,
        'total_common': total_common,
        'missing_count': len(missing_techniques),
        'coverage_percentage': coverage_percentage,
        'missing_techniques': missing_techniques,
        'covered_techniques': list(covered_techniques.intersection(set(common_techniques.keys()))),
        'tactics_coverage': tactics_coverage,
        'rules_by_technique': rules_by_technique,
        'total_rules': len(all_rules)
    }

# ==========================================================
# 🚀 Scheduled Tasks
# ==========================================================

def run_scheduled_tasks():
    """
    Run all scheduled background tasks:
    1. Update attack frequencies
    2. Recalculate economic scores
    3. Log activity
    """
    print("🔄 Running scheduled tasks...")
    
    # Update attack frequencies
    updated = update_attack_frequency()
    print(f"  ✓ Updated {updated} rule frequencies")
    
    # Recalculate scores
    calculate_economic_score()
    print(f"  ✓ Recalculated economic scores")
    
    print("✅ Scheduled tasks completed")
    return True