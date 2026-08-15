"""
Historical Investigation Learning Service
Preserves analyst expertise and suggests similar incidents
"""
from app.models import Investigation, Rule, db
from app.extensions import db
import json
from datetime import datetime, timedelta
from difflib import SequenceMatcher

class InvestigationLearning:
    """AI-powered learning from historical investigations"""
    
    @staticmethod
    def find_similar_incidents(rule_id, limit=5):
        """Find similar past investigations based on rule category and resolution"""
        current_rule = Rule.query.get(rule_id)
        if not current_rule:
            return []
        
        # Find investigations from same category with successful resolution
        similar_invs = db.session.query(Investigation).join(Rule).filter(
            Rule.category == current_rule.category,
            Investigation.resolution == 'True_Positive',
            Investigation.rule_id != rule_id
        ).order_by(Investigation.created_at.desc()).limit(limit).all()
        
        return similar_invs
    
    @staticmethod
    def get_successful_investigation_paths(rule_id):
        """Extract successful investigation steps from past incidents"""
        rule = Rule.query.get(rule_id)
        if not rule:
            return []
        
        # Get all successful investigations for this rule
        successful_invs = Investigation.query.filter_by(
            rule_id=rule_id,
            resolution='True_Positive'
        ).order_by(Investigation.created_at.desc()).limit(10).all()
        
        paths = []
        for inv in successful_invs:
            if inv.steps:
                try:
                    steps = json.loads(inv.steps)
                    paths.append({
                        'steps': steps,
                        'time_spent': inv.time_spent,
                        'analyst_id': inv.analyst_id,
                        'created_at': inv.created_at,
                        'notes': inv.notes
                    })
                except:
                    continue
        
        return paths
    
    @staticmethod
    def suggest_missing_detections():
        """Identify gaps in detection coverage based on MITRE ATT&CK"""
        all_rules = Rule.query.all()
        covered_techniques = set()
        
        for rule in all_rules:
            if rule.mitre_technique and rule.mitre_technique != 'N/A':
                covered_techniques.add(rule.mitre_technique)
        
        # Common MITRE techniques that should be covered
        common_techniques = [
            'T1110',  # Brute Force
            'T1046',  # Network Service Scanning
            'T1059',  # Command and Scripting Interpreter
            'T1078',  # Valid Accounts
            'T1087',  # Account Discovery
            'T1133',  # External Remote Services
            'T1190',  # Exploit Public-Facing Application
            'T1210',  # Exploitation of Remote Services
            'T1550',  # Use Alternate Authentication Material
            'T1562',  # Impair Defenses
            'T1566',  # Phishing
            'T1574',  # Hijack Execution Flow
            'T1585',  # Establish Accounts
            'T1588',  # Obtain Capabilities
            'T1589',  # Gather Victim Identity Information
        ]
        
        missing_techniques = []
        for tech in common_techniques:
            if tech not in covered_techniques:
                missing_techniques.append(tech)
        
        # Get technique descriptions (simplified)
        technique_names = {
            'T1110': 'Brute Force',
            'T1046': 'Network Service Scanning',
            'T1059': 'Command and Scripting Interpreter',
            'T1078': 'Valid Accounts',
            'T1087': 'Account Discovery',
            'T1133': 'External Remote Services',
            'T1190': 'Exploit Public-Facing Application',
            'T1210': 'Exploitation of Remote Services',
            'T1550': 'Use Alternate Authentication Material',
            'T1562': 'Impair Defenses',
            'T1566': 'Phishing',
            'T1574': 'Hijack Execution Flow',
            'T1585': 'Establish Accounts',
            'T1588': 'Obtain Capabilities',
            'T1589': 'Gather Victim Identity Information',
        }
        
        return [
            {
                'technique_id': tech,
                'name': technique_names.get(tech, 'Unknown'),
                'priority': 'High' if tech in ['T1110', 'T1190', 'T1566'] else 'Medium'
            }
            for tech in missing_techniques
        ]
    
    @staticmethod
    def get_expertise_preservation(rule_id):
        """Preserve analyst expertise for a rule"""
        investigations = Investigation.query.filter_by(rule_id=rule_id).all()
        
        if not investigations:
            return {
                'total_analysts': 0,
                'common_steps': [],
                'best_practices': [],
                'avg_resolution_time': 0
            }
        
        # Collect all steps
        all_steps = []
        analysts = set()
        total_time = 0
        
        for inv in investigations:
            analysts.add(inv.analyst_id)
            total_time += inv.time_spent or 0
            if inv.steps:
                try:
                    steps = json.loads(inv.steps)
                    all_steps.extend(steps)
                except:
                    continue
        
        # Find most common steps
        from collections import Counter
        step_counter = Counter(all_steps)
        common_steps = step_counter.most_common(5)
        
        return {
            'total_analysts': len(analysts),
            'common_steps': [step for step, count in common_steps],
            'avg_resolution_time': round(total_time / len(investigations), 1) if investigations else 0,
            'total_investigations': len(investigations)
        }

    @staticmethod
    def get_learning_insights(rule_id):
        """Get comprehensive learning insights for a rule"""
        similar = InvestigationLearning.find_similar_incidents(rule_id)
        paths = InvestigationLearning.get_successful_investigation_paths(rule_id)
        expertise = InvestigationLearning.get_expertise_preservation(rule_id)
        
        insights = {
            'similar_incidents': len(similar),
            'successful_paths': paths[:3],  # Top 3 successful paths
            'expertise': expertise,
            'recommended_steps': []
        }
        
        # Generate recommended steps from successful paths
        if paths:
            all_steps = []
            for path in paths:
                all_steps.extend(path.get('steps', []))
            from collections import Counter
            step_counter = Counter(all_steps)
            insights['recommended_steps'] = [step for step, count in step_counter.most_common(5)]
        
        return insights