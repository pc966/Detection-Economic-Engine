from app.models import Rule
from flask import render_template
from weasyprint import HTML
import os

CRITICALITY = {"Low": 1, "Medium": 2, "High": 3, "Critical": 5}
FREQUENCY = {"Rare": 1, "Occasional": 2, "Common": 3, "Very Common": 5}

def generate_pdf_report(rules):
    """Generate professional PDF report"""
    html_content = render_template('pdf_report.html', rules=rules)
    pdf = HTML(string=html_content).write_pdf()
    return pdf

def predict_attack_impact(mitre_technique, attack_frequency, asset_criticality):
    """Adversary Evolution Predictor"""
    freq_w = FREQUENCY.get(attack_frequency, 1)
    crit_w = CRITICALITY.get(asset_criticality, 1)
    mitre_w = 1.5 if mitre_technique and mitre_technique != 'N/A' else 1.0
    
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