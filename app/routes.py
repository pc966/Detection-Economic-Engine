from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response, make_response
from flask_login import login_user, logout_user, login_required, current_user
from flask_jwt_extended import jwt_required
from .models import User, Rule, Investigation, Playbook, AuditLog
from . import db
from .services import (
    calculate_economic_score, 
    log_investigation, 
    parse_siem_json_to_rule, 
    suggest_playbook, 
    create_default_playbooks, 
    get_ai_suggestions, 
    generate_pdf_report,
    predict_attack_impact
)
import csv
import io
import json
import os

auth_bp = Blueprint('auth', __name__)
main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__)

# ----------------- AUTHENTICATION -----------------
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        flash('Invalid Credentials')
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

# ----------------- DASHBOARD & RULES -----------------
@main_bp.route('/')
@login_required
def dashboard():
    create_default_playbooks()
    calculate_economic_score()
    rules = Rule.query.order_by(Rule.id.desc()).all()
    return render_template('dashboard.html', rules=rules, user=current_user)

@main_bp.route('/add_rule', methods=['GET', 'POST'])
@login_required
def add_rule():
    if current_user.role != 'admin':
        flash('❌ Only Admins can add rules!', 'error')
        return redirect(url_for('main.dashboard'))
    if request.method == 'POST':
        try:
            new_rule = Rule(
                name=request.form['name'],
                attack_frequency=request.form['attack_frequency'],
                asset_criticality=request.form['asset_criticality'],
                detection_accuracy=float(request.form['detection_accuracy']),
                false_positive_rate=float(request.form['false_positive_rate']),
                maintenance_hours=float(request.form['maintenance_hours'])
            )
            db.session.add(new_rule)
            db.session.commit()
            flash('✅ Rule added successfully!', 'success')
        except Exception as e:
            flash(f'❌ Error: {str(e)}', 'error')
        return redirect(url_for('main.dashboard'))
    return render_template('add_rule.html')

@main_bp.route('/edit_rule/<int:rule_id>', methods=['GET', 'POST'])
@login_required
def edit_rule(rule_id):
    if current_user.role != 'admin':
        flash('❌ Only Admins can edit rules!', 'error')
        return redirect(url_for('main.dashboard'))
    rule = Rule.query.get_or_404(rule_id)
    if request.method == 'POST':
        try:
            rule.name = request.form['name']
            rule.attack_frequency = request.form['attack_frequency']
            rule.asset_criticality = request.form['asset_criticality']
            rule.detection_accuracy = float(request.form['detection_accuracy'])
            rule.false_positive_rate = float(request.form['false_positive_rate'])
            rule.maintenance_hours = float(request.form['maintenance_hours'])
            db.session.commit()
            flash('✅ Rule updated successfully!', 'success')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            flash(f'❌ Error: {str(e)}', 'error')
    return render_template('add_rule.html', rule=rule, is_edit=True)

@main_bp.route('/delete_rule/<int:rule_id>', methods=['POST'])
@login_required
def delete_rule(rule_id):
    if current_user.role != 'admin':
        flash('❌ Only Admins can delete rules!', 'error')
        return redirect(url_for('main.dashboard'))
    rule = Rule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    flash('🗑️ Rule deleted successfully!', 'success')
    return redirect(url_for('main.dashboard'))

# ----------------- ANALYST FEATURES -----------------
@main_bp.route('/flag_rule/<int:rule_id>', methods=['POST'])
@login_required
def flag_rule(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    rule.flag_for_review = True
    db.session.commit()
    flash('📌 Rule flagged for review by Admin!', 'success')
    return redirect(url_for('main.dashboard'))

@main_bp.route('/my_investigations')
@login_required
def my_investigations():
    my_invs = Investigation.query.filter(
        Investigation.analyst_id == current_user.id,
        Investigation.rule_id.isnot(None)
    ).order_by(Investigation.id.desc()).all()
    return render_template('my_investigations.html', investigations=my_invs)

# ----------------- INVESTIGATION (With AI Learning) -----------------
@main_bp.route('/investigate/<int:rule_id>', methods=['GET', 'POST'])
@login_required
def investigate(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    investigations = Investigation.query.filter_by(rule_id=rule_id).order_by(Investigation.id.desc()).all()
    
    suggested_playbook = suggest_playbook(rule.category)
    playbook_steps = json.loads(suggested_playbook.steps) if suggested_playbook else []
    ai_suggestions = get_ai_suggestions(rule.name, rule.category)
    
    # 🚀 FIX: Pichla page yaad rakhna (Referer)
    referer = request.referrer if request.referrer else url_for('main.dashboard')
    
    if request.method == 'POST':
        steps_list = [s.strip() for s in request.form['steps'].split(',') if s.strip()]
        log_investigation(
            rule_id=rule_id,
            analyst_id=current_user.id,
            steps_list=steps_list,
            resolution=request.form['resolution'],
            time_spent=float(request.form['time_spent'])
        )
        flash('✅ Investigation logged successfully!', 'success')
        return redirect(url_for('main.investigate', rule_id=rule_id))
        
    return render_template('investigate.html', rule=rule, investigations=investigations, playbook_steps=playbook_steps, ai_suggestions=ai_suggestions, referer=referer)

# ----------------- REPORTS & PDF -----------------
@main_bp.route('/reports')
@login_required
def reports():
    rules = Rule.query.all()
    total_rules = len(rules)
    avg_score = round(sum(r.score for r in rules) / total_rules, 2) if total_rules > 0 else 0
    total_investigations = Investigation.query.count()
    return render_template('reports.html', rules=rules, total_rules=total_rules, avg_score=avg_score, total_investigations=total_investigations)

@main_bp.route('/export.pdf')
@login_required
def export_pdf():
    rules = Rule.query.all()
    pdf = generate_pdf_report(rules)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=soc_report.pdf'
    return response

# ----------------- 🚀 NEW: ADVANCED FEATURES -----------------

# 1. Adversary Evolution Predictor API
@main_bp.route('/predict_attack', methods=['POST'])
@login_required
def predict_attack():
    if current_user.role != 'admin':
        return jsonify({"error": "Access Denied"}), 403
        
    data = request.get_json()
    mitre = data.get('mitre_technique', 'T9999')
    freq = data.get('attack_frequency', 'Common')
    crit = data.get('asset_criticality', 'High')
    
    result = predict_attack_impact(mitre, freq, crit)
    return jsonify(result)

# 2. System Audit Logs (Only for Admin)
@main_bp.route('/audit_logs')
@login_required
def audit_logs():
    if current_user.role != 'admin':
        flash('Access Denied!', 'error')
        return redirect(url_for('main.dashboard'))
    logs = AuditLog.query.filter(AuditLog.user_id.isnot(None)).order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_logs.html', logs=logs)

# 3. Filter Dashboard by Recommendation
@main_bp.route('/filter/<rec>')
@login_required
def filter_rules(rec):
    rules = Rule.query.filter_by(recommendation=rec).order_by(Rule.id.desc()).all()
    return render_template('dashboard.html', rules=rules, user=current_user)

# ----------------- IMPORT / EXPORT -----------------
@main_bp.route('/export.csv')
@login_required
def export_csv():
    rules = Rule.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Name', 'Frequency', 'Criticality', 'Accuracy', 'FP Rate', 'Score', 'Recommendation'])
    for r in rules:
        writer.writerow([r.id, r.name, r.attack_frequency, r.asset_criticality, r.detection_accuracy, r.false_positive_rate, r.score, r.recommendation])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=rules_export.csv"})

@main_bp.route('/import', methods=['POST'])
@login_required
def import_csv():
    if current_user.role != 'admin':
        flash('❌ Only Admins can import CSV!', 'error')
        return redirect(url_for('main.dashboard'))
    
    file = request.files.get('file')
    if not file:
        flash('❌ No file selected!', 'error')
        return redirect(url_for('main.dashboard'))
    
    # 🚀 FIX: Check if file is a valid CSV
    if not file.filename.endswith('.csv'):
        flash('❌ Please upload a valid .csv file!', 'error')
        return redirect(url_for('main.dashboard'))

    try:
        stream = io.StringIO(file.stream.read().decode("utf-8"))
        reader = csv.DictReader(stream)
        count = 0
        for row in reader:
            if all(k in row for k in ['name', 'attack_frequency', 'asset_criticality', 'detection_accuracy', 'false_positive_rate']):
                new_rule = Rule(
                    name=row['name'],
                    attack_frequency=row['attack_frequency'],
                    asset_criticality=row['asset_criticality'],
                    detection_accuracy=float(row['detection_accuracy']),
                    false_positive_rate=float(row['false_positive_rate']),
                    maintenance_hours=float(row.get('maintenance_hours', 2.0))
                )
                db.session.add(new_rule)
                count += 1
        db.session.commit()
        flash(f'✅ Successfully imported {count} rules!', 'success')
    except Exception as e:
        flash(f'❌ Import error: {str(e)}', 'error')
    return redirect(url_for('main.dashboard'))

@main_bp.route('/import_json', methods=['POST'])
@login_required
def import_json():
    if current_user.role != 'admin':
        flash('❌ Only Admins can import JSON!', 'error')
        return redirect(url_for('main.dashboard'))
    file = request.files.get('json_file')
    if not file:
        flash('❌ No JSON file selected!', 'error')
        return redirect(url_for('main.dashboard'))
    try:
        data = json.load(file)
        count = 0
        if isinstance(data, dict) and 'soc_rules' in data:
            for item in data['soc_rules']:
                db.session.add(parse_siem_json_to_rule(item))
                count += 1
        elif isinstance(data, list):
            for item in data:
                db.session.add(parse_siem_json_to_rule(item))
                count += 1
        else:
            db.session.add(parse_siem_json_to_rule(data))
            count = 1
        db.session.commit()
        flash(f'✅ Successfully imported {count} real SOC rule(s) from JSON!', 'success')
    except Exception as e:
        flash(f'❌ JSON Import error: {str(e)}', 'error')
    return redirect(url_for('main.dashboard'))

# ----------------- API ENDPOINTS (SIEM Integration) -----------------
@api_bp.route('/ingest', methods=['POST'])
@jwt_required()
def ingest_siem_alert():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        new_rule = parse_siem_json_to_rule(data)
        db.session.add(new_rule)
        db.session.commit()
        return jsonify({"status": "Ingested successfully", "id": new_rule.id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500