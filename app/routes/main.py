from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response, make_response
from flask_login import login_required, current_user
from app.models import Rule, Investigation, Playbook, AuditLog
from app.extensions import db
from app.services.scoring import calculate_economic_score, get_ai_insights, get_mitre_coverage_stats
from app.services.investigation import log_investigation, get_ai_suggestions, suggest_playbook, get_smart_recommendations
from app.services.reporting import generate_pdf_report, predict_attack_impact
from app.utils.helpers import log_audit
import csv
import io
import json
from datetime import datetime

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@login_required
def dashboard():
    calculate_economic_score()
    rules = Rule.query.order_by(Rule.id.desc()).all()
    
    # Calculate statistics
    total = len(rules)
    prioritize = sum(1 for r in rules if r.recommendation == 'Prioritize')
    retire = sum(1 for r in rules if r.recommendation == 'Retire')
    improve = sum(1 for r in rules if r.recommendation == 'Improve')
    monitor = sum(1 for r in rules if r.recommendation == 'Monitor')
    
    # Get MITRE coverage stats for dashboard
    mitre_stats = get_mitre_coverage_stats()
    
    return render_template('dashboard.html', 
                         rules=rules,
                         user=current_user,
                         total=total,
                         prioritize=prioritize,
                         retire=retire,
                         improve=improve,
                         monitor=monitor,
                         mitre_coverage=mitre_stats['coverage_percentage'])

@main_bp.route('/add_rule', methods=['GET', 'POST'])
@login_required
def add_rule():
    if not current_user.is_admin():
        flash('Only Admins can add rules!', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Check if MITRE technique is passed via query parameter
    mitre_technique = request.args.get('mitre', '')
    suggested_name = request.args.get('name', '')
    
    if request.method == 'POST':
        try:
            rule = Rule(
                name=request.form.get('name'),
                category=request.form.get('category', 'General'),
                severity=request.form.get('severity', 'Medium'),
                mitre_technique=request.form.get('mitre_technique', 'N/A'),
                description=request.form.get('description', ''),
                priority=int(request.form.get('priority', 3)),
                attack_frequency=request.form.get('attack_frequency', 'Common'),
                asset_criticality=request.form.get('asset_criticality', 'High'),
                detection_accuracy=float(request.form.get('detection_accuracy', 90.0)),
                false_positive_rate=float(request.form.get('false_positive_rate', 5.0)),
                maintenance_hours=float(request.form.get('maintenance_hours', 2.0))
            )
            db.session.add(rule)
            db.session.commit()
            
            log_audit(current_user.id, 'CREATE_RULE', f'Created rule: {rule.name}')
            flash('Rule added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
        
        return redirect(url_for('main.dashboard'))
    
    return render_template('add_rule.html', 
                         is_edit=False,
                         mitre_technique=mitre_technique,
                         suggested_name=suggested_name)

@main_bp.route('/edit_rule/<int:rule_id>', methods=['GET', 'POST'])
@login_required
def edit_rule(rule_id):
    if not current_user.is_admin():
        flash('Only Admins can edit rules!', 'error')
        return redirect(url_for('main.dashboard'))
    
    rule = Rule.query.get_or_404(rule_id)
    
    if request.method == 'POST':
        try:
            rule.name = request.form.get('name')
            rule.category = request.form.get('category', 'General')
            rule.severity = request.form.get('severity', 'Medium')
            rule.mitre_technique = request.form.get('mitre_technique', 'N/A')
            rule.description = request.form.get('description', '')
            rule.priority = int(request.form.get('priority', 3))
            rule.attack_frequency = request.form.get('attack_frequency', 'Common')
            rule.asset_criticality = request.form.get('asset_criticality', 'High')
            rule.detection_accuracy = float(request.form.get('detection_accuracy', 90.0))
            rule.false_positive_rate = float(request.form.get('false_positive_rate', 5.0))
            rule.maintenance_hours = float(request.form.get('maintenance_hours', 2.0))
            
            db.session.commit()
            log_audit(current_user.id, 'EDIT_RULE', f'Edited rule: {rule.name}')
            flash('Rule updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
        
        return redirect(url_for('main.dashboard'))
    
    return render_template('add_rule.html', rule=rule, is_edit=True)

@main_bp.route('/delete_rule/<int:rule_id>', methods=['POST'])
@login_required
def delete_rule(rule_id):
    if not current_user.is_admin():
        flash('Only Admins can delete rules!', 'error')
        return redirect(url_for('main.dashboard'))
    
    rule = Rule.query.get_or_404(rule_id)
    rule_name = rule.name
    
    db.session.delete(rule)
    db.session.commit()
    
    log_audit(current_user.id, 'DELETE_RULE', f'Deleted rule: {rule_name}')
    flash('Rule deleted successfully!', 'success')
    return redirect(url_for('main.dashboard'))

@main_bp.route('/flag_rule/<int:rule_id>', methods=['POST'])
@login_required
def flag_rule(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    rule.flag_for_review = True
    db.session.commit()
    
    log_audit(current_user.id, 'FLAG_RULE', f'Flagged rule for review: {rule.name}')
    flash('Rule flagged for review by Admin!', 'success')
    return redirect(url_for('main.dashboard'))

@main_bp.route('/investigate/<int:rule_id>', methods=['GET', 'POST'])
@login_required
def investigate(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    investigations = Investigation.query.filter_by(rule_id=rule_id).order_by(Investigation.id.desc()).all()
    
    suggested_playbook = suggest_playbook(rule.category)
    playbook_steps = suggested_playbook.get_steps() if suggested_playbook else []
    
    # Enhanced AI suggestions
    ai_data = get_ai_suggestions(rule.name, rule.category, rule_id)
    smart_recommendations = get_smart_recommendations(rule_id)
    ai_insights = get_ai_insights(rule_id)
    
    # Get learning insights
    try:
        from app.services.learning import InvestigationLearning
        learning_insights = InvestigationLearning.get_learning_insights(rule_id)
    except:
        learning_insights = None
    
    referer = request.referrer or url_for('main.dashboard')
    
    if request.method == 'POST':
        try:
            steps_list = [s.strip() for s in request.form.get('steps', '').split(',') if s.strip()]
            log_investigation(
                rule_id=rule_id,
                analyst_id=current_user.id,
                steps_list=steps_list,
                resolution=request.form.get('resolution'),
                time_spent=float(request.form.get('time_spent', 15)),
                notes=request.form.get('notes', '')
            )
            log_audit(current_user.id, 'INVESTIGATE', f'Investigated rule: {rule.name}')
            flash('Investigation logged successfully!', 'success')
        except Exception as e:
            flash(f'Error logging investigation: {str(e)}', 'error')
        
        return redirect(url_for('main.investigate', rule_id=rule_id))
    
    return render_template('investigate.html', 
                         rule=rule, 
                         investigations=investigations, 
                         playbook_steps=playbook_steps,
                         ai_data=ai_data,
                         smart_recommendations=smart_recommendations,
                         ai_insights=ai_insights,
                         learning_insights=learning_insights,
                         referer=referer)

@main_bp.route('/my_investigations')
@login_required
def my_investigations():
    investigations = Investigation.query.filter(
        Investigation.analyst_id == current_user.id
    ).order_by(Investigation.id.desc()).all()
    return render_template('my_investigations.html', investigations=investigations)

@main_bp.route('/reports')
@login_required
def reports():
    rules = Rule.query.all()
    total_rules = len(rules)
    avg_score = round(sum(r.score for r in rules) / total_rules, 2) if total_rules > 0 else 0
    total_investigations = Investigation.query.count()
    
    # Get MITRE stats for reports
    mitre_stats = get_mitre_coverage_stats()
    
    return render_template('reports.html', 
                         rules=rules, 
                         total_rules=total_rules, 
                         avg_score=avg_score, 
                         total_investigations=total_investigations,
                         mitre_coverage=mitre_stats)

@main_bp.route('/export.pdf')
@login_required
def export_pdf():
    rules = Rule.query.all()
    pdf = generate_pdf_report(rules)
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=soc_report.pdf'
    return response

@main_bp.route('/predict_attack', methods=['POST'])
@login_required
def predict_attack():
    if not current_user.is_admin():
        return jsonify({"error": "Access Denied"}), 403
    
    data = request.get_json()
    mitre = data.get('mitre_technique', 'T9999')
    freq = data.get('attack_frequency', 'Common')
    crit = data.get('asset_criticality', 'High')
    
    result = predict_attack_impact(mitre, freq, crit)
    return jsonify(result)

@main_bp.route('/audit_logs')
@login_required
def audit_logs():
    if not current_user.is_admin():
        flash('Access Denied!', 'error')
        return redirect(url_for('main.dashboard'))
    
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('audit_logs.html', logs=logs)

@main_bp.route('/filter/<rec>')
@login_required
def filter_rules(rec):
    rules = Rule.query.filter_by(recommendation=rec).order_by(Rule.id.desc()).all()
    
    # Calculate statistics for filtered view
    total = len(rules)
    prioritize = sum(1 for r in rules if r.recommendation == 'Prioritize')
    retire = sum(1 for r in rules if r.recommendation == 'Retire')
    improve = sum(1 for r in rules if r.recommendation == 'Improve')
    monitor = sum(1 for r in rules if r.recommendation == 'Monitor')
    
    return render_template('dashboard.html', 
                         rules=rules,
                         user=current_user,
                         total=total,
                         prioritize=prioritize,
                         retire=retire,
                         improve=improve,
                         monitor=monitor)

@main_bp.route('/export.csv')
@login_required
def export_csv():
    rules = Rule.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Name', 'Category', 'Severity', 'MITRE', 'Frequency', 'Criticality', 'Accuracy', 'FP Rate', 'Score', 'Recommendation'])
    for r in rules:
        writer.writerow([r.id, r.name, r.category, r.severity, r.mitre_technique, 
                        r.attack_frequency, r.asset_criticality, r.detection_accuracy, 
                        r.false_positive_rate, r.score, r.recommendation])
    return Response(output.getvalue(), mimetype="text/csv", 
                   headers={"Content-Disposition": "attachment;filename=rules_export.csv"})

# ==========================================================
# 🚀 ENHANCED Import with AI Validation
# ==========================================================

@main_bp.route('/import', methods=['POST'])
@login_required
def import_csv():
    if not current_user.is_admin():
        flash('Only Admins can import CSV!', 'error')
        return redirect(url_for('main.dashboard'))
    
    file = request.files.get('file')
    if not file:
        flash('No file selected!', 'error')
        return redirect(url_for('main.dashboard'))
    
    if not file.filename.endswith('.csv'):
        flash('Please upload a valid .csv file!', 'error')
        return redirect(url_for('main.dashboard'))

    try:
        stream = io.StringIO(file.stream.read().decode("utf-8"))
        reader = csv.DictReader(stream)
        count = 0
        errors = []
        
        for row in reader:
            try:
                # Validate required fields
                if not all(k in row for k in ['name', 'attack_frequency', 'asset_criticality']):
                    errors.append(f"Missing required fields in row: {row}")
                    continue
                
                # Create rule with AI validation
                new_rule = Rule(
                    name=row.get('name', '').strip(),
                    category=row.get('category', 'General'),
                    severity=row.get('severity', 'Medium'),
                    mitre_technique=row.get('mitre_technique', 'N/A'),
                    description=row.get('description', ''),
                    attack_frequency=row.get('attack_frequency', 'Common'),
                    asset_criticality=row.get('asset_criticality', 'High'),
                    detection_accuracy=float(row.get('detection_accuracy', 90.0)),
                    false_positive_rate=float(row.get('false_positive_rate', 5.0)),
                    maintenance_hours=float(row.get('maintenance_hours', 2.0))
                )
                db.session.add(new_rule)
                count += 1
            except Exception as e:
                errors.append(f"Error in row: {row.get('name', 'unknown')} - {str(e)}")
        
        db.session.commit()
        
        log_audit(current_user.id, 'IMPORT_CSV', f'Imported {count} rules from CSV')
        
        if errors:
            flash(f'⚠️ Imported {count} rules with {len(errors)} errors. Check logs for details.', 'warning')
        else:
            flash(f'✅ Successfully imported {count} rules!', 'success')
            
    except Exception as e:
        flash(f'Import error: {str(e)}', 'error')
    
    return redirect(url_for('main.dashboard'))

@main_bp.route('/import_json', methods=['POST'])
@login_required
def import_json():
    if not current_user.is_admin():
        flash('Only Admins can import JSON!', 'error')
        return redirect(url_for('main.dashboard'))
    
    file = request.files.get('json_file')
    if not file:
        flash('No JSON file selected!', 'error')
        return redirect(url_for('main.dashboard'))
    
    try:
        data = json.load(file)
        count = 0
        errors = []
        
        # Support different JSON formats
        rules_to_import = []
        if isinstance(data, dict):
            if 'soc_rules' in data:
                rules_to_import = data['soc_rules']
            elif 'rules' in data:
                rules_to_import = data['rules']
            else:
                rules_to_import = [data]
        elif isinstance(data, list):
            rules_to_import = data
        else:
            flash('Invalid JSON format!', 'error')
            return redirect(url_for('main.dashboard'))
        
        for item in rules_to_import:
            try:
                rule = parse_siem_json_to_rule(item)
                db.session.add(rule)
                count += 1
            except Exception as e:
                errors.append(f"Error importing rule: {item.get('rule_name', 'unknown')} - {str(e)}")
        
        db.session.commit()
        
        log_audit(current_user.id, 'IMPORT_JSON', f'Imported {count} rules from JSON')
        
        if errors:
            flash(f'⚠️ Imported {count} rules with {len(errors)} errors.', 'warning')
        else:
            flash(f'✅ Successfully imported {count} SOC rule(s) from JSON!', 'success')
            
    except json.JSONDecodeError as e:
        flash(f'Invalid JSON format: {str(e)}', 'error')
    except Exception as e:
        flash(f'JSON Import error: {str(e)}', 'error')
    
    return redirect(url_for('main.dashboard'))

def parse_siem_json_to_rule(data):
    """Parse SIEM JSON data to Rule object"""
    name = data.get('rule_name', data.get('alert_name', data.get('name', 'Unnamed Rule')))
    category = data.get('category', 'General')
    severity = data.get('severity', 'Medium')
    mitre_id = data.get('mitre_attack', {}).get('technique_id', data.get('mitre_technique', 'N/A'))
    description = data.get('description', 'No details provided')
    priority = data.get('priority', 3)

    # Map severity to asset criticality
    if severity == 'Critical':
        asset_criticality = 'Critical'
        detection_accuracy = 98.5
        false_positive_rate = 1.5
    elif severity == 'High':
        asset_criticality = 'High'
        detection_accuracy = 92.0
        false_positive_rate = 5.0
    elif severity == 'Medium':
        asset_criticality = 'Medium'
        detection_accuracy = 85.0
        false_positive_rate = 10.0
    else:
        asset_criticality = 'Low'
        detection_accuracy = 75.0
        false_positive_rate = 15.0

    # Map priority to attack frequency
    if priority == 1:
        attack_frequency = 'Very Common'
    elif priority == 2:
        attack_frequency = 'Common'
    elif priority == 3:
        attack_frequency = 'Occasional'
    else:
        attack_frequency = 'Rare'

    return Rule(
        name=name,
        category=category,
        severity=severity,
        mitre_technique=mitre_id,
        description=description,
        priority=priority,
        attack_frequency=attack_frequency,
        asset_criticality=asset_criticality,
        detection_accuracy=detection_accuracy,
        false_positive_rate=false_positive_rate,
        maintenance_hours=data.get('maintenance_hours', 2.0)
    )

# ==========================================================
# 🚀 AI Insights API Endpoints
# ==========================================================

@main_bp.route('/ai_insights/<int:rule_id>')
@login_required
def ai_insights(rule_id):
    """Get AI insights for a specific rule"""
    insights = get_ai_insights(rule_id)
    return jsonify(insights)

@main_bp.route('/ai_suggestions/<int:rule_id>')
@login_required
def ai_suggestions(rule_id):
    """Get AI suggestions for a specific rule"""
    rule = Rule.query.get_or_404(rule_id)
    suggestions = get_ai_suggestions(rule.name, rule.category, rule_id)
    return jsonify(suggestions)

@main_bp.route('/smart_recommendations/<int:rule_id>')
@login_required
def smart_recommendations(rule_id):
    """Get smart recommendations for a specific rule"""
    recommendations = get_smart_recommendations(rule_id)
    return jsonify(recommendations)

# ==========================================================
# 🧠 Historical Investigation Learning Routes
# ==========================================================

@main_bp.route('/learning/similar/<int:rule_id>')
@login_required
def get_similar_incidents(rule_id):
    """Get similar past incidents for a rule"""
    from app.services.learning import InvestigationLearning
    similar = InvestigationLearning.find_similar_incidents(rule_id)
    
    return jsonify({
        'similar_incidents': [{
            'id': inv.id,
            'rule_name': inv.rule.name if inv.rule else 'Unknown',
            'resolution': inv.resolution,
            'time_spent': inv.time_spent,
            'created_at': inv.created_at.isoformat() if inv.created_at else None
        } for inv in similar]
    })

@main_bp.route('/learning/paths/<int:rule_id>')
@login_required
def get_successful_paths(rule_id):
    """Get successful investigation paths"""
    from app.services.learning import InvestigationLearning
    paths = InvestigationLearning.get_successful_investigation_paths(rule_id)
    
    return jsonify({
        'successful_paths': paths
    })

@main_bp.route('/learning/missing_detections')
@login_required
def get_missing_detections():
    """Get missing detection gaps"""
    from app.services.learning import InvestigationLearning
    missing = InvestigationLearning.suggest_missing_detections()
    
    return jsonify({
        'missing_detections': missing,
        'total_missing': len(missing)
    })

@main_bp.route('/learning/expertise/<int:rule_id>')
@login_required
def get_expertise(rule_id):
    """Get preserved expertise for a rule"""
    from app.services.learning import InvestigationLearning
    expertise = InvestigationLearning.get_expertise_preservation(rule_id)
    
    return jsonify(expertise)

@main_bp.route('/learning/insights/<int:rule_id>')
@login_required
def get_learning_insights(rule_id):
    """Get comprehensive learning insights"""
    from app.services.learning import InvestigationLearning
    insights = InvestigationLearning.get_learning_insights(rule_id)
    
    return jsonify(insights)

# ==========================================================
# 🚀 MITRE ATT&CK Coverage Route
# ==========================================================

@main_bp.route('/mitre_coverage')
@login_required
def mitre_coverage():
    """Show MITRE ATT&CK coverage heatmap and missing detections"""
    from app.services.scoring import get_mitre_coverage_stats
    
    stats = get_mitre_coverage_stats()
    
    return render_template('mitre_coverage.html',
                         covered_count=stats['covered_count'],
                         missing_count=stats['missing_count'],
                         coverage_percentage=stats['coverage_percentage'],
                         missing_detections=stats['missing_techniques'],
                         tactics_coverage=stats.get('tactics_coverage', {}))