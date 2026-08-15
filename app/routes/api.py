from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import Rule, Investigation, AuditLog
from app.extensions import db
from app.services.scoring import calculate_economic_score
from app.services.investigation import log_investigation
from app.services.reporting import predict_attack_impact
import json
from datetime import datetime

api_bp = Blueprint('api', __name__)

# ==========================================================
# 📥 SIEM Integration Endpoints
# ==========================================================

@api_bp.route('/ingest', methods=['POST'])
@jwt_required()
def ingest_siem_alert():
    """
    Ingest a SIEM alert as a new rule
    Expected JSON format:
    {
        "rule_name": "Brute Force Attempt",
        "category": "Authentication",
        "severity": "High",
        "mitre_attack": {"technique_id": "T1110"},
        "description": "Multiple failed login attempts",
        "priority": 2,
        "attack_frequency": "Common",
        "asset_criticality": "High",
        "detection_accuracy": 92.0,
        "false_positive_rate": 5.0
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        # Parse SIEM JSON to Rule
        rule = parse_siem_json_to_rule(data)
        db.session.add(rule)
        db.session.commit()
        
        # Log the ingestion
        user_id = get_jwt_identity()
        audit = AuditLog(
            user_id=user_id,
            action='SIEM_INGEST',
            description=f'Ingested SIEM rule: {rule.name}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown')
        )
        db.session.add(audit)
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "message": "Rule ingested successfully",
            "id": rule.id,
            "score": rule.score,
            "recommendation": rule.recommendation
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def parse_siem_json_to_rule(data):
    """Parse SIEM JSON data to Rule object"""
    from app.models import Rule
    
    name = data.get('rule_name', data.get('alert_name', 'Unnamed SIEM Alert'))
    category = data.get('category', 'General')
    severity = data.get('severity', 'Medium')
    mitre_id = data.get('mitre_attack', {}).get('technique_id', 'N/A')
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
# 📊 Analytics & Statistics Endpoints
# ==========================================================

@api_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """Get system statistics"""
    try:
        total_rules = Rule.query.count()
        total_investigations = Investigation.query.count()
        
        # Recommendation distribution
        prioritize = Rule.query.filter_by(recommendation='Prioritize').count()
        monitor = Rule.query.filter_by(recommendation='Monitor').count()
        improve = Rule.query.filter_by(recommendation='Improve').count()
        retire = Rule.query.filter_by(recommendation='Retire').count()
        
        # Average score
        from sqlalchemy import func
        avg_score = db.session.query(func.avg(Rule.score)).scalar() or 0
        
        return jsonify({
            "total_rules": total_rules,
            "total_investigations": total_investigations,
            "recommendations": {
                "prioritize": prioritize,
                "monitor": monitor,
                "improve": improve,
                "retire": retire
            },
            "average_score": round(float(avg_score), 2),
            "timestamp": datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/rules', methods=['GET'])
@jwt_required()
def get_rules():
    """Get all rules with optional filtering"""
    try:
        # Get query parameters
        recommendation = request.args.get('recommendation')
        category = request.args.get('category')
        limit = request.args.get('limit', 100, type=int)
        
        query = Rule.query
        
        if recommendation:
            query = query.filter_by(recommendation=recommendation)
        if category:
            query = query.filter_by(category=category)
        
        rules = query.order_by(Rule.score.desc()).limit(limit).all()
        
        return jsonify({
            "rules": [{
                "id": r.id,
                "name": r.name,
                "category": r.category,
                "severity": r.severity,
                "mitre_technique": r.mitre_technique,
                "score": r.score,
                "recommendation": r.recommendation,
                "detection_accuracy": r.detection_accuracy,
                "false_positive_rate": r.false_positive_rate,
                "created_at": r.created_at.isoformat() if r.created_at else None
            } for r in rules]
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/rules/<int:rule_id>', methods=['GET'])
@jwt_required()
def get_rule(rule_id):
    """Get a specific rule by ID"""
    try:
        rule = Rule.query.get_or_404(rule_id)
        
        investigations = Investigation.query.filter_by(rule_id=rule_id).all()
        
        return jsonify({
            "id": rule.id,
            "name": rule.name,
            "category": rule.category,
            "severity": rule.severity,
            "mitre_technique": rule.mitre_technique,
            "description": rule.description,
            "attack_frequency": rule.attack_frequency,
            "asset_criticality": rule.asset_criticality,
            "detection_accuracy": rule.detection_accuracy,
            "false_positive_rate": rule.false_positive_rate,
            "maintenance_hours": rule.maintenance_hours,
            "score": rule.score,
            "recommendation": rule.recommendation,
            "flag_for_review": rule.flag_for_review,
            "created_at": rule.created_at.isoformat() if rule.created_at else None,
            "investigations": [{
                "id": inv.id,
                "analyst_id": inv.analyst_id,
                "resolution": inv.resolution,
                "time_spent": inv.time_spent,
                "created_at": inv.created_at.isoformat() if inv.created_at else None
            } for inv in investigations]
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================================
# 🔮 Prediction Endpoint
# ==========================================================

@api_bp.route('/predict', methods=['POST'])
@jwt_required()
def predict():
    """Predict attack impact"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        mitre = data.get('mitre_technique', 'T9999')
        freq = data.get('attack_frequency', 'Common')
        crit = data.get('asset_criticality', 'High')
        
        result = predict_attack_impact(mitre, freq, crit)
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================================
# 📝 Investigation Endpoints
# ==========================================================

@api_bp.route('/investigations', methods=['GET'])
@jwt_required()
def get_investigations():
    """Get investigations with optional filtering"""
    try:
        rule_id = request.args.get('rule_id')
        analyst_id = request.args.get('analyst_id')
        
        query = Investigation.query
        
        if rule_id:
            query = query.filter_by(rule_id=rule_id)
        if analyst_id:
            query = query.filter_by(analyst_id=analyst_id)
        
        investigations = query.order_by(Investigation.created_at.desc()).limit(100).all()
        
        return jsonify({
            "investigations": [{
                "id": inv.id,
                "rule_id": inv.rule_id,
                "analyst_id": inv.analyst_id,
                "resolution": inv.resolution,
                "time_spent": inv.time_spent,
                "steps": inv.get_steps(),
                "notes": inv.notes,
                "created_at": inv.created_at.isoformat() if inv.created_at else None
            } for inv in investigations]
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/investigations', methods=['POST'])
@jwt_required()
def create_investigation():
    """Create a new investigation"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        user_id = get_jwt_identity()
        
        inv_id = log_investigation(
            rule_id=data.get('rule_id'),
            analyst_id=user_id,
            steps_list=data.get('steps', []),
            resolution=data.get('resolution', 'Benign'),
            time_spent=float(data.get('time_spent', 15)),
            notes=data.get('notes', '')
        )
        
        return jsonify({
            "status": "success",
            "message": "Investigation logged successfully",
            "id": inv_id
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================================
# 🛡️ Health Check Endpoint
# ==========================================================

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "Detection Economics Engine",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }), 200