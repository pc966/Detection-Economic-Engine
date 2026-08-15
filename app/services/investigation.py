from app.models import Investigation, Rule, Playbook, db
import json
from datetime import datetime, timedelta

def log_investigation(rule_id, analyst_id, steps_list, resolution, time_spent, notes=''):
    inv = Investigation(
        rule_id=rule_id,
        analyst_id=analyst_id,
        steps=json.dumps(steps_list),
        resolution=resolution,
        time_spent=time_spent,
        notes=notes
    )
    db.session.add(inv)
    db.session.commit()
    return inv.id

def get_ai_suggestions(rule_name, category, rule_id=None):
    """Get AI suggestions based on past successful investigations"""
    # Get past successful investigations
    past_invs = db.session.query(Investigation).join(Rule).filter(
        Rule.category == category,
        Investigation.resolution == 'True_Positive'
    ).order_by(Investigation.created_at.desc()).limit(10).all()
    
    # Also get investigations for this specific rule
    if rule_id:
        rule_invs = Investigation.query.filter_by(
            rule_id=rule_id,
            resolution='True_Positive'
        ).order_by(Investigation.created_at.desc()).limit(5).all()
        past_invs = rule_invs + past_invs
    
    if not past_invs:
        return {
            "suggestions": ["No historical data available. Start logging investigations to enable AI learning."],
            "confidence": 0
        }
    
    # Analyze steps
    steps_counter = {}
    resolutions = []
    times = []
    
    for inv in past_invs:
        if inv.resolution:
            resolutions.append(inv.resolution)
        if inv.time_spent:
            times.append(inv.time_spent)
        if inv.steps:
            try:
                steps = json.loads(inv.steps)
                for step in steps:
                    steps_counter[step] = steps_counter.get(step, 0) + 1
            except:
                continue
    
    # Get top steps
    top_steps = sorted(steps_counter.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Calculate confidence based on data volume
    confidence = min(len(past_invs) / 20, 1.0) * 100  # Max 100%
    
    # Generate suggestions
    suggestions = []
    
    if top_steps:
        suggestions.append("📋 Recommended steps based on past successes:")
        for step, count in top_steps:
            suggestions.append(f"  • {step} (used in {count} investigations)")
    
    # Add recommendations based on resolution patterns
    if resolutions:
        true_positives = sum(1 for r in resolutions if r == 'True_Positive')
        success_rate = (true_positives / len(resolutions)) * 100
        if success_rate > 80:
            suggestions.append(f"✅ This approach has a {success_rate:.0f}% success rate")
        elif success_rate < 50:
            suggestions.append("⚠️ Consider alternative investigation approaches")
    
    # Time-based suggestions
    if times:
        avg_time = sum(times) / len(times)
        if avg_time > 45:
            suggestions.append(f"⏱️ Average investigation time: {avg_time:.1f} mins - Consider optimization")
        else:
            suggestions.append(f"✅ Good efficiency: {avg_time:.1f} mins average")
    
    return {
        "suggestions": suggestions,
        "confidence": round(confidence, 1),
        "total_analyzed": len(past_invs)
    }

def suggest_playbook(category):
    playbooks = Playbook.query.filter_by(category=category).all()
    return playbooks[0] if playbooks else None

def get_smart_recommendations(rule_id):
    """Get smart recommendations for a rule"""
    rule = Rule.query.get(rule_id)
    if not rule:
        return {"error": "Rule not found"}
    
    recommendations = []
    
    # Analyze rule performance
    investigations = Investigation.query.filter_by(rule_id=rule_id).all()
    
    if not investigations:
        return {
            "recommendations": [
                "📝 Start logging investigations to get personalized recommendations",
                "🔍 Consider testing this rule in a controlled environment"
            ]
        }
    
    # Calculate metrics
    total = len(investigations)
    true_pos = sum(1 for i in investigations if i.resolution == 'True_Positive')
    false_pos = sum(1 for i in investigations if i.resolution == 'False_Positive')
    
    # Generate recommendations
    if total > 5:
        if false_pos / total > 0.3:
            recommendations.append("⚠️ High False Positive rate detected. Consider:")
            recommendations.append("  • Adjust threshold values")
            recommendations.append("  • Add additional validation checks")
            recommendations.append("  • Review the detection logic")
        
        if true_pos / total > 0.8:
            recommendations.append("✅ Excellent True Positive rate. Consider:")
            recommendations.append("  • Deploy to more environments")
            recommendations.append("  • Share this rule with the team")
        
        # Score-based recommendations
        if rule.score < 5:
            recommendations.append("📉 Low economic score. Consider:")
            recommendations.append("  • Improving detection accuracy")
            recommendations.append("  • Reducing maintenance overhead")
            recommendations.append("  • Automating response actions")
        elif rule.score > 9:
            recommendations.append("🏆 High value rule! Maintain and monitor:")
            recommendations.append("  • Document best practices")
            recommendations.append("  • Train junior analysts on this rule")
    
    return {
        "recommendations": recommendations,
        "metrics": {
            "total_investigations": total,
            "true_positive_rate": round((true_pos / total) * 100, 1) if total > 0 else 0,
            "false_positive_rate": round((false_pos / total) * 100, 1) if total > 0 else 0
        }
    }