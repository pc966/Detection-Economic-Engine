// ==========================================================
// Detection Economics Engine - Main JavaScript
// ==========================================================

// ==========================================================
// 📊 Chart Initialization
// ==========================================================

function initCharts() {
    const chartCanvas = document.getElementById('topRulesChart');
    if (!chartCanvas) return;

    const ctx = chartCanvas.getContext('2d');
    const ruleNames = JSON.parse(chartCanvas.dataset.names || '[]');
    const ruleScores = JSON.parse(chartCanvas.dataset.scores || '[]');
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ruleNames,
            datasets: [{
                label: 'Score',
                data: ruleScores,
                backgroundColor: [
                    'rgba(59, 130, 246, 0.7)',
                    'rgba(16, 185, 129, 0.7)',
                    'rgba(234, 179, 8, 0.7)',
                    'rgba(139, 92, 246, 0.7)',
                    'rgba(236, 72, 153, 0.7)'
                ],
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#9ca3af' }
                },
                x: {
                    grid: { display: false },
                    ticks: {
                        color: '#9ca3af',
                        maxRotation: 15,
                        font: { size: 10 }
                    }
                }
            }
        }
    });
}

// ==========================================================
// 🔍 Search Functionality
// ==========================================================

function handleSearch(inputElement) {
    const query = inputElement.value.toLowerCase();
    const rows = document.querySelectorAll('#rulesTableBody tr');
    
    rows.forEach(row => {
        const name = row.querySelector('.rule-name');
        if (name) {
            const text = name.innerText.toLowerCase();
            row.style.display = text.includes(query) ? '' : 'none';
        }
    });
}

// ==========================================================
# 🔮 Predict Attack Functionality
// ==========================================================

async function predictAttack() {
    const mitre = document.getElementById('pred_mitre')?.value || '';
    const freq = document.getElementById('pred_freq')?.value || 'Common';
    const crit = document.getElementById('pred_crit')?.value || 'High';
    const resultDiv = document.getElementById('pred_result');
    const scoreSpan = document.getElementById('pred_score');
    const recSpan = document.getElementById('pred_rec');
    
    if (!resultDiv || !scoreSpan || !recSpan) return;
    
    try {
        const response = await fetch('/predict_attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                mitre_technique: mitre,
                attack_frequency: freq,
                asset_criticality: crit
            })
        });
        
        if (response.ok) {
            const data = await response.json();
            scoreSpan.innerText = data.predicted_score || '0.0';
            recSpan.innerText = data.predicted_recommendation || 'Monitor';
            resultDiv.classList.remove('hidden');
        } else {
            const error = await response.json();
            showToast(error.error || 'Error predicting attack', 'error');
        }
    } catch (error) {
        showToast('Network error: ' + error.message, 'error');
    }
}

// ==========================================================
# 🪟 Modal Functions
// ==========================================================

function openRuleDetails(id, name, score, rec, acc, fp) {
    const modal = document.getElementById('ruleModal');
    if (!modal) return;
    
    document.getElementById('modalRuleName').innerText = name + ' (#' + id + ')';
    document.getElementById('modalScore').innerText = score || '0.0';
    document.getElementById('modalRec').innerText = rec || 'Monitor';
    document.getElementById('modalAcc').innerText = (acc || 0) + '%';
    document.getElementById('modalFp').innerText = (fp || 0) + '%';
    
    let analysis = 'This rule is currently in ' + (rec || 'Monitor') + ' status. ';
    if (rec === 'Prioritize') analysis += 'High value asset protection required.';
    else if (rec === 'Retire') analysis += 'Consider removal due to cost-benefit ratio.';
    else if (rec === 'Improve') analysis += 'Optimization needed for better performance.';
    else analysis += 'Monitor periodically for changes.';
    document.getElementById('modalAnalysis').innerText = analysis;
    
    const investigateBtn = document.getElementById('modalInvestigateBtn');
    if (investigateBtn) {
        investigateBtn.href = '/investigate/' + id;
    }
    
    modal.classList.add('active');
}

function closeModal() {
    const modal = document.getElementById('ruleModal');
    if (modal) {
        modal.classList.remove('active');
    }
}

function closeModalOutside(e) {
    if (e.target === e.currentTarget) {
        closeModal();
    }
}

// ==========================================================
# 🔔 Toast Notifications
// ==========================================================

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.innerText = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100px)';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// ==========================================================
# 📋 Copy to Clipboard
// ==========================================================

function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('Copied to clipboard!', 'success');
        }).catch(() => {
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    showToast('Copied to clipboard!', 'success');
}

// ==========================================================
# 📅 Format Date Helper
// ==========================================================

function formatDateTime(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// ==========================================================
# 🚀 Initialize on DOM Load
// ==========================================================

document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    initCharts();
    
    // Setup search input
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('keyup', function(e) {
            handleSearch(e.target);
        });
    }
    
    // Setup modal close on Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeModal();
        }
    });
    
    // Auto-hide flash messages
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(msg => {
        setTimeout(() => {
            msg.style.opacity = '0';
            msg.style.transform = 'translateY(-10px)';
            setTimeout(() => msg.remove(), 500);
        }, 5000);
    });
});

// ==========================================================
# 📊 Export Functions
// ==========================================================

function exportRules(format = 'csv') {
    window.location.href = '/export.' + format;
}

function importRules(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const formData = new FormData();
    formData.append('file', file);
    
    // Determine format from file extension
    const ext = file.name.split('.').pop().toLowerCase();
    const url = ext === 'csv' ? '/import' : '/import_json';
    
    fetch(url, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        showToast(data.message || 'Import successful!', 'success');
        setTimeout(() => location.reload(), 1500);
    })
    .catch(error => {
        showToast('Import failed: ' + error.message, 'error');
    });
}