// Massive scan module
let currentMassiveScanRegistry = null;
let massiveScanResults = [];

// Update scan summary display
function updateMassiveScanSummary() {
    const registry = currentMassiveScanRegistry || (document.getElementById('massiveScanRegistry') ? document.getElementById('massiveScanRegistry').value : null);
    const repoPattern = document.getElementById('massiveScanRepoPattern') ? document.getElementById('massiveScanRepoPattern').value : '*';
    const modeSelect = document.getElementById('massiveScanMode');
    const mode = modeSelect ? modeSelect.value : 'all';
    const ageValue = document.getElementById('massiveScanAgeValue') ? document.getElementById('massiveScanAgeValue').value : 30;
    const ageUnit = document.getElementById('massiveScanAgeUnit') ? document.getElementById('massiveScanAgeUnit').value : 'days';
    const includeAllTags = document.getElementById('massiveScanIncludeAllTags') ? document.getElementById('massiveScanIncludeAllTags').checked : true;
    const dryRun = document.getElementById('massiveScanDryRun') ? document.getElementById('massiveScanDryRun').checked : true;
    
    const modeLabels = {
        'all': 'All Images',
        'unscanned': 'Only Unscanned Images',
        'older': `Images Older Than ${ageValue} ${ageUnit}`
    };
    
    let summaryEl = document.getElementById('massiveScanSummary');
    if (!summaryEl) return;
    
    let html = '<div class="alert alert-info mb-0"><h6 class="alert-heading"><i class="bi bi-list-check"></i> Scan Configuration:</h6><ul class="mb-0">';
    html += `<li><strong>Registry:</strong> ${registry || 'Not selected'}</li>`;
    html += `<li><strong>Repository Pattern:</strong> <code>${repoPattern}</code></li>`;
    html += `<li><strong>Scan Mode:</strong> ${modeLabels[mode] || mode}</li>`;
    html += `<li><strong>Include All Tags:</strong> ${includeAllTags ? 'Yes (all tags per repo)' : 'No (latest only)'}</li>`;
    html += `<li><strong>Scanner:</strong> Trivy</li>`;
    html += `<li><strong>Mode:</strong> <span class="badge ${dryRun ? 'bg-warning' : 'bg-success'}">${dryRun ? 'Preview Only' : 'Live Scan'}</span></li>`;
    html += '</ul></div>';
    
    if (!dryRun) {
        html += '<div class="alert alert-warning mt-2 mb-0"><i class="bi bi-exclamation-triangle"></i> This will perform actual vulnerability scans which may take a long time!</div>';
    }
    
    summaryEl.innerHTML = html;
    
    // Update button state
    const runBtn = document.getElementById('runMassiveScan');
    if (runBtn) {
        if (!currentMassiveScanRegistry) {
            runBtn.disabled = true;
        } else {
            runBtn.disabled = false;
        }
    }
}

function updateMassiveScanModeUI() {
    const modeSelect = document.getElementById('massiveScanMode');
    const ageGroup = document.getElementById('massiveScanAgeGroup');
    if (!modeSelect || !ageGroup) return;
    ageGroup.style.display = modeSelect.value === 'older' ? 'block' : 'none';
    updateMassiveScanSummary();
}

// Populate repo pattern dropdown
function populateMassiveScanRepoDropdown(registryName) {
    if (!registryName) {
        const select = document.getElementById('massiveScanRepoPattern');
        if (select) {
            select.innerHTML = '<option value="*">* (Nessun registry selezionato)</option>';
            select.disabled = true;
        }
        document.getElementById('massiveScanSummary').innerHTML = '<p class="text-muted">Seleziona un registry per iniziare</p>';
        return;
    }
    fetch(`/api/repositories/${encodeURIComponent(registryName)}`)
        .then(r => {
            if (!r.ok) throw new Error('Network response was not ok');
            return r.json();
        })
        .then(data => {
            const select = document.getElementById('massiveScanRepoPattern');
            if (!select) return;
            const selectedValue = select.value;
            select.innerHTML = '<option value="*">* (All repositories)</option>';
            select.disabled = false;
            data.repositories.forEach(repo => {
                const option = document.createElement('option');
                option.value = repo;
                option.textContent = repo;
                select.appendChild(option);
            });
            const prefixes = new Set();
            data.repositories.forEach(repo => {
                const parts = repo.split('/');
                if (parts.length > 1) prefixes.add(parts[0] + '/*');
            });
            if (prefixes.size > 0) {
                const optgroup = document.createElement('optgroup');
                optgroup.label = 'Wildcard Patterns';
                prefixes.forEach(pattern => {
                    const option = document.createElement('option');
                    option.value = pattern;
                    option.textContent = pattern;
                    optgroup.appendChild(option);
                });
                select.appendChild(optgroup);
            }
            updateMassiveScanSummary();
        })
        .catch(err => {
            const select = document.getElementById('massiveScanRepoPattern');
            if (select) {
                select.innerHTML = '<option value="*">* (Errore)</option>';
                select.disabled = true;
            }
        });
}

function formatTimeAgo(dateString) {
    if (!dateString) return 'Unknown';
    const date = new Date(dateString.replace('Z', ''));
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return Math.floor(seconds / 60) + ' minutes ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + ' hours ago';
    if (seconds < 2592000) return Math.floor(seconds / 86400) + ' days ago';
    return Math.floor(seconds / 31536000) + ' years ago';
}

// Run massive scan
function runMassiveScan() {
    const registry = currentMassiveScanRegistry;
    if (!registry) { alert('Please select a registry first'); return; }
    
    const dryRun = document.getElementById('massiveScanDryRun').checked;
    const mode = document.getElementById('massiveScanMode').value;
    const includeAllTags = document.getElementById('massiveScanIncludeAllTags').checked;
    
    const data = {
        repoPattern: document.getElementById('massiveScanRepoPattern').value || '*',
        mode: mode,
        ageValue: document.getElementById('massiveScanAgeValue').value,
        ageUnit: document.getElementById('massiveScanAgeUnit').value,
        includeAllTags: includeAllTags,
        dryRun: dryRun
    };
    
    const btn = document.getElementById('runMassiveScan');
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.dataset.scanning = 'true';
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Scanning...';
    if (!dryRun) {
        document.getElementById('massiveScanProgressBar').style.display = 'block';
    }
    
    const timeoutId = setTimeout(() => {
        btn.disabled = false;
        btn.dataset.scanning = 'false';
        btn.innerHTML = originalHtml;
        document.getElementById('massiveScanProgressBar').style.display = 'none';
        if (typeof showAlert === 'function') showAlert('Scan timed out after 10 minutes.', 'warning');
    }, 600000);
    
    fetch(`/api/scan-massive/${encodeURIComponent(registry)}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(r => r.json())
    .then(result => {
        clearTimeout(timeoutId);
        if (result.results) massiveScanResults = massiveScanResults.concat(result.results);
        renderMassiveScanResults();
        if (!dryRun) {
            document.getElementById('massiveScanProgressBarInner').style.width = '100%';
            setTimeout(() => {
                document.getElementById('massiveScanProgressBar').style.display = 'none';
                document.getElementById('massiveScanProgressBarInner').style.width = '0%';
            }, 500);
        }
        const msgType = result.success ? 'success' : 'danger';
        const msg = result.success ? 'Scan completed: ' + result.scanned + ' scanned, ' + result.skipped + ' skipped, ' + result.errors + ' errors' : 'Scan failed: ' + result.error;
        if (typeof showAlert === 'function') showAlert(msg, msgType);
        if (!dryRun) document.getElementById('massiveScanProgressBar').style.display = 'none';
    })
    .catch(err => {
        clearTimeout(timeoutId);
        if (typeof showAlert === 'function') showAlert('Scan failed: ' + err.message, 'danger');
        document.getElementById('massiveScanProgressBar').style.display = 'none';
    })
    .finally(() => {
        btn.disabled = false;
        btn.dataset.scanning = 'false';
        btn.innerHTML = originalHtml;
        document.getElementById('massiveScanProgressBarInner').style.width = '0%';
    });
}

function renderMassiveScanResults() {
    const container = document.getElementById('massiveScanResults');
    if (!container) return;
    const totalEl = document.getElementById('massiveScanTotal');
    const scannedEl = document.getElementById('massiveScanScanned');
    const skippedEl = document.getElementById('massiveScanSkipped');
    const errorsEl = document.getElementById('massiveScanErrors');
    if (totalEl) totalEl.textContent = massiveScanResults.length;
    
    let scanned = 0, skipped = 0, errors = 0;
    massiveScanResults.forEach(r => {
        if (r.status === 'success' || r.status === 'dry-run') scanned++;
        else if (r.status === 'skipped') skipped++;
        else if (r.status === 'error') errors++;
    });
    if (scannedEl) scannedEl.textContent = scanned;
    if (skippedEl) skippedEl.textContent = skipped;
    if (errorsEl) errorsEl.textContent = errors;
    
    if (massiveScanResults.length === 0) { container.innerHTML = '<p class="text-muted">Run scan to see results...</p>'; return; }
    
    let html = '<div class="table-responsive"><table class="table table-sm table-hover"><thead><tr><th>Image</th><th>Status</th><th>Vulnerabilities</th></tr></thead><tbody>';
    const recent = massiveScanResults.slice(-50);
    recent.forEach(r => {
        let statusHtml = '';
        let vulnHtml = '-';
        if (r.status === 'success' && r.result) {
            statusHtml = '<span class="badge bg-success"><i class="bi bi-check-circle"></i></span>';
            const total = r.result.total || 0;
            const cls = total === 0 ? 'bg-success' : total < 5 ? 'bg-warning' : total < 20 ? 'bg-danger' : 'bg-dark';
            vulnHtml = `<span class="badge ${cls}">${total}</span>`;
        } else if (r.status === 'dry-run') {
            statusHtml = '<span class="badge bg-warning">Preview</span>';
        } else if (r.status === 'skipped') {
            statusHtml = '<span class="badge bg-secondary">Skipped</span>';
        } else if (r.status === 'error') {
            statusHtml = '<span class="badge bg-danger">Error</span>';
        }
        html += `<tr><td><small>${r.repo}:${r.tag}</small></td><td>${statusHtml}</td><td>${vulnHtml}</td></tr>`;
    });
    html += '</tbody></table></div>';
    if (massiveScanResults.length > 50) {
        html += '<p class="text-muted text-center">Showing last 50 of ' + massiveScanResults.length + ' results</p>';
    }
    container.innerHTML = html;
}

function resetMassiveScanResults() {
    const ids = ['massiveScanTotal', 'massiveScanScanned', 'massiveScanSkipped', 'massiveScanErrors'];
    ids.forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '0'; });
    const el = document.getElementById('massiveScanResults');
    if (el) el.innerHTML = '<p class="text-muted">Run scan to see results...</p>';
    massiveScanResults = [];
}

function resetMassiveScanForm() {
    const mode = document.getElementById('massiveScanMode');
    const ageGroup = document.getElementById('massiveScanAgeGroup');
    const ageValue = document.getElementById('massiveScanAgeValue');
    const includeAllTags = document.getElementById('massiveScanIncludeAllTags');
    const dryRun = document.getElementById('massiveScanDryRun');
    if (mode) mode.value = 'all';
    if (ageGroup) ageGroup.style.display = 'none';
    if (ageValue) ageValue.value = '30';
    if (includeAllTags) includeAllTags.checked = true;
    if (dryRun) dryRun.checked = true;
    updateMassiveScanSummary();
    resetMassiveScanResults();
}

function initMassiveScan() {
    currentMassiveScanRegistry = null;
    const mode = document.getElementById('massiveScanMode');
    const ageValue = document.getElementById('massiveScanAgeValue');
    const ageUnit = document.getElementById('massiveScanAgeUnit');
    const includeAllTags = document.getElementById('massiveScanIncludeAllTags');
    const dryRun = document.getElementById('massiveScanDryRun');
    const runBtn = document.getElementById('runMassiveScan');
    const registrySelector = document.getElementById('registrySelector');
    
    if (mode) mode.addEventListener('change', updateMassiveScanModeUI);
    if (ageValue) ageValue.addEventListener('input', updateMassiveScanSummary);
    if (ageUnit) ageUnit.addEventListener('change', updateMassiveScanSummary);
    if (includeAllTags) includeAllTags.addEventListener('change', updateMassiveScanSummary);
    if (dryRun) dryRun.addEventListener('change', updateMassiveScanSummary);
    
    if (runBtn) {
        runBtn.addEventListener('click', function() {
            if (!document.getElementById('massiveScanDryRun').checked) {
                if (confirm('This will perform actual vulnerability scans. Continue?')) runMassiveScan();
            } else runMassiveScan();
        });
    }
    
    if (registrySelector) {
        registrySelector.addEventListener('change', function() {
            currentMassiveScanRegistry = this.value;
            populateMassiveScanRepoDropdown(this.value);
        });
        if (registrySelector.value) {
            currentMassiveScanRegistry = registrySelector.value;
            populateMassiveScanRepoDropdown(registrySelector.value);
        }
    }
    
    updateMassiveScanModeUI();
    updateMassiveScanSummary();
    resetMassiveScanResults();
}