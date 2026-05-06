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
        'older': `Images Older Than ${ageValue} ${ageUnit}`,
        'never-scanned': 'Never Scanned'
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
        if (!registry) {
            runBtn.disabled = true;
        } else {
            runBtn.disabled = false;
        }
    }
}

// Update mode UI when selection changes
function updateMassiveScanModeUI() {
    const modeSelect = document.getElementById('massiveScanMode');
    const ageGroup = document.getElementById('massiveScanAgeGroup');
    if (!modeSelect || !ageGroup) return;
    
    if (modeSelect.value === 'older') {
        ageGroup.style.display = 'block';
    } else {
        ageGroup.style.display = 'none';
    }
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
            
            if (selectedValue && document.getElementById('massiveScanRepoPattern')) {
                const s = document.getElementById('massiveScanRepoPattern');
                if (s) s.value = selectedValue;
            }
            
            // Add wildcard patterns
            const prefixes = new Set();
            data.repositories.forEach(repo => {
                const parts = repo.split('/');
                if (parts.length > 1) {
                    prefixes.add(parts[0] + '/*');
                }
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
            console.error('Failed to load repositories:', err);
            const select = document.getElementById('massiveScanRepoPattern');
            if (select) {
                select.innerHTML = '<option value="*">* (Errore caricamento)</option>';
                select.disabled = true;
            }
        });
}

// Reset results display
function resetMassiveScanResults() {
    const totalEl = document.getElementById('massiveScanTotal');
    const scannedEl = document.getElementById('massiveScanScanned');
    const skippedEl = document.getElementById('massiveScanSkipped');
    const errorsEl = document.getElementById('massiveScanErrors');
    const resultsEl = document.getElementById('massiveScanResults');
    const progressBar = document.getElementById('massiveScanProgressBar');
    const progressBarInner = document.getElementById('massiveScanProgressBarInner');
    
    if (totalEl) totalEl.textContent = '0';
    if (scannedEl) scannedEl.textContent = '0';
    if (skippedEl) skippedEl.textContent = '0';
    if (errorsEl) errorsEl.textContent = '0';
    if (resultsEl) resultsEl.innerHTML = '<p class="text-muted">Run scan to see results...</p>';
    if (progressBar) progressBar.style.display = 'none';
    if (progressBarInner) progressBarInner.style.width = '0%';
    
    massiveScanResults = [];
}

// Render scan results
function renderMassiveScanResults() {
    const container = document.getElementById('massiveScanResults');
    const totalEl = document.getElementById('massiveScanTotal');
    const scannedEl = document.getElementById('massiveScanScanned');
    const skippedEl = document.getElementById('massiveScanSkipped');
    const errorsEl = document.getElementById('massiveScanErrors');
    
    if (!container || !totalEl || !scannedEl || !skippedEl || !errorsEl) return;
    
    let scanned = 0, skipped = 0, errors = 0;
    massiveScanResults.forEach(r => {
        if (r.status === 'success' || r.status === 'dry-run') scanned++;
        else if (r.status === 'skipped') skipped++;
        else if (r.status === 'error') errors++;
    });
    
    totalEl.textContent = massiveScanResults.length;
    scannedEl.textContent = scanned;
    skippedEl.textContent = skipped;
    errorsEl.textContent = errors;
    
    if (massiveScanResults.length === 0) {
        container.innerHTML = '<p class="text-muted">No results yet...</p>';
        return;
    }
    
    let html = '<div class="table-responsive"><table class="table table-sm table-hover"><thead><tr><th>Image</th><th>Status</th><th>Vulnerabilities</th><th>Last Scan</th><th>Age</th></tr></thead><tbody>';
    
    const recentResults = massiveScanResults.slice(-50);
    recentResults.forEach(r => {
        const imageName = `${r.repo}:${r.tag}`;
        let statusHtml = '';
        let vulnHtml = '-';
        let lastScanHtml = '-';
        let ageHtml = '-';
        
        if (r.status === 'success' && r.result) {
            statusHtml = '<span class="badge bg-success"><i class="bi bi-check-circle"></i> Scanned</span>';
            const total = r.result.total || 0;
            const badgeClass = total === 0 ? 'bg-success' : total < 5 ? 'bg-warning' : total < 20 ? 'bg-danger' : 'bg-dark';
            vulnHtml = `<span class="badge ${badgeClass}">${total}</span>`;
            if (r.result.summary) {
                vulnHtml += `<br><small>C:${r.result.summary.CRITICAL||0} H:${r.result.summary.HIGH||0} M:${r.result.summary.MEDIUM||0} L:${r.result.summary.LOW||0}</small>`;
            }
            lastScanHtml = r.result.scannedAt ? formatTimeAgo(r.result.scannedAt) : 'Just now';
        } else if (r.status === 'dry-run') {
            statusHtml = '<span class="badge bg-warning"><i class="bi bi-eye"></i> Preview</span>';
            vulnHtml = '<span class="text-muted">N/A</span>';
        } else if (r.status === 'skipped') {
            statusHtml = '<span class="badge bg-secondary"><i class="bi bi-skip-end"></i> Skipped</span>';
        } else if (r.status === 'error') {
            statusHtml = '<span class="badge bg-danger"><i class="bi bi-x-circle"></i> Error</span>';
        }
        
        if (r.details && r.details.created) {
            ageHtml = formatTimeAgo(r.details.created);
        }
        
        html += '<tr><td><small>' + imageName + '</small></td><td>' + statusHtml + '</td><td>' + vulnHtml + '</td><td><small>' + lastScanHtml + '</small></td><td><small>' + ageHtml + '</small></td></tr>';
    });
    
    html += '</tbody></table></div>';
    if (massiveScanResults.length > 50) {
        html += '<p class="text-muted text-center">Showing last 50 of ' + massiveScanResults.length + ' results</p>';
    }
    container.innerHTML = html;
}

// Format time ago
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
    const registry = currentMassiveScanRegistry || (document.getElementById('massiveScanRegistry') ? document.getElementById('massiveScanRegistry').value : null);
    if (!registry) {
        alert('Please select a registry first');
        return;
    }
    
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
        showAlert('Scan timed out after 10 minutes. Please try again or scan fewer images.', 'warning');
    }, 600000);
    
    fetch(`/api/scan-massive/${encodeURIComponent(registry)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(r => r.json())
    .then(result => {
        clearTimeout(timeoutId);
        if (result.results) {
            massiveScanResults = massiveScanResults.concat(result.results);
        }
        renderMassiveScanResults();
        
        if (!dryRun) {
            document.getElementById('massiveScanProgressBarInner').style.width = '100%';
            setTimeout(() => {
                document.getElementById('massiveScanProgressBar').style.display = 'none';
                document.getElementById('massiveScanProgressBarInner').style.width = '0%';
            }, 500);
        }
        
        if (result.success) {
            showAlert('Scan completed: ' + result.scanned + ' scanned, ' + result.skipped + ' skipped, ' + result.errors + ' errors', 'success');
        } else {
            showAlert('Scan failed: ' + result.error, 'danger');
            document.getElementById('massiveScanProgressBar').style.display = 'none';
        }
    })
    .catch(err => {
        clearTimeout(timeoutId);
        showAlert('Scan failed: ' + err.message, 'danger');
        document.getElementById('massiveScanProgressBar').style.display = 'none';
    })
    .finally(() => {
        btn.disabled = false;
        btn.dataset.scanning = 'false';
        btn.innerHTML = originalHtml;
        document.getElementById('massiveScanProgressBarInner').style.width = '0%';
    });
}

// Reset form
function resetMassiveScanForm() {
    const modeSelect = document.getElementById('massiveScanMode');
    const ageGroup = document.getElementById('massiveScanAgeGroup');
    const ageValue = document.getElementById('massiveScanAgeValue');
    const includeAllTags = document.getElementById('massiveScanIncludeAllTags');
    const dryRun = document.getElementById('massiveScanDryRun');
    const repoPattern = document.getElementById('massiveScanRepoPattern');
    
    if (modeSelect) modeSelect.value = 'all';
    if (ageGroup) ageGroup.style.display = 'none';
    if (ageValue) ageValue.value = '30';
    if (includeAllTags) includeAllTags.checked = true;
    if (dryRun) dryRun.checked = true;
    if (repoPattern) repoPattern.innerHTML = '<option value="*">* (All repositories)</option>';
    
    updateMassiveScanSummary();
    resetMassiveScanResults();
}

// Initialize massive scan module
function initMassiveScan() {
    currentMassiveScanRegistry = null;
    
    const modeSelect = document.getElementById('massiveScanMode');
    const ageValue = document.getElementById('massiveScanAgeValue');
    const ageUnit = document.getElementById('massiveScanAgeUnit');
    const includeAllTags = document.getElementById('massiveScanIncludeAllTags');
    const dryRun = document.getElementById('massiveScanDryRun');
    const repoPattern = document.getElementById('massiveScanRepoPattern');
    const runBtn = document.getElementById('runMassiveScan');
    const registrySelector = document.getElementById('registrySelector');
    
    if (modeSelect) {
        modeSelect.addEventListener('change', updateMassiveScanModeUI);
    }
    if (ageValue) ageValue.addEventListener('input', updateMassiveScanSummary);
    if (ageUnit) ageUnit.addEventListener('change', updateMassiveScanSummary);
    if (includeAllTags) includeAllTags.addEventListener('change', updateMassiveScanSummary);
    if (dryRun) dryRun.addEventListener('change', updateMassiveScanSummary);
    if (repoPattern) repoPattern.addEventListener('change', updateMassiveScanSummary);
    
    if (runBtn) {
        runBtn.addEventListener('click', function() {
            const dryRun = document.getElementById('massiveScanDryRun').checked;
            if (dryRun) {
                runMassiveScan();
            } else {
                if (confirm('This will perform actual vulnerability scans on selected images. This may take a long time and consume significant resources. Continue?')) {
                    runMassiveScan();
                }
            }
        });
    }
    
    if (registrySelector) {
        registrySelector.addEventListener('change', function() {
            currentMassiveScanRegistry = this.value;
            populateMassiveScanRepoDropdown(this.value);
        });
    }
    
    if (registrySelector && registrySelector.value) {
        currentMassiveScanRegistry = registrySelector.value;
        populateMassiveScanRepoDropdown(registrySelector.value);
    }
    
    updateMassiveScanModeUI();
    updateMassiveScanSummary();
    resetMassiveScanResults();
}