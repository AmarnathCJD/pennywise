/**
 * PennyWise Web UI - Main Application
 * Professional vulnerability scanner frontend
 */

class PennyWiseApp {
    constructor() {
        this.currentScanId = null;
        this.scanInterval = null;
        this.startTime = null;
        this.lastLogCount = 0;  // Track last displayed log count
        this.config = {
            timeout: 10,
            maxDepth: 3,
            userAgent: 'PennyWise Security Scanner v1.0',
            concurrency: 10,
            aiModel: 'local',
            apiKey: '',
            aiSeverity: false,
            aiRemediation: false,
            payloadEvasion: false,
            payloadAggressive: false,
            timeBased: true,
            reportFormat: 'json',
            autoSave: true,
            includeEvidence: true
        };
        
        this.init();
    }
    
    init() {
        this.bindNavigation();
        this.bindScanControls();
        this.bindSettings();
        this.bindModal();
        this.loadConfig();
        this.loadReports();
        
        // Update concurrency slider display
        const concurrencySlider = document.getElementById('concurrency');
        const concurrencyValue = document.getElementById('concurrency-value');
        if (concurrencySlider && concurrencyValue) {
            concurrencySlider.addEventListener('input', () => {
                concurrencyValue.textContent = concurrencySlider.value;
            });
        }
    }
    
    // ==========================================
    // Navigation
    // ==========================================
    
    bindNavigation() {
        const navLinks = document.querySelectorAll('.nav-link');
        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const section = link.dataset.section;
                this.showSection(section);
                
                // Update active state
                navLinks.forEach(l => l.classList.remove('active'));
                link.classList.add('active');
            });
        });
    }
    
    showSection(sectionName) {
        const sections = document.querySelectorAll('.section');
        sections.forEach(section => {
            section.classList.remove('active');
        });
        
        const targetSection = document.getElementById(`${sectionName}-section`);
        if (targetSection) {
            targetSection.classList.add('active');
        }
    }
    
    // ==========================================
    // Scan Controls
    // ==========================================
    
    bindScanControls() {
        const startBtn = document.getElementById('start-scan');
        const stopBtn = document.getElementById('stop-scan');
        const validateBtn = document.getElementById('validate-url');
        const exportJsonBtn = document.getElementById('export-json');
        const exportHtmlBtn = document.getElementById('export-html');
        
        if (startBtn) {
            startBtn.addEventListener('click', () => this.startScan());
        }
        
        if (stopBtn) {
            stopBtn.addEventListener('click', () => this.stopScan());
        }
        
        if (validateBtn) {
            validateBtn.addEventListener('click', () => this.validateUrl());
        }
        
        if (exportJsonBtn) {
            exportJsonBtn.addEventListener('click', () => this.exportResults('json'));
        }
        
        if (exportHtmlBtn) {
            exportHtmlBtn.addEventListener('click', () => this.exportResults('html'));
        }
        
        // Clear log button
        const clearLogBtn = document.getElementById('clear-log');
        if (clearLogBtn) {
            clearLogBtn.addEventListener('click', () => this.clearLog());
        }
    }
    
    async validateUrl() {
        const urlInput = document.getElementById('target-url');
        const url = urlInput.value.trim();
        
        if (!url) {
            this.showToast('Please enter a URL', 'error');
            return;
        }
        
        try {
            new URL(url);
            this.showToast('URL is valid', 'success');
        } catch {
            this.showToast('Invalid URL format', 'error');
        }
    }
    
    async startScan() {
        const urlInput = document.getElementById('target-url');
        const url = urlInput.value.trim();
        
        if (!url) {
            this.showToast('Please enter a target URL', 'error');
            return;
        }
        
        // Gather attack types
        const attackCheckboxes = document.querySelectorAll('input[name="attack"]:checked');
        const attacks = Array.from(attackCheckboxes).map(cb => cb.value);
        
        if (attacks.length === 0) {
            this.showToast('Please select at least one attack type', 'error');
            return;
        }
        
        // Gather options
        const options = {
            crawl: document.getElementById('opt-crawl')?.checked ?? true,
            ai_analysis: document.getElementById('opt-ai')?.checked ?? false,
            parallel: document.getElementById('opt-parallel')?.checked ?? true,
            concurrency: parseInt(document.getElementById('concurrency')?.value ?? '10')
        };
        
        // Show progress card
        const progressCard = document.getElementById('progress-card');
        const resultsCard = document.getElementById('results-card');
        if (progressCard) progressCard.classList.remove('hidden');
        if (resultsCard) resultsCard.classList.add('hidden');
        
        // Update UI state
        const startBtn = document.getElementById('start-scan');
        const stopBtn = document.getElementById('stop-scan');
        if (startBtn) startBtn.disabled = true;
        if (stopBtn) stopBtn.disabled = false;
        
        this.clearLog();
        this.addLogEntry('Initializing scan...', 'info');
        this.startTime = Date.now();
        this.lastLogCount = 0;  // Reset log counter
        
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target_url: url,
                    attacks: attacks,
                    options: options
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error: ${response.status}`);
            }
            
            const data = await response.json();
            this.currentScanId = data.scan_id;
            
            this.addLogEntry(`Scan started with ID: ${this.currentScanId}`, 'success');
            this.addLogEntry(`Target: ${url}`, 'info');
            this.addLogEntry(`Attacks: ${attacks.join(', ')}`, 'info');
            
            // Start polling for status
            this.startStatusPolling();
            
        } catch (error) {
            this.addLogEntry(`Error starting scan: ${error.message}`, 'error');
            this.showToast('Failed to start scan', 'error');
            this.resetScanUI();
        }
    }
    
    startStatusPolling() {
        this.scanInterval = setInterval(() => this.pollStatus(), 1000);
    }
    
    async pollStatus() {
        if (!this.currentScanId) return;
        
        try {
            const response = await fetch(`/api/status/${this.currentScanId}`);
            if (!response.ok) return;
            
            const data = await response.json();
            
            // Update progress bar
            const progressBar = document.getElementById('progress-bar');
            if (progressBar) {
                progressBar.style.width = `${data.progress}%`;
            }
            
            // Update status text
            const statusEl = document.getElementById('scan-status');
            if (statusEl) {
                statusEl.textContent = this.capitalizeFirst(data.status);
            }
            
            // Update stats
            const elapsedTime = Math.round((Date.now() - this.startTime) / 1000);
            document.getElementById('stat-requests').textContent = data.requests || 0;
            document.getElementById('stat-vulns').textContent = data.vulnerabilities || 0;
            document.getElementById('stat-time').textContent = `${elapsedTime}s`;
            
            // Display new log entries only (avoid duplicates)
            if (data.logs && data.logs.length > this.lastLogCount) {
                const newLogs = data.logs.slice(this.lastLogCount);
                newLogs.forEach(log => {
                    this.addLogEntry(log.message, log.level);
                });
                this.lastLogCount = data.logs.length;
            }
            
            // Check if scan is complete
            if (data.status === 'completed' || data.status === 'error') {
                this.stopStatusPolling();
                await this.loadResults();
            }
            
        } catch (error) {
            console.error('Status polling error:', error);
        }
    }
    
    stopStatusPolling() {
        if (this.scanInterval) {
            clearInterval(this.scanInterval);
            this.scanInterval = null;
        }
    }
    
    async stopScan() {
        this.stopStatusPolling();
        this.addLogEntry('Scan stopped by user', 'warning');
        this.resetScanUI();
        
        // Try to stop on server if we have a scan ID
        if (this.currentScanId) {
            try {
                await fetch(`/api/scan/${this.currentScanId}/stop`, { method: 'POST' });
            } catch (error) {
                console.error('Error stopping scan:', error);
            }
        }
    }
    
    resetScanUI() {
        const startBtn = document.getElementById('start-scan');
        const stopBtn = document.getElementById('stop-scan');
        if (startBtn) startBtn.disabled = false;
        if (stopBtn) stopBtn.disabled = true;
    }
    
    async loadResults() {
        if (!this.currentScanId) return;
        
        try {
            const response = await fetch(`/api/results/${this.currentScanId}`);
            if (!response.ok) return;
            
            const data = await response.json();
            this.displayResults(data);
            
        } catch (error) {
            console.error('Error loading results:', error);
            this.showToast('Failed to load results', 'error');
        }
    }
    
    displayResults(data) {
        const resultsCard = document.getElementById('results-card');
        if (resultsCard) resultsCard.classList.remove('hidden');
        
        // Update summary counts
        const severityCounts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        };
        
        const vulnerabilities = data.vulnerabilities || [];
        vulnerabilities.forEach(vuln => {
            const severity = (vuln.severity || 'info').toLowerCase();
            if (severityCounts.hasOwnProperty(severity)) {
                severityCounts[severity]++;
            }
        });
        
        Object.keys(severityCounts).forEach(severity => {
            const el = document.getElementById(`count-${severity}`);
            if (el) el.textContent = severityCounts[severity];
        });
        
        // Populate table
        const tableBody = document.getElementById('results-table-body');
        if (!tableBody) return;
        
        tableBody.innerHTML = '';
        
        if (vulnerabilities.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align: center; color: var(--color-text-muted);">
                        No vulnerabilities found
                    </td>
                </tr>
            `;
            return;
        }
        
        vulnerabilities.forEach((vuln, index) => {
            const hasDbStructure = vuln.db_structure && vuln.db_structure.length > 0;
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>
                    <span class="severity-badge severity-${(vuln.severity || 'info').toLowerCase()}">
                        ${vuln.severity || 'Info'}
                    </span>
                </td>
                <td>
                    <span class="type-badge">${vuln.type || 'Unknown'}</span>
                    ${hasDbStructure ? '<span style="margin-left: 4px;" title="Database structure extracted">🗄️</span>' : ''}
                </td>
                <td class="location-text" title="${vuln.url || ''}">${this.truncateUrl(vuln.url || '')}</td>
                <td>${this.truncate(vuln.details || vuln.payload || '', 50)}</td>
                <td>
                    <button class="btn btn-icon btn-sm view-details" data-index="${index}" title="View Details">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="16" x2="12" y2="12"></line>
                            <line x1="12" y1="8" x2="12" y2="8"></line>
                        </svg>
                    </button>
                </td>
            `;
            tableBody.appendChild(row);
        });
        
        // Bind detail buttons
        const detailBtns = tableBody.querySelectorAll('.view-details');
        detailBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const index = parseInt(btn.dataset.index);
                this.showVulnerabilityDetails(vulnerabilities[index]);
            });
        });
        
        // Store results for export
        this.currentResults = data;
        
        this.addLogEntry('Scan completed', 'success');
        this.addLogEntry(`Found ${vulnerabilities.length} vulnerabilities`, 'info');
        
        // Fetch AI insights for all vulnerabilities and display summary
        this.addLogEntry('🤖 Analyzing vulnerabilities with AI...', 'info');
        this.fetchAllAIInsights(vulnerabilities);
        
        this.resetScanUI();
        this.showToast(`Scan complete - ${vulnerabilities.length} vulnerabilities found`, 'success');
    }
    
    async fetchAllAIInsights(vulnerabilities) {
        let criticalCount = 0;
        let highCount = 0;
        let remediationPriorities = { critical: 0, high: 0, medium: 0 };
        
        for (const vuln of vulnerabilities.slice(0, 10)) { // Limit to first 10 to avoid spam
            try {
                const [classification, remediation] = await Promise.all([
                    this.fetchClassification(vuln),
                    this.fetchRemediation(vuln)
                ]);
                
                if (classification?.classification) {
                    const severity = classification.classification.severity?.toLowerCase();
                    if (severity === 'critical') criticalCount++;
                    else if (severity === 'high') highCount++;
                    
                    // Log classification
                    this.addLogEntry(
                        `🎯 ${vuln.type}: CVSS ${classification.classification.cvss_score} - ${classification.classification.exploitability} to exploit`,
                        'info'
                    );
                }
                
                if (remediation?.remediation) {
                    const priority = remediation.remediation.priority?.toLowerCase();
                    if (priority === 'critical') remediationPriorities.critical++;
                    else if (priority === 'high') remediationPriorities.high++;
                    else if (priority === 'medium') remediationPriorities.medium++;
                    
                    // Log top remediation step
                    if (remediation.remediation.steps && remediation.remediation.steps[0]) {
                        this.addLogEntry(
                            `🛡️ Fix ${vuln.type}: ${remediation.remediation.steps[0]}`,
                            'success'
                        );
                    }
                }
                
                // Small delay to avoid overwhelming the UI
                await new Promise(resolve => setTimeout(resolve, 100));
                
            } catch (error) {
                console.error('Error fetching AI insights for vuln:', error);
            }
        }
        
        // Summary log
        this.addLogEntry(
            `📊 AI Analysis: ${criticalCount} Critical, ${highCount} High severity threats detected`,
            'warning'
        );
        this.addLogEntry(
            `🎯 Remediation: ${remediationPriorities.critical} Critical, ${remediationPriorities.high} High, ${remediationPriorities.medium} Medium priority fixes needed`,
            'info'
        );
    }
    
    // ==========================================
    // Modal
    // ==========================================
    
    bindModal() {
        const modal = document.getElementById('vuln-modal');
        const closeBtn = document.getElementById('close-modal');
        const backdrop = modal?.querySelector('.modal-backdrop');
        
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.closeModal());
        }
        
        if (backdrop) {
            backdrop.addEventListener('click', () => this.closeModal());
        }
        
        // Copy payload button
        const copyPayloadBtn = document.getElementById('copy-payload');
        if (copyPayloadBtn) {
            copyPayloadBtn.addEventListener('click', () => this.copyPayload());
        }
    }
    
    async showVulnerabilityDetails(vuln) {
        const modal = document.getElementById('vuln-modal');
        const modalBody = document.getElementById('modal-body');
        
        if (!modal || !modalBody) return;
        
        this.currentVuln = vuln;
        
        // Initial render with loading placeholders for AI insights
        modalBody.innerHTML = this.generateVulnDetailsHTML(vuln, null, null);
        modal.classList.add('active');
        
        // Fetch AI insights in background
        this.fetchAIInsights(vuln, modalBody);
    }
    
    generateVulnDetailsHTML(vuln, classification, remediation) {
        return `
            <div class="vuln-detail-grid">
                <div class="detail-section">
                    <h4>Severity</h4>
                    <span class="severity-badge severity-${(vuln.severity || 'info').toLowerCase()}">${vuln.severity || 'Info'}</span>
                </div>
                <div class="detail-section">
                    <h4>Type</h4>
                    <span class="type-badge">${vuln.type || 'Unknown'}</span>
                </div>
                
                ${classification ? `
                <div class="detail-section">
                    <h4>CVSS Score</h4>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.25rem; font-weight: 700; color: var(--accent);">${classification.cvss_score}</span>
                        <span style="font-size: 0.75rem; color: var(--text-secondary);">${classification.risk_level}</span>
                    </div>
                </div>
                <div class="detail-section">
                    <h4>Exploitability</h4>
                    <span class="type-badge" style="background: rgba(255, 140, 66, 0.15); color: var(--high);">${classification.exploitability}</span>
                </div>
                ` : ''}
                
                <div class="detail-section full-width">
                    <h4>URL</h4>
                    <code style="font-size: 12px; word-break: break-all;">${vuln.url || 'N/A'}</code>
                </div>
                <div class="detail-section full-width">
                    <h4>Payload</h4>
                    <pre style="background: var(--color-bg-primary); padding: var(--spacing-md); border-radius: var(--radius-md); overflow-x: auto; font-size: 12px;">${vuln.payload || 'N/A'}</pre>
                </div>
                ${vuln.parameter ? `
                <div class="detail-section">
                    <h4>Parameter</h4>
                    <code>${vuln.parameter}</code>
                </div>
                ` : ''}
                ${vuln.evidence ? `
                <div class="detail-section full-width">
                    <h4>Evidence</h4>
                    <pre style="background: var(--color-bg-primary); padding: var(--spacing-md); border-radius: var(--radius-md); overflow-x: auto; font-size: 12px; max-height: 150px;">${this.escapeHtml(vuln.evidence)}</pre>
                </div>
                ` : ''}
                ${vuln.db_structure ? `
                <div class="detail-section full-width">
                    <h4>🗄️ Database Structure (Extracted)</h4>
                    <pre style="background: var(--color-bg-primary); padding: var(--spacing-md); border-radius: var(--radius-md); overflow-x: auto; font-size: 12px; max-height: 200px; color: var(--color-success);">${this.escapeHtml(vuln.db_structure)}</pre>
                </div>
                ` : ''}
                
                ${classification ? `
                <div class="detail-section full-width ai-insight-card">
                    <div class="ai-header">
                        <h4>🤖 AI Classification Analysis</h4>
                        <span class="ai-badge">${classification.method || 'rule-based'}</span>
                    </div>
                    <div class="ai-insight-content">
                        <div class="insight-item">
                            <span class="insight-label">Business Impact:</span>
                            <span>${classification.business_impact}</span>
                        </div>
                        <div class="insight-item">
                            <span class="insight-label">Attack Vector:</span>
                            <span>${classification.attack_vector}</span>
                        </div>
                        <div class="insight-item">
                            <span class="insight-label">Remediation Effort:</span>
                            <span>${classification.remediation_effort}</span>
                        </div>
                    </div>
                </div>
                ` : `
                <div class="detail-section full-width" id="classification-loading">
                    <div class="loading-card">
                        <div class="spinner"></div>
                        <span>Loading AI classification...</span>
                    </div>
                </div>
                `}
                
                ${remediation ? `
                <div class="detail-section full-width ai-insight-card">
                    <div class="ai-header">
                        <h4>🛡️ AI Remediation Guide</h4>
                        <span class="ai-badge">${remediation.method || 'rule-based'}</span>
                    </div>
                    <div class="remediation-content">
                        <div class="priority-badge priority-${remediation.priority?.toLowerCase() || 'medium'}">
                            Priority: ${remediation.priority || 'Medium'}
                        </div>
                        ${remediation.steps && remediation.steps.length > 0 ? `
                        <ol class="remedy-steps">
                            ${remediation.steps.map(step => `<li>${step}</li>`).join('')}
                        </ol>
                        ` : ''}
                        ${remediation.code_example ? `
                        <div class="code-example">
                            <h5>Code Example:</h5>
                            <pre>${this.escapeHtml(remediation.code_example)}</pre>
                        </div>
                        ` : ''}
                    </div>
                </div>
                ` : `
                <div class="detail-section full-width" id="remediation-loading">
                    <div class="loading-card">
                        <div class="spinner"></div>
                        <span>Loading AI remediation guide...</span>
                    </div>
                </div>
                `}
            </div>
            <style>
                .vuln-detail-grid {
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: var(--spacing-md);
                }
                .detail-section {
                    display: flex;
                    flex-direction: column;
                    gap: var(--spacing-xs);
                }
                .detail-section.full-width {
                    grid-column: 1 / -1;
                }
                .detail-section h4 {
                    font-size: var(--font-size-xs);
                    color: var(--color-text-muted);
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                    margin: 0;
                }
                .ai-insight-card {
                    background: rgba(0, 212, 255, 0.03);
                    border: 1px solid rgba(0, 212, 255, 0.1);
                    border-radius: 12px;
                    padding: 1rem;
                }
                .ai-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    margin-bottom: 0.75rem;
                }
                .ai-badge {
                    font-size: 0.65rem;
                    padding: 0.25rem 0.5rem;
                    background: rgba(124, 58, 237, 0.2);
                    color: var(--accent-secondary);
                    border-radius: 6px;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                }
                .ai-insight-content {
                    display: flex;
                    flex-direction: column;
                    gap: 0.5rem;
                }
                .insight-item {
                    display: flex;
                    gap: 0.5rem;
                    font-size: 0.875rem;
                }
                .insight-label {
                    color: var(--text-muted);
                    font-weight: 600;
                    min-width: 140px;
                }
                .remediation-content {
                    display: flex;
                    flex-direction: column;
                    gap: 0.75rem;
                }
                .priority-badge {
                    display: inline-block;
                    padding: 0.35rem 0.75rem;
                    border-radius: 8px;
                    font-size: 0.75rem;
                    font-weight: 600;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                    width: fit-content;
                }
                .priority-badge.priority-critical {
                    background: rgba(255, 59, 92, 0.2);
                    color: var(--critical);
                }
                .priority-badge.priority-high {
                    background: rgba(255, 140, 66, 0.2);
                    color: var(--high);
                }
                .priority-badge.priority-medium {
                    background: rgba(255, 217, 61, 0.2);
                    color: var(--medium);
                }
                .remedy-steps {
                    margin: 0;
                    padding-left: 1.5rem;
                    color: var(--text-secondary);
                }
                .remedy-steps li {
                    margin-bottom: 0.5rem;
                    font-size: 0.875rem;
                    line-height: 1.6;
                }
                .code-example {
                    margin-top: 0.5rem;
                }
                .code-example h5 {
                    font-size: 0.75rem;
                    color: var(--text-muted);
                    margin-bottom: 0.5rem;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                }
                .code-example pre {
                    background: var(--color-bg-primary);
                    padding: 0.75rem;
                    border-radius: 8px;
                    font-size: 0.75rem;
                    overflow-x: auto;
                    border: 1px solid var(--border);
                }
                .loading-card {
                    display: flex;
                    align-items: center;
                    gap: 0.75rem;
                    padding: 1rem;
                    background: rgba(0, 0, 0, 0.2);
                    border-radius: 8px;
                    color: var(--text-muted);
                    font-size: 0.875rem;
                }
                .spinner {
                    width: 16px;
                    height: 16px;
                    border: 2px solid rgba(0, 212, 255, 0.2);
                    border-top-color: var(--accent);
                    border-radius: 50%;
                    animation: spin 0.8s linear infinite;
                }
                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
            </style>
        `;
    }
    
    async fetchAIInsights(vuln, modalBody) {
        console.log('🤖 Fetching AI insights for:', vuln);
        try {
            // Fetch classification and remediation in parallel
            console.log('📡 Calling /api/classify and /api/remedy...');
            const [classificationData, remediationData] = await Promise.all([
                this.fetchClassification(vuln),
                this.fetchRemediation(vuln)
            ]);
            
            console.log('✅ Classification result:', classificationData);
            console.log('✅ Remediation result:', remediationData);
            
            // Re-render with complete data
            modalBody.innerHTML = this.generateVulnDetailsHTML(
                vuln,
                classificationData?.classification,
                remediationData?.remediation
            );
            
            console.log('✅ AI insights rendered successfully');
        } catch (error) {
            console.error('❌ Error fetching AI insights:', error);
            // Remove loading indicators on error
            const loadingEls = modalBody.querySelectorAll('#classification-loading, #remediation-loading');
            loadingEls.forEach(el => el.remove());
        }
    }
    
    async fetchClassification(vuln) {
        try {
            const payload = {
                vuln_type: vuln.type,
                endpoint: vuln.url,
                parameter: vuln.parameter || '',
                payload: vuln.payload || '',
                impact: vuln.details || ''
            };
            console.log('📤 Sending to /api/classify:', payload);
            
            const response = await fetch('/api/classify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            
            console.log('📥 Classification response status:', response.status);
            
            if (response.ok) {
                const data = await response.json();
                console.log('📥 Classification data:', data);
                return data;
            } else {
                const errorText = await response.text();
                console.error('❌ Classification error response:', errorText);
            }
        } catch (error) {
            console.error('❌ Classification fetch error:', error);
        }
        return null;
    }
    
    async fetchRemediation(vuln) {
        try {
            const payload = {
                vuln_type: vuln.type,
                endpoint: vuln.url,
                parameter: vuln.parameter || '',
                payload: vuln.payload || '',
                impact: vuln.details || ''
            };
            console.log('📤 Sending to /api/remedy:', payload);
            
            const response = await fetch('/api/remedy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            
            console.log('📥 Remediation response status:', response.status);
            
            if (response.ok) {
                const data = await response.json();
                console.log('📥 Remediation data:', data);
                return data;
            } else {
                const errorText = await response.text();
                console.error('❌ Remediation error response:', errorText);
            }
        } catch (error) {
            console.error('❌ Remediation fetch error:', error);
        }
        return null;
    }
    
    closeModal() {
        const modal = document.getElementById('vuln-modal');
        if (modal) {
            modal.classList.remove('active');
        }
    }
    
    copyPayload() {
        if (this.currentVuln && this.currentVuln.payload) {
            navigator.clipboard.writeText(this.currentVuln.payload);
            this.showToast('Payload copied to clipboard', 'success');
        }
    }
    
    // ==========================================
    // Settings
    // ==========================================
    
    bindSettings() {
        const saveBtn = document.getElementById('save-settings');
        const resetBtn = document.getElementById('reset-settings');
        
        if (saveBtn) {
            saveBtn.addEventListener('click', () => this.saveSettings());
        }
        
        if (resetBtn) {
            resetBtn.addEventListener('click', () => this.resetSettings());
        }
    }
    
    async loadConfig() {
        try {
            const response = await fetch('/api/config');
            if (response.ok) {
                const data = await response.json();
                this.config = { ...this.config, ...data };
                this.applyConfigToUI();
            }
        } catch (error) {
            console.log('Using default config');
        }
    }
    
    applyConfigToUI() {
        // Apply settings to UI elements
        const mappings = {
            'timeout': this.config.timeout,
            'max-depth': this.config.maxDepth,
            'user-agent': this.config.userAgent,
            'ai-model': this.config.aiModel,
            'api-key': this.config.apiKey,
            'report-format': this.config.reportFormat
        };
        
        Object.entries(mappings).forEach(([id, value]) => {
            const el = document.getElementById(id);
            if (el) el.value = value;
        });
        
        // Checkboxes
        const checkMappings = {
            'ai-severity': this.config.aiSeverity,
            'ai-remediation': this.config.aiRemediation,
            'payload-evasion': this.config.payloadEvasion,
            'payload-aggressive': this.config.payloadAggressive,
            'time-based': this.config.timeBased,
            'auto-save': this.config.autoSave,
            'include-evidence': this.config.includeEvidence
        };
        
        Object.entries(checkMappings).forEach(([id, value]) => {
            const el = document.getElementById(id);
            if (el) el.checked = value;
        });
    }
    
    async saveSettings() {
        // Gather settings from UI
        this.config.timeout = parseInt(document.getElementById('timeout')?.value || '10');
        this.config.maxDepth = parseInt(document.getElementById('max-depth')?.value || '3');
        this.config.userAgent = document.getElementById('user-agent')?.value || '';
        this.config.aiModel = document.getElementById('ai-model')?.value || 'local';
        this.config.apiKey = document.getElementById('api-key')?.value || '';
        this.config.reportFormat = document.getElementById('report-format')?.value || 'json';
        
        this.config.aiSeverity = document.getElementById('ai-severity')?.checked || false;
        this.config.aiRemediation = document.getElementById('ai-remediation')?.checked || false;
        this.config.payloadEvasion = document.getElementById('payload-evasion')?.checked || false;
        this.config.payloadAggressive = document.getElementById('payload-aggressive')?.checked || false;
        this.config.timeBased = document.getElementById('time-based')?.checked || true;
        this.config.autoSave = document.getElementById('auto-save')?.checked || true;
        this.config.includeEvidence = document.getElementById('include-evidence')?.checked || true;
        
        try {
            const response = await fetch('/api/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(this.config)
            });
            
            if (response.ok) {
                this.showToast('Settings saved successfully', 'success');
            } else {
                throw new Error('Failed to save');
            }
        } catch (error) {
            this.showToast('Failed to save settings', 'error');
        }
    }
    
    resetSettings() {
        this.config = {
            timeout: 10,
            maxDepth: 3,
            userAgent: 'PennyWise Security Scanner v1.0',
            concurrency: 10,
            aiModel: 'local',
            apiKey: '',
            aiSeverity: false,
            aiRemediation: false,
            payloadEvasion: false,
            payloadAggressive: false,
            timeBased: true,
            reportFormat: 'json',
            autoSave: true,
            includeEvidence: true
        };
        this.applyConfigToUI();
        this.showToast('Settings reset to defaults', 'success');
    }
    
    // ==========================================
    // Reports
    // ==========================================
    
    async loadReports() {
        try {
            const response = await fetch('/api/reports');
            if (!response.ok) return;
            
            const data = await response.json();
            this.displayReportsList(data.reports || []);
            
        } catch (error) {
            console.log('No reports available');
        }
    }
    
    displayReportsList(reports) {
        const reportsList = document.getElementById('reports-list');
        if (!reportsList) return;
        
        if (reports.length === 0) {
            return; // Keep empty state
        }
        
        reportsList.innerHTML = '';
        
        reports.forEach(report => {
            const item = document.createElement('div');
            item.className = 'report-item';
            item.innerHTML = `
                <div class="report-info">
                    <span class="report-title">${report.name || report.filename}</span>
                    <span class="report-meta">${report.date || 'Unknown date'} • ${report.vulnerabilities || 0} vulnerabilities</span>
                </div>
                <div class="report-actions">
                    <button class="btn btn-secondary btn-sm" data-file="${report.filename}" data-action="view">View</button>
                    <button class="btn btn-secondary btn-sm" data-file="${report.filename}" data-action="download">Download</button>
                    <button class="btn btn-icon btn-sm" data-file="${report.filename}" data-action="delete" title="Delete">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="3,6 5,6 21,6"></polyline>
                            <path d="M19,6v14a2,2 0 0,1-2,2H7a2,2 0 0,1-2-2V6m3,0V4a2,2 0 0,1,2-2h4a2,2 0 0,1,2,2v2"></path>
                        </svg>
                    </button>
                </div>
            `;
            reportsList.appendChild(item);
        });
        
        // Bind actions
        reportsList.querySelectorAll('button[data-action]').forEach(btn => {
            btn.addEventListener('click', () => {
                const file = btn.dataset.file;
                const action = btn.dataset.action;
                this.handleReportAction(file, action);
            });
        });
    }
    
    async handleReportAction(filename, action) {
        switch (action) {
            case 'view':
                window.open(`/api/reports/${filename}`, '_blank');
                break;
            case 'download':
                const link = document.createElement('a');
                link.href = `/api/reports/${filename}`;
                link.download = filename;
                link.click();
                break;
            case 'delete':
                if (confirm(`Delete report ${filename}?`)) {
                    try {
                        await fetch(`/api/reports/${filename}`, { method: 'DELETE' });
                        this.loadReports();
                        this.showToast('Report deleted', 'success');
                    } catch {
                        this.showToast('Failed to delete report', 'error');
                    }
                }
                break;
        }
    }
    
    // ==========================================
    // Export
    // ==========================================
    
    async exportResults(format) {
        if (!this.currentResults) {
            this.showToast('No results to export', 'error');
            return;
        }
        
        if (format === 'json') {
            const blob = new Blob([JSON.stringify(this.currentResults, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `pennywise-scan-${Date.now()}.json`;
            link.click();
            URL.revokeObjectURL(url);
            this.showToast('Report exported as JSON', 'success');
        } else if (format === 'html') {
            this.showToast('Generating AI-enhanced HTML report...', 'info');
            const html = await this.generateHtmlReport(this.currentResults);
            const blob = new Blob([html], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `pennywise-ai-report-${Date.now()}.html`;
            link.click();
            URL.revokeObjectURL(url);
            this.showToast('AI Report exported as HTML', 'success');
        }
    }
    
    async generateHtmlReport(data) {
        const vulns = data.vulnerabilities || [];
        
        // Fetch AI insights for vulnerabilities
        const vulnsWithAI = await Promise.all(
            vulns.slice(0, 20).map(async (vuln) => {
                try {
                    const [classification, remediation] = await Promise.all([
                        this.fetchClassification(vuln),
                        this.fetchRemediation(vuln)
                    ]);
                    return {
                        ...vuln,
                        ai_classification: classification?.classification,
                        ai_remediation: remediation?.remediation
                    };
                } catch (error) {
                    console.error('Error fetching AI for vuln:', error);
                    return vuln;
                }
            })
        );
        
        return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PennyWise Scan Report</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #0d1117; color: #f0f6fc; }
        h1 { color: #58a6ff; }
        .vuln-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .severity { padding: 4px 12px; border-radius: 4px; font-weight: bold; text-transform: uppercase; font-size: 12px; }
        .critical { background: #da3633; color: white; }
        .high { background: #f85149; color: white; }
        .medium { background: #d29922; color: white; }
        .low { background: #3fb950; color: white; }
        .info { background: #58a6ff; color: white; }
        .ai-section { background: rgba(0, 212, 255, 0.05); border-left: 3px solid #00d4ff; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .ai-section h4 { color: #00d4ff; margin: 0 0 10px 0; }
        .remedy-section { background: rgba(124, 58, 237, 0.05); border-left: 3px solid #7c3aed; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .remedy-section h4 { color: #7c3aed; margin: 0 0 10px 0; }
        .remedy-steps { margin-left: 20px; line-height: 1.8; }
        dl { display: grid; grid-template-columns: 150px 1fr; gap: 8px; margin: 10px 0; }
        dt { font-weight: bold; color: #8b949e; }
        dd { margin: 0; }
        code { background: #0d1117; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <h1>🛡️ PennyWise AI Security Report</h1>
    <p><strong>Generated:</strong> ${new Date().toISOString()}</p>
    <p><strong>Target:</strong> ${data.target || 'Unknown'}</p>
    <p><strong>Total Vulnerabilities:</strong> ${vulns.length}</p>
    <p style="color: #8b949e; font-size: 14px;">⚠️ Note: AI insights included for first 20 vulnerabilities</p>
    
    ${vulnsWithAI.map(v => `
    <div class="vuln-card">
        <div class="vuln-header">
            <h3 style="margin: 0;">${v.type || 'Unknown'} Vulnerability</h3>
            <span class="severity ${(v.severity || 'info').toLowerCase()}">${v.severity || 'Info'}</span>
        </div>
        
        <dl>
            <dt>URL:</dt><dd><code>${this.escapeHtml(v.url || '')}</code></dd>
            <dt>Parameter:</dt><dd><code>${this.escapeHtml(v.parameter || 'N/A')}</code></dd>
            <dt>Payload:</dt><dd><code>${this.escapeHtml(v.payload || '')}</code></dd>
            <dt>Details:</dt><dd>${this.escapeHtml(v.details || '')}</dd>
        </dl>
        
        ${v.ai_classification ? `
        <div class="ai-section">
            <h4>🤖 AI Classification Analysis</h4>
            <dl>
                <dt>CVSS Score:</dt><dd><strong>${v.ai_classification.cvss_score}</strong> (${v.ai_classification.risk_level})</dd>
                <dt>Exploitability:</dt><dd>${v.ai_classification.exploitability}</dd>
                <dt>Business Impact:</dt><dd>${v.ai_classification.business_impact}</dd>
                <dt>Remediation Effort:</dt><dd>${v.ai_classification.remediation_effort}</dd>
            </dl>
        </div>
        ` : ''}
        
        ${v.ai_remediation ? `
        <div class="remedy-section">
            <h4>🛡️ AI Remediation Guide</h4>
            <p><strong>Priority:</strong> ${v.ai_remediation.priority}</p>
            ${v.ai_remediation.steps ? `
            <ol class="remedy-steps">
                ${v.ai_remediation.steps.map(step => `<li>${this.escapeHtml(step)}</li>`).join('')}
            </ol>
            ` : ''}
            ${v.ai_remediation.code_example ? `
            <div style="margin-top: 10px;">
                <strong>Code Example:</strong>
                <pre style="background: #0d1117; padding: 10px; overflow-x: auto; border-radius: 4px;"><code>${this.escapeHtml(v.ai_remediation.code_example)}</code></pre>
            </div>
            ` : ''}
        </div>
        ` : ''}
    </div>
    `).join('')}
    
    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #30363d; text-align: center; color: #8b949e;">
        <p>Generated by PennyWise AI Security Scanner</p>
    </footer>
</body>
</html>`;
    }
    
    // ==========================================
    // Log & Toast
    // ==========================================
    
    addLogEntry(message, level = 'info') {
        const logContent = document.getElementById('log-content');
        if (!logContent) return;
        
        const entry = document.createElement('div');
        entry.className = `log-entry log-${level}`;
        entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        logContent.appendChild(entry);
        logContent.scrollTop = logContent.scrollHeight;
    }
    
    clearLog() {
        const logContent = document.getElementById('log-content');
        if (logContent) {
            logContent.innerHTML = '<div class="log-entry log-info">Log cleared</div>';
        }
    }
    
    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `<span class="toast-message">${message}</span>`;
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
    
    // ==========================================
    // Utilities
    // ==========================================
    
    capitalizeFirst(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }
    
    truncate(str, length) {
        if (str.length <= length) return str;
        return str.substring(0, length) + '...';
    }
    
    truncateUrl(url) {
        if (url.length <= 50) return url;
        try {
            const parsed = new URL(url);
            return parsed.hostname + '...' + url.slice(-20);
        } catch {
            return this.truncate(url, 50);
        }
    }
    
    escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
}

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    window.pennywise = new PennyWiseApp();
});
