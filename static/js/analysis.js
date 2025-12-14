/**
 * Analysis UI Handler
 * Manages the visitor analysis process and displays results
 */

document.addEventListener('DOMContentLoaded', async function() {
    await runAnalysis();
});

async function runAnalysis() {
    try {
        // Show loading screen
        showLoadingScreen();

        // Simulate progress updates
        simulateProgress();

        // Collect browser fingerprint
        updateLoadingStatus('Collecting browser fingerprint...');
        const fingerprinter = new BrowserFingerprint();
        const fingerprint = await fingerprinter.collect();

        // Wait a bit for async operations
        await sleep(2000);

        // Send to server for analysis
        updateLoadingStatus('Analyzing visitor data...');
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                fingerprint: fingerprint
            })
        });

        if (!response.ok) {
            throw new Error('Analysis failed');
        }

        const data = await response.json();

        if (data.success) {
            // Complete progress
            setProgress(100);
            await sleep(500);

            // Hide loading and show results
            hideLoadingScreen();
            displayResults(data.results);
        } else {
            throw new Error(data.error || 'Unknown error');
        }

    } catch (error) {
        console.error('Analysis error:', error);
        alert('Analysis failed: ' + error.message);
    }
}

function showLoadingScreen() {
    document.getElementById('loadingScreen').style.display = 'block';
    document.getElementById('resultsContainer').style.display = 'none';
}

function hideLoadingScreen() {
    document.getElementById('loadingScreen').style.display = 'none';
    document.getElementById('resultsContainer').style.display = 'block';
}

function updateLoadingStatus(message) {
    document.getElementById('loadingStatus').textContent = message;
}

function setProgress(percent) {
    const progressBar = document.getElementById('progressBar');
    progressBar.style.width = percent + '%';
    progressBar.textContent = percent + '%';
}

async function simulateProgress() {
    const steps = [
        { percent: 20, delay: 500 },
        { percent: 40, delay: 800 },
        { percent: 60, delay: 600 },
        { percent: 80, delay: 700 },
    ];

    for (const step of steps) {
        await sleep(step.delay);
        setProgress(step.percent);
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function displayResults(results) {
    // Display Overall Risk Assessment
    displayRiskAssessment(results.risk_assessment);

    // Display all analysis sections
    displayBasicInfo(results.basic_info);
    displayHeaderAnalysis(results.header_analysis);
    displayUserAgentAnalysis(results.user_agent_analysis);
    displayFingerprintAnalysis(results.browser_fingerprint);
    displayProxyVpnDetection(results.proxy_vpn_detection);
    displayAutomationDetection(results.automation_detection);
    displayConsistencyChecks(results.consistency_checks);
    displayThreatIndicators(results.threat_indicators);
    displayBehavioralSignals(results.behavioral_signals);

    // Display NEW advanced analysis sections
    displayAdvancedMouseTracking(results.advanced_behavioral);
    displayKeyboardScrollBehavior(results.advanced_behavioral);
    displayTimingAnalysis(results.timing_analysis);
    displayVMDetection(results.vm_detection);
    displayBrowserExtensions(results.browser_extensions);
    displayCSSMediaQueries(results.css_media_queries);
    displaySpeechClientHints(results.speech_synthesis, results.client_hints);
}

function displayRiskAssessment(risk) {
    // Risk Score
    document.getElementById('riskScore').textContent = risk.total_score;
    const riskCard = document.getElementById('riskScoreCard');

    if (risk.risk_level === 'critical' || risk.risk_level === 'high') {
        riskCard.classList.add('bg-danger', 'bg-opacity-10', 'border-danger');
    } else if (risk.risk_level === 'medium') {
        riskCard.classList.add('bg-warning', 'bg-opacity-10', 'border-warning');
    } else {
        riskCard.classList.add('bg-success', 'bg-opacity-10', 'border-success');
    }

    // Visitor Quality
    const qualityElement = document.getElementById('visitorQuality');
    qualityElement.textContent = risk.visitor_quality.toUpperCase();
    qualityElement.className = 'fw-bold mb-0 ' + getQualityClass(risk.visitor_quality);

    // Authenticity
    const genuineElement = document.getElementById('genuineStatus');
    genuineElement.textContent = risk.is_genuine ? 'GENUINE' : 'SUSPICIOUS';
    genuineElement.className = 'fw-bold mb-0 ' + (risk.is_genuine ? 'text-success' : 'text-danger');

    // Confidence
    document.getElementById('confidence').textContent = risk.confidence + '%';

    // Red Flags
    const redFlagsList = document.getElementById('redFlagsList');
    document.getElementById('redFlagCount').textContent = risk.red_flags.length;
    redFlagsList.innerHTML = '';
    risk.red_flags.forEach(flag => {
        const li = document.createElement('li');
        li.className = 'mb-2';
        li.innerHTML = `<i class="bi bi-x-circle text-danger me-2"></i><span class="status-bad">${flag}</span>`;
        redFlagsList.appendChild(li);
    });

    // Green Flags
    const greenFlagsList = document.getElementById('greenFlagsList');
    document.getElementById('greenFlagCount').textContent = risk.green_flags.length;
    greenFlagsList.innerHTML = '';
    risk.green_flags.forEach(flag => {
        const li = document.createElement('li');
        li.className = 'mb-2';
        li.innerHTML = `<i class="bi bi-check-circle text-success me-2"></i><span class="status-good">${flag}</span>`;
        greenFlagsList.appendChild(li);
    });
}

function displayBasicInfo(info) {
    const table = document.getElementById('basicInfoTable');
    table.innerHTML = `
        <tbody>
            <tr><th>IP Address</th><td><code>${info.ip_address}</code></td></tr>
            <tr><th>Timestamp</th><td>${info.timestamp}</td></tr>
            <tr><th>Method</th><td><span class="badge bg-primary">${info.method}</span></td></tr>
            <tr><th>Protocol</th><td>${info.protocol}</td></tr>
            <tr><th>Secure Connection</th><td>${getBadge(info.is_secure, 'Yes', 'No')}</td></tr>
        </tbody>
    `;
}

function displayHeaderAnalysis(analysis) {
    const container = document.getElementById('headerAnalysis');

    let html = `
        <div class="mb-3">
            <strong>Header Quality:</strong>
            <span class="${getStatusClass(analysis.header_quality)}">${analysis.header_quality.toUpperCase()}</span>
        </div>
        <div class="mb-3">
            <strong>Total Headers:</strong> ${analysis.total_headers}
        </div>
    `;

    if (analysis.missing_standard_headers.length > 0) {
        html += `
            <div class="alert alert-warning mb-3">
                <strong><i class="bi bi-exclamation-triangle me-2"></i>Missing Headers:</strong>
                <ul class="mb-0 mt-2">
                    ${analysis.missing_standard_headers.map(h => `<li><code>${h}</code></li>`).join('')}
                </ul>
            </div>
        `;
    }

    if (analysis.suspicious_patterns.length > 0) {
        html += `
            <div class="alert alert-danger mb-3">
                <strong><i class="bi bi-shield-x me-2"></i>Suspicious Patterns:</strong>
                <ul class="mb-0 mt-2">
                    ${analysis.suspicious_patterns.map(p => `<li class="status-bad">${p}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    if (Object.keys(analysis.proxy_headers).length > 0) {
        html += `
            <div class="alert alert-warning mb-3">
                <strong><i class="bi bi-hdd-network me-2"></i>Proxy Headers Found:</strong>
                <ul class="mb-0 mt-2">
                    ${Object.entries(analysis.proxy_headers).map(([k, v]) =>
                        `<li><code>${k}:</code> ${v}</li>`
                    ).join('')}
                </ul>
            </div>
        `;
    }

    container.innerHTML = html;
}

function displayUserAgentAnalysis(analysis) {
    const container = document.getElementById('userAgentAnalysis');

    let html = `
        <div class="mb-3">
            <strong>Quality:</strong>
            <span class="${getStatusClass(analysis.quality)}">${analysis.quality.toUpperCase()}</span>
        </div>
        <div class="mb-3">
            <strong>User-Agent String:</strong><br>
            <code class="d-block mt-2 p-2 bg-dark rounded">${analysis.raw_user_agent}</code>
        </div>
    `;

    if (analysis.parsed && Object.keys(analysis.parsed).length > 0) {
        html += `
            <div class="row mb-3">
                <div class="col-md-6">
                    <table class="table table-sm table-dark">
                        <tr><th>Browser</th><td>${analysis.parsed.browser} ${analysis.parsed.browser_version}</td></tr>
                        <tr><th>OS</th><td>${analysis.parsed.os} ${analysis.parsed.os_version}</td></tr>
                        <tr><th>Device</th><td>${analysis.parsed.device}</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <table class="table table-sm table-dark">
                        <tr><th>Is Mobile</th><td>${getBadge(analysis.parsed.is_mobile, 'Yes', 'No')}</td></tr>
                        <tr><th>Is Tablet</th><td>${getBadge(analysis.parsed.is_tablet, 'Yes', 'No')}</td></tr>
                        <tr><th>Is Bot</th><td>${getBadge(analysis.parsed.is_bot, 'Yes', 'No', true)}</td></tr>
                    </table>
                </div>
            </div>
        `;
    }

    if (analysis.suspicious_patterns.length > 0) {
        html += `
            <div class="alert alert-danger">
                <strong><i class="bi bi-bug me-2"></i>Suspicious Patterns:</strong>
                <ul class="mb-0 mt-2">
                    ${analysis.suspicious_patterns.map(p => `<li class="status-bad">${p}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    container.innerHTML = html;
}

function displayFingerprintAnalysis(analysis) {
    const container = document.getElementById('fingerprintAnalysis');

    let html = `
        <div class="mb-3">
            <strong>Fingerprint Quality:</strong>
            <span class="${getStatusClass(analysis.quality)}">${analysis.quality.toUpperCase()}</span>
        </div>
    `;

    if (analysis.manipulation_indicators.length > 0) {
        html += `
            <div class="alert alert-danger mb-3">
                <strong><i class="bi bi-exclamation-octagon me-2"></i>Manipulation Indicators:</strong>
                <div class="mt-2">
                    ${analysis.manipulation_indicators.map(i => {
                        if (typeof i === 'object') {
                            return `
                                <div class="mb-2 p-2 bg-dark bg-opacity-50 rounded">
                                    <div class="status-bad">${i.message}</div>
                                    <small class="text-muted">
                                        <code>${i.property || 'N/A'}</code> =
                                        <span class="text-warning">${i.value}</span>
                                    </small>
                                </div>
                            `;
                        } else {
                            return `<li class="status-bad">${i}</li>`;
                        }
                    }).join('')}
                </div>
            </div>
        `;
    }

    if (analysis.inconsistencies.length > 0) {
        html += `
            <div class="alert alert-warning mb-3">
                <strong><i class="bi bi-question-circle me-2"></i>Inconsistencies:</strong>
                <div class="mt-2">
                    ${analysis.inconsistencies.map(i => {
                        if (typeof i === 'object') {
                            return `
                                <div class="mb-2 p-2 bg-dark bg-opacity-50 rounded">
                                    <div class="status-suspicious">${i.message}</div>
                                    <small class="text-muted">
                                        <code>${i.property || 'N/A'}</code> =
                                        <span class="text-warning">${i.value}</span>
                                    </small>
                                </div>
                            `;
                        } else {
                            return `<li class="status-suspicious">${i}</li>`;
                        }
                    }).join('')}
                </div>
            </div>
        `;
    }

    // Display fingerprint data summary
    const fp = analysis.fingerprint_data;
    if (fp && Object.keys(fp).length > 0) {
        html += `
            <div class="row">
                <div class="col-md-6">
                    <h6 class="mb-3">Device Information</h6>
                    <table class="table table-sm table-dark">
                        ${fp.platform ? `<tr><th>Platform</th><td>${fp.platform}</td></tr>` : ''}
                        ${fp.screen_width ? `<tr><th>Screen</th><td>${fp.screen_width}x${fp.screen_height}</td></tr>` : ''}
                        ${fp.hardware_concurrency ? `<tr><th>CPU Cores</th><td>${fp.hardware_concurrency}</td></tr>` : ''}
                        ${fp.device_memory ? `<tr><th>Device Memory</th><td>${fp.device_memory} GB</td></tr>` : ''}
                        ${fp.timezone ? `<tr><th>Timezone</th><td>${fp.timezone}</td></tr>` : ''}
                    </table>
                </div>
                <div class="col-md-6">
                    <h6 class="mb-3">Browser Features</h6>
                    <table class="table table-sm table-dark">
                        ${fp.webdriver !== undefined ? `<tr><th>WebDriver</th><td>${getBadge(fp.webdriver, 'Yes', 'No', true)}</td></tr>` : ''}
                        ${fp.plugins !== undefined ? `<tr><th>Plugins</th><td>${fp.plugins}</td></tr>` : ''}
                        ${fp.canvas ? `<tr><th>Canvas</th><td>${fp.canvas === 'blocked' ? '<span class="status-bad">Blocked</span>' : '<span class="status-good">Available</span>'}</td></tr>` : ''}
                        ${fp.webgl_vendor ? `<tr><th>WebGL Vendor</th><td>${fp.webgl_vendor}</td></tr>` : ''}
                    </table>
                </div>
            </div>
        `;
    }

    container.innerHTML = html;
}

function displayProxyVpnDetection(detection) {
    const container = document.getElementById('proxyVpnDetection');

    let html = `
        <div class="mb-3">
            <strong>Risk Level:</strong>
            <span class="${getRiskLevelClass(detection.risk_level)}">${detection.risk_level.toUpperCase()}</span>
        </div>
        <div class="mb-3">
            <strong>Proxy Likely:</strong>
            ${getBadge(detection.is_proxy_likely, 'Yes', 'No', true)}
        </div>
    `;

    if (detection.proxy_headers_found.length > 0) {
        html += `
            <div class="alert alert-warning mb-3">
                <strong><i class="bi bi-hdd-network me-2"></i>Proxy Headers Detected:</strong>
                <ul class="mb-0 mt-2">
                    ${detection.proxy_headers_found.map(h => `<li><code>${h}</code></li>`).join('')}
                </ul>
            </div>
        `;
    }

    if (detection.indicators.length > 0) {
        html += `
            <div class="alert alert-danger">
                <strong><i class="bi bi-shield-x me-2"></i>Detection Indicators:</strong>
                <div class="mt-2">
                    ${detection.indicators.map(i => {
                        if (typeof i === 'object') {
                            return `
                                <div class="mb-2 p-2 bg-dark bg-opacity-50 rounded">
                                    <div class="status-bad">${i.message}</div>
                                    <small class="text-muted">
                                        <code>${i.header || i.property || 'N/A'}</code> =
                                        <span class="text-warning">${i.value}</span>
                                    </small>
                                </div>
                            `;
                        } else {
                            return `<li class="status-bad">${i}</li>`;
                        }
                    }).join('')}
                </div>
            </div>
        `;
    } else {
        html += `<div class="alert alert-success">No proxy/VPN indicators detected</div>`;
    }

    container.innerHTML = html;
}

function displayAutomationDetection(detection) {
    const container = document.getElementById('automationDetection');

    let html = `
        <div class="mb-3">
            <strong>Detection Confidence:</strong>
            <span class="${getConfidenceClass(detection.confidence)}">${detection.confidence.toUpperCase().replace('_', ' ')}</span>
        </div>
    `;

    if (detection.automation_type.length > 0) {
        html += `
            <div class="alert alert-danger mb-3">
                <strong><i class="bi bi-robot me-2"></i>Automation Tools Detected:</strong>
                <ul class="mb-0 mt-2">
                    ${detection.automation_type.map(t => `<li class="status-bad">${t}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    if (detection.indicators.length > 0) {
        html += `
            <div class="alert alert-warning">
                <strong><i class="bi bi-gear me-2"></i>Automation Indicators:</strong>
                <div class="mt-2">
                    ${detection.indicators.map(i => {
                        if (typeof i === 'object') {
                            return `
                                <div class="mb-2 p-2 bg-dark bg-opacity-50 rounded">
                                    <div class="status-suspicious">${i.message}</div>
                                    <small class="text-muted">
                                        <code>${i.property || 'N/A'}</code> =
                                        <span class="text-warning">${i.value}</span>
                                        ${i.tool ? `<span class="badge bg-danger ms-2">${i.tool}</span>` : ''}
                                    </small>
                                </div>
                            `;
                        } else {
                            return `<li class="status-suspicious">${i}</li>`;
                        }
                    }).join('')}
                </div>
            </div>
        `;
    } else {
        html += `<div class="alert alert-success">No automation detected</div>`;
    }

    container.innerHTML = html;
}

function displayConsistencyChecks(checks) {
    const container = document.getElementById('consistencyChecks');

    let html = `
        <div class="row mb-3">
            <div class="col-md-4">
                <div class="text-center p-3 bg-success bg-opacity-10 rounded">
                    <h4 class="text-success">${checks.passed}</h4>
                    <small class="text-muted">Passed</small>
                </div>
            </div>
            <div class="col-md-4">
                <div class="text-center p-3 bg-warning bg-opacity-10 rounded">
                    <h4 class="text-warning">${checks.warnings}</h4>
                    <small class="text-muted">Warnings</small>
                </div>
            </div>
            <div class="col-md-4">
                <div class="text-center p-3 bg-danger bg-opacity-10 rounded">
                    <h4 class="text-danger">${checks.failed}</h4>
                    <small class="text-muted">Failed</small>
                </div>
            </div>
        </div>
    `;

    if (checks.checks.length > 0) {
        html += `<table class="table table-dark table-sm">
            <thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead>
            <tbody>`;

        checks.checks.forEach(check => {
            const statusClass = check.status === 'passed' ? 'success' :
                              check.status === 'warning' ? 'warning' : 'danger';
            const icon = check.status === 'passed' ? 'check-circle' :
                        check.status === 'warning' ? 'exclamation-triangle' : 'x-circle';

            html += `
                <tr>
                    <td>${check.check}</td>
                    <td><i class="bi bi-${icon} text-${statusClass}"></i></td>
                    <td><small>${check.details}</small></td>
                </tr>
            `;
        });

        html += `</tbody></table>`;
    }

    container.innerHTML = html;
}

function displayThreatIndicators(threats) {
    const container = document.getElementById('threatIndicators');

    let html = `
        <div class="mb-3">
            <strong>Threat Level:</strong>
            <span class="${getRiskLevelClass(threats.threat_level)}">${threats.threat_level.toUpperCase()}</span>
        </div>
    `;

    if (threats.threats_detected.length > 0) {
        html += `
            <div class="alert alert-danger mb-3">
                <strong><i class="bi bi-exclamation-octagon me-2"></i>Threats Detected:</strong>
                <ul class="mb-0 mt-2">
                    ${threats.threats_detected.map(t => `<li class="status-bad">${t}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    if (threats.risk_factors.length > 0) {
        html += `
            <div class="alert alert-warning">
                <strong><i class="bi bi-shield-exclamation me-2"></i>Risk Factors:</strong>
                <ul class="mb-0 mt-2">
                    ${threats.risk_factors.map(r => `<li class="status-suspicious">${r}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    if (threats.threats_detected.length === 0 && threats.risk_factors.length === 0) {
        html += `<div class="alert alert-success">No threats detected</div>`;
    }

    container.innerHTML = html;
}

function displayBehavioralSignals(signals) {
    const container = document.getElementById('behavioralSignals');

    let html = `
        <div class="mb-3">
            <strong>Behavioral Score:</strong>
            <span class="${getBehavioralClass(signals.behavioral_score)}">${signals.behavioral_score.toUpperCase().replace('_', ' ')}</span>
        </div>
        <table class="table table-dark table-sm">
            <tbody>
                <tr><th>Mouse Movement</th><td>${getBadge(signals.mouse_movement, 'Detected', 'Not Detected', false)}</td></tr>
                <tr><th>Keyboard Input</th><td>${getBadge(signals.keyboard_input, 'Detected', 'Not Detected', false)}</td></tr>
                <tr><th>Touch Support</th><td>${getBadge(signals.touch_support, 'Yes', 'No')}</td></tr>
                <tr><th>Page Focus</th><td>${getBadge(signals.page_focus, 'Yes', 'No', false)}</td></tr>
                <tr><th>Scroll Behavior</th><td>${getBadge(signals.scroll_behavior, 'Detected', 'Not Detected', false)}</td></tr>
            </tbody>
        </table>
    `;

    container.innerHTML = html;
}

// Helper functions
function getQualityClass(quality) {
    const map = {
        'good': 'text-success',
        'acceptable': 'text-info',
        'suspicious': 'text-warning',
        'bad': 'text-danger'
    };
    return map[quality] || 'text-muted';
}

function getStatusClass(status) {
    const map = {
        'good': 'status-good',
        'acceptable': 'status-info',
        'suspicious': 'status-suspicious',
        'bad': 'status-bad',
        'unknown': 'status-warning'
    };
    return map[status] || 'status-warning';
}

function getRiskLevelClass(level) {
    const map = {
        'none': 'text-success',
        'low': 'text-info',
        'medium': 'text-warning',
        'high': 'text-danger',
        'critical': 'text-danger fw-bold'
    };
    return map[level] || 'text-muted';
}

function getConfidenceClass(confidence) {
    const map = {
        'very_high': 'text-danger fw-bold',
        'high': 'text-danger',
        'medium': 'text-warning',
        'low': 'text-success'
    };
    return map[confidence] || 'text-muted';
}

function getBehavioralClass(score) {
    const map = {
        'human_likely': 'text-success',
        'uncertain': 'text-warning',
        'bot_likely': 'text-danger'
    };
    return map[score] || 'text-muted';
}

function getBadge(condition, trueText, falseText, inverse = false) {
    const isTrue = inverse ? !condition : condition;
    const badgeClass = isTrue ? 'bg-success' : 'bg-danger';
    const text = condition ? trueText : falseText;
    return `<span class="badge ${badgeClass}">${text}</span>`;
}

// ========== NEW DISPLAY FUNCTIONS FOR ADVANCED FEATURES ==========

function displayAdvancedMouseTracking(advanced) {
    const container = document.getElementById('advancedMouseTracking');
    if (!advanced) return;

    const mouse = advanced.mouse_behavior || {};
    const click = advanced.click_behavior || {};

    let html = `
        <div class="mb-3">
            <strong>Human Likelihood:</strong>
            <span class="${getHumanLikelihoodClass(advanced.human_likelihood)}">${advanced.human_likelihood.toUpperCase()}</span>
        </div>
        <div class="row">
            <div class="col-md-6">
                <h6 class="mb-3">Mouse Movement Analysis</h6>
                <table class="table table-sm table-dark">
                    <tr><th>Total Movements</th><td>${mouse.total_movements || 0}</td></tr>
                    <tr><th>Average Velocity</th><td>${mouse.average_velocity || 0} px/s</td></tr>
                    <tr><th>Max Velocity</th><td>${mouse.max_velocity || 0} px/s</td></tr>
                    <tr><th>Average Acceleration</th><td>${mouse.average_acceleration || 0}</td></tr>
                    <tr><th>Human Curves Detected</th><td>${getBadge(mouse.has_human_curves, 'Yes', 'No')}</td></tr>
                    <tr><th>Quality</th><td><span class="${getStatusClass(mouse.quality)}">${(mouse.quality || 'unknown').toUpperCase()}</span></td></tr>
                </table>
    `;

    if (mouse.bot_indicator) {
        html += `
            <div class="alert alert-danger">
                <strong><i class="bi bi-robot me-2"></i>Bot Indicator:</strong>
                <div class="mt-2 p-2 bg-dark bg-opacity-50 rounded">
                    <div class="status-bad">${mouse.bot_indicator}</div>
                    <small class="text-muted">
                        <div>Max Velocity: <span class="text-warning">${mouse.max_velocity || 0} px/s</span></div>
                        <div>Avg Velocity: <span class="text-warning">${mouse.average_velocity || 0} px/s</span></div>
                        <div>Human Curves: <span class="text-warning">${mouse.has_human_curves ? 'Yes' : 'No'}</span></div>
                    </small>
                </div>
            </div>
        `;
    }

    html += `
            </div>
            <div class="col-md-6">
                <h6 class="mb-3">Click Behavior Analysis</h6>
                <table class="table table-sm table-dark">
                    <tr><th>Total Clicks</th><td>${click.total_clicks || 0}</td></tr>
                    <tr><th>Average Interval</th><td>${click.average_interval || 0} ms</td></tr>
                    <tr><th>Rhythm Variance</th><td>${click.rhythm_variance || 0}</td></tr>
                    <tr><th>Quality</th><td><span class="${getStatusClass(click.quality)}">${(click.quality || 'unknown').toUpperCase()}</span></td></tr>
                </table>
    `;

    if (click.bot_indicator) {
        html += `
            <div class="alert alert-danger">
                <strong><i class="bi bi-robot me-2"></i>Bot Indicator:</strong>
                <div class="mt-2 p-2 bg-dark bg-opacity-50 rounded">
                    <div class="status-bad">${click.bot_indicator}</div>
                    <small class="text-muted">
                        <div>Total Clicks: <span class="text-warning">${click.total_clicks || 0}</span></div>
                        <div>Avg Interval: <span class="text-warning">${click.average_interval || 0} ms</span></div>
                        <div>Rhythm Variance: <span class="text-warning">${click.rhythm_variance || 0}</span></div>
                    </small>
                </div>
            </div>
        `;
    } else if (click.rhythm_variance > 100) {
        html += `
            <div class="alert alert-success">
                <strong><i class="bi bi-check-circle me-2"></i>Human Pattern:</strong>
                Natural click rhythm variation detected (Variance: ${click.rhythm_variance})
            </div>
        `;
    }

    html += `</div></div>`;
    container.innerHTML = html;
}

function displayKeyboardScrollBehavior(advanced) {
    const container = document.getElementById('keyboardScrollBehavior');
    if (!advanced) return;

    const keyboard = advanced.keyboard_behavior || {};
    const scroll = advanced.scroll_behavior || {};

    let html = `
        <div class="row">
            <div class="col-12">
                <h6 class="mb-3">Keyboard Dynamics</h6>
                <table class="table table-sm table-dark">
                    <tr><th>Average Dwell Time</th><td>${keyboard.average_dwell_time || 0} ms</td></tr>
                    <tr><th>Average Flight Time</th><td>${keyboard.average_flight_time || 0} ms</td></tr>
                    <tr><th>Typing Rhythm</th><td>${keyboard.typing_rhythm || 0}</td></tr>
                    <tr><th>Quality</th><td><span class="${getStatusClass(keyboard.quality)}">${(keyboard.quality || 'unknown').toUpperCase()}</span></td></tr>
                </table>
            </div>
            <div class="col-12 mt-3">
                <h6 class="mb-3">Scroll Behavior</h6>
                <table class="table table-sm table-dark">
                    <tr><th>Total Scrolls</th><td>${scroll.total_scrolls || 0}</td></tr>
                    <tr><th>Average Velocity</th><td>${scroll.average_velocity || 0} px/s</td></tr>
                    <tr><th>Has Scrolled</th><td>${getBadge(scroll.has_scrolled, 'Yes', 'No')}</td></tr>
                </table>
            </div>
        </div>
    `;

    container.innerHTML = html;
}

function displayTimingAnalysis(timing) {
    const container = document.getElementById('timingAnalysis');
    if (!timing) return;

    let html = `
        <div class="mb-3">
            <strong>Suspicion Level:</strong>
            <span class="${getRiskLevelClass(timing.suspicion_level)}">${timing.suspicion_level.toUpperCase()}</span>
        </div>
        <table class="table table-sm table-dark">
            <tr><th>Page Load Time</th><td>${timing.page_load_time || 0} ms</td></tr>
            <tr><th>Time to First Interaction</th><td>${timing.time_to_first_interaction || 'N/A'} ms</td></tr>
            <tr><th>Time to First Click</th><td>${timing.time_to_first_click || 'N/A'} ms</td></tr>
            <tr><th>Time to First Scroll</th><td>${timing.time_to_first_scroll || 'N/A'} ms</td></tr>
        </table>
    `;

    if (timing.reason) {
        html += `
            <div class="alert alert-danger">
                <strong><i class="bi bi-exclamation-triangle me-2"></i>Timing Issue:</strong>
                <div class="mt-2 p-2 bg-dark bg-opacity-50 rounded">
                    <div class="status-bad">${timing.reason}</div>
                    <small class="text-muted">
                        <div>Page Load: <span class="text-warning">${timing.page_load_time || 0} ms</span></div>
                        <div>First Interaction: <span class="text-warning">${timing.time_to_first_interaction || 'N/A'} ms</span></div>
                        <div>First Click: <span class="text-warning">${timing.time_to_first_click || 'N/A'} ms</span></div>
                    </small>
                </div>
            </div>
        `;
    }

    container.innerHTML = html;
}

function displayVMDetection(vm) {
    const container = document.getElementById('vmDetection');
    if (!vm) return;

    let html = `
        <div class="mb-3">
            <strong>VM Likelihood:</strong>
            <span class="${getRiskLevelClass(vm.vm_likelihood)}">${vm.vm_likelihood.toUpperCase()}</span>
        </div>
        <div class="mb-3">
            <strong>Is Likely VM:</strong>
            ${getBadge(vm.is_likely_vm, 'Yes', 'No', true)}
        </div>
        <div class="mb-3">
            <strong>Total Indicators:</strong> ${vm.total_indicators}
        </div>
    `;

    if (vm.indicators && Object.keys(vm.indicators).length > 0) {
        const trueIndicators = Object.entries(vm.indicators).filter(([k, v]) => v === true);
        if (trueIndicators.length > 0) {
            html += `
                <div class="alert alert-warning">
                    <strong><i class="bi bi-hdd-rack me-2"></i>VM Indicators Found:</strong>
                    <div class="mt-2">
                        ${trueIndicators.map(([k, v]) => {
                            const displayName = k.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                            return `
                                <div class="mb-2 p-2 bg-dark bg-opacity-50 rounded">
                                    <div class="status-suspicious">${displayName}</div>
                                    <small class="text-muted">
                                        <code>${k}</code> = <span class="text-warning">true</span>
                                    </small>
                                </div>
                            `;
                        }).join('')}
                    </div>
                </div>
            `;
        }
    }

    container.innerHTML = html;
}

function displayBrowserExtensions(extensions) {
    const container = document.getElementById('browserExtensions');
    if (!extensions) return;

    let html = `
        <div class="mb-3">
            <strong>Total Detected:</strong> ${extensions.total_detected || 0}
        </div>
        <table class="table table-sm table-dark">
            <tr><th>Ad Blocker</th><td>${getBadge(extensions.adblock_detected, 'Detected', 'Not Found')}</td></tr>
            <tr><th>DevTools</th><td>${getBadge(extensions.devtools_detected, 'Detected', 'Not Found')}</td></tr>
            <tr><th>Privacy Concerned</th><td>${getBadge(extensions.privacy_concerned, 'Yes', 'No')}</td></tr>
        </table>
    `;

    if (extensions.privacy_concerned) {
        html += `
            <div class="alert alert-success">
                <strong><i class="bi bi-shield-check me-2"></i>Privacy-Aware User:</strong>
                Ad blocker or privacy extensions detected
            </div>
        `;
    }

    container.innerHTML = html;
}

function displayCSSMediaQueries(css) {
    const container = document.getElementById('cssMediaQueries');
    if (!css) return;

    let html = `
        <div class="mb-3">
            <strong>Total Features:</strong> ${css.total_features || 0}
        </div>
        <table class="table table-sm table-dark">
            <tr><th>Pointer Type</th><td><span class="badge bg-info">${css.pointer_type || 'unknown'}</span></td></tr>
            <tr><th>Hover Capable</th><td>${getBadge(css.hover_capable, 'Yes', 'No')}</td></tr>
            <tr><th>Color Gamut</th><td><span class="badge bg-info">${css.color_gamut || 'unknown'}</span></td></tr>
            <tr><th>Prefers Dark Mode</th><td>${getBadge(css.prefers_dark_mode, 'Yes', 'No')}</td></tr>
            <tr><th>Reduced Motion</th><td>${getBadge(css.reduced_motion, 'Yes', 'No')}</td></tr>
        </table>
    `;

    container.innerHTML = html;
}

function displaySpeechClientHints(speech, hints) {
    const container = document.getElementById('speechClientHints');

    let html = '<h6 class="mb-3">Speech Synthesis</h6>';

    if (speech && speech.supported) {
        html += `
            <table class="table table-sm table-dark mb-4">
                <tr><th>Supported</th><td>${getBadge(true, 'Yes', 'No')}</td></tr>
                <tr><th>Voices Count</th><td>${speech.voices_count || 0}</td></tr>
                <tr><th>Has Voices</th><td>${getBadge(speech.has_voices, 'Yes', 'No')}</td></tr>
                <tr><th>Uniqueness</th><td><span class="badge bg-info">${speech.uniqueness || 'unknown'}</span></td></tr>
            </table>
        `;
    } else {
        html += `<p class="text-muted">Not supported</p>`;
    }

    html += '<h6 class="mb-3 mt-4">Client Hints (UA-CH)</h6>';

    if (hints && hints.supported) {
        html += `
            <table class="table table-sm table-dark">
                <tr><th>Supported</th><td>${getBadge(true, 'Yes', 'No')}</td></tr>
                <tr><th>Mobile</th><td>${getBadge(hints.mobile, 'Yes', 'No')}</td></tr>
                <tr><th>Platform</th><td>${hints.platform || 'unknown'}</td></tr>
                ${hints.architecture ? `<tr><th>Architecture</th><td>${hints.architecture}</td></tr>` : ''}
                ${hints.bitness ? `<tr><th>Bitness</th><td>${hints.bitness}-bit</td></tr>` : ''}
            </table>
        `;
    } else {
        html += `<p class="text-muted">Not supported</p>`;
    }

    container.innerHTML = html;
}

function getHumanLikelihoodClass(likelihood) {
    const map = {
        'high': 'text-success fw-bold',
        'medium': 'text-warning',
        'low': 'text-danger fw-bold',
        'unknown': 'text-muted'
    };
    return map[likelihood] || 'text-muted';
}
