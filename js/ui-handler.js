/**
 * UI Handler for Marstek Firmware Analyzer
 */

let analyzer = null;
let analysisResults = null;

function initializeApp() {
    analyzer = new FirmwareAnalyzer();
    setupEventListeners();
}

function setupEventListeners() {
    const fileInput = document.getElementById('firmwareFile');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const downloadAllBtn = document.getElementById('downloadAllBtn');

    // File input change handler
    fileInput.addEventListener('change', function(event) {
        const file = event.target.files[0];
        analyzeBtn.disabled = !file;
        
        // Reset previous results
        hideSection('resultsSection');
        hideSection('errorSection');
        hideSection('progressSection');
    });

    // Analyze button handler
    analyzeBtn.addEventListener('click', function() {
        const fileInput = document.getElementById('firmwareFile');
        const file = fileInput.files[0];
        
        if (file) {
            analyzeFirmware(file);
        }
    });

    // Download all button handler
    downloadAllBtn.addEventListener('click', function() {
        if (analysisResults && analysisResults.certificates) {
            downloadAllCertificates();
        }
    });
}

async function analyzeFirmware(file) {
    try {
        // Show progress section and hide others
        showSection('progressSection');
        hideSection('resultsSection');
        hideSection('errorSection');
        
        // Disable analyze button and show spinner
        const analyzeBtn = document.getElementById('analyzeBtn');
        const spinner = document.getElementById('analyzeSpinner');
        analyzeBtn.disabled = true;
        spinner.classList.remove('d-none');

        // Read file
        const fileData = await readFileAsArrayBuffer(file);
        
        // Run analysis with progress updates
        analysisResults = await analyzer.analyze(fileData, updateProgress);
        
        // Display results
        displayResults(analysisResults);
        
        // Hide progress, show results
        hideSection('progressSection');
        showSection('resultsSection');
        
    } catch (error) {
        console.error('Analysis error:', error);
        showError(error.message);
        hideSection('progressSection');
    } finally {
        // Re-enable analyze button and hide spinner
        const analyzeBtn = document.getElementById('analyzeBtn');
        const spinner = document.getElementById('analyzeSpinner');
        analyzeBtn.disabled = false;
        spinner.classList.add('d-none');
    }
}

function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(new Error('Failed to read file'));
        reader.readAsArrayBuffer(file);
    });
}

function updateProgress(percentage, message) {
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    
    progressBar.style.width = `${percentage}%`;
    progressBar.setAttribute('aria-valuenow', percentage);
    progressText.textContent = message;
}

function displayResults(results) {
    displaySummary(results.summary);
    displayAwsEndpoints(results.awsEndpoints);
    displayCertificates(results.certificates);
}

function displaySummary(summary) {
    const summarySection = document.getElementById('summarySection');
    summarySection.innerHTML = `
        <h6 class="mb-3">Analysis Summary</h6>
        <div class="summary-stats">
            <div class="stat-item">
                <div class="stat-number">${summary.certificatesFound}</div>
                <div class="stat-label">Certificates Extracted</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">${summary.awsEndpointsFound}</div>
                <div class="stat-label">AWS Endpoints Found</div>
            </div>
        </div>
    `;
}

function displayAwsEndpoints(endpoints) {
    const awsSection = document.getElementById('awsSection');
    
    if (endpoints && endpoints.length > 0) {
        let html = '<h6 class="mb-3">AWS IoT Endpoints</h6>';
        endpoints.forEach(endpoint => {
            html += `
                <div class="aws-endpoint mb-2">
                    <strong>AWS IoT Endpoint:</strong> ${escapeHtml(endpoint.decoded)}
                </div>
            `;
        });
        awsSection.innerHTML = html;
    } else {
        awsSection.innerHTML = '<h6 class="mb-3">AWS IoT Endpoints</h6><p class="text-muted">No AWS IoT endpoints found</p>';
    }
}

function displayCertificates(certificates) {
    const certificatesSection = document.getElementById('certificatesSection');
    
    if (certificates && certificates.length > 0) {
        let html = '<h6 class="mb-3">Extracted Certificates</h6>';
        
        certificates.forEach((cert, index) => {
            const certDetails = parseCertificateDetails(cert.decrypted);
            
            html += `
                <div class="certificate-item">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <h6 class="mb-0">Certificate ${cert.index}: ${cert.type}</h6>
                        <button type="button" class="btn btn-outline-primary btn-sm download-btn" 
                                onclick="downloadCertificate(${index})">
                            Download ${cert.filename}
                        </button>
                    </div>
                    
                    <div class="certificate-details">
                        <div class="row">
                            <div class="col-md-6">
                                <strong>Type:</strong> ${cert.type}<br>
                                <strong>Offset:</strong> 0x${cert.offset.toString(16).toUpperCase().padStart(8, '0')}<br>
                                ${certDetails.commonName ? `<strong>Common Name (CN):</strong> ${escapeHtml(certDetails.commonName)}<br>` : ''}
                                ${certDetails.organization ? `<strong>Organization:</strong> ${escapeHtml(certDetails.organization)}<br>` : ''}
                                ${certDetails.country ? `<strong>Country:</strong> ${escapeHtml(certDetails.country)}<br>` : ''}
                                ${certDetails.keySize ? `<strong>Key Size:</strong> ${certDetails.keySize}<br>` : ''}
                                ${getKeyMatchDisplay(cert)}
                            </div>
                            <div class="col-md-6">
                                ${certDetails.issuerCN ? `<strong>Issued By:</strong> ${escapeHtml(certDetails.issuerCN)}<br>` : ''}
                                ${certDetails.validFrom ? `<strong>Valid From:</strong> ${certDetails.validFrom}<br>` : ''}
                                ${certDetails.validTo ? `<strong>Valid To:</strong> ${certDetails.validTo}<br>` : ''}
                                ${certDetails.serialNumber ? `<strong>Serial:</strong> ${certDetails.serialNumber.length > 30 ? certDetails.serialNumber.substring(0, 30) + '...' : certDetails.serialNumber}<br>` : ''}
                            </div>
                        </div>
                        ${certDetails.subject ? `
                        <div class="mt-2">
                            <strong>Full Subject:</strong><br>
                            <small class="text-muted">${escapeHtml(certDetails.subject)}</small>
                        </div>` : ''}
                        ${certDetails.issuer ? `
                        <div class="mt-1">
                            <strong>Full Issuer:</strong><br>
                            <small class="text-muted">${escapeHtml(certDetails.issuer)}</small>
                        </div>` : ''}
                    </div>
                </div>
            `;
        });
        
        certificatesSection.innerHTML = html;
    } else {
        certificatesSection.innerHTML = '<h6 class="mb-3">Certificates</h6><p class="text-muted">No certificates found</p>';
    }
}

function parseCertificateDetails(pemData) {
    // First try with node-forge if available
    if (typeof parseX509Certificate === 'function') {
        try {
            const forgeDetails = parseX509Certificate(pemData);
            if (forgeDetails && Object.keys(forgeDetails).length > 0) {
                return forgeDetails;
            }
        } catch (error) {
            console.warn('node-forge parsing failed, falling back to regex:', error);
        }
    }
    
    const details = {};
    
    try {
        if (pemData.includes('BEGIN CERTIFICATE')) {
            // Extract basic info from PEM data using more comprehensive regex
            const subjectMatch = pemData.match(/Subject:\s*([^\n\r]+)/);
            const issuerMatch = pemData.match(/Issuer:\s*([^\n\r]+)/);
            const validFromMatch = pemData.match(/Not Before:\s*([^\n\r]+)/);
            const validToMatch = pemData.match(/Not After:\s*([^\n\r]+)/);
            const serialMatch = pemData.match(/Serial Number:\s*([^\n\r]+)/);
            
            if (subjectMatch) {
                details.subject = subjectMatch[1].trim();
                // Extract CN from subject
                const cnMatch = details.subject.match(/CN\s*=\s*([^,\n\r]+)/i);
                if (cnMatch) {
                    details.commonName = cnMatch[1].trim();
                }
            }
            
            if (issuerMatch) {
                details.issuer = issuerMatch[1].trim();
                // Extract issuer CN
                const issuerCnMatch = details.issuer.match(/CN\s*=\s*([^,\n\r]+)/i);
                if (issuerCnMatch) {
                    details.issuerCN = issuerCnMatch[1].trim();
                }
            }
            
            if (validFromMatch) details.validFrom = validFromMatch[1].trim();
            if (validToMatch) details.validTo = validToMatch[1].trim();
            if (serialMatch) details.serialNumber = serialMatch[1].trim();
            
            // Try to determine key size
            if (pemData.includes('2048 bit') || pemData.includes('RSA-2048')) {
                details.keySize = '2048 bits';
            } else if (pemData.includes('4096 bit') || pemData.includes('RSA-4096')) {
                details.keySize = '4096 bits';
            } else if (pemData.includes('1024 bit') || pemData.includes('RSA-1024')) {
                details.keySize = '1024 bits';
            }
            
            // Try to extract more fields
            const organizationMatch = details.subject?.match(/O\s*=\s*([^,\n\r]+)/i);
            if (organizationMatch) {
                details.organization = organizationMatch[1].trim();
            }
            
            const countryMatch = details.subject?.match(/C\s*=\s*([^,\n\r]+)/i);
            if (countryMatch) {
                details.country = countryMatch[1].trim();
            }
            
        } else if (pemData.includes('BEGIN RSA PRIVATE KEY') || pemData.includes('BEGIN PRIVATE KEY')) {
            details.type = 'RSA Private Key';
            
            // Try to determine key size for private keys
            if (pemData.includes('2048 bit') || pemData.length > 1600) {
                details.keySize = '2048 bits';
            } else if (pemData.includes('4096 bit') || pemData.length > 3000) {
                details.keySize = '4096 bits';
            } else if (pemData.includes('1024 bit')) {
                details.keySize = '1024 bits';
            }
        }
    } catch (error) {
        console.warn('Error parsing certificate details:', error);
    }
    
    return details;
}

function downloadCertificate(index) {
    if (analysisResults && analysisResults.certificates && analysisResults.certificates[index]) {
        const cert = analysisResults.certificates[index];
        downloadFile(cert.decrypted, cert.filename, 'text/plain');
    }
}

function downloadAllCertificates() {
    if (!analysisResults || !analysisResults.certificates) return;
    
    // Create a zip-like structure by downloading each file
    analysisResults.certificates.forEach((cert, index) => {
        setTimeout(() => {
            downloadFile(cert.decrypted, cert.filename, 'text/plain');
        }, index * 500); // Stagger downloads by 500ms
    });
    
    // Also download AWS endpoints if available
    if (analysisResults.awsEndpoints && analysisResults.awsEndpoints.length > 0) {
        const endpointData = analysisResults.awsEndpoints.map(ep => ep.decoded).join('\n');
        setTimeout(() => {
            downloadFile(endpointData, 'aws_iot_endpoints.txt', 'text/plain');
        }, analysisResults.certificates.length * 500);
    }
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    
    URL.revokeObjectURL(url);
}

function showSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        section.classList.remove('d-none');
    }
}

function hideSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        section.classList.add('d-none');
    }
}

function showError(message) {
    const errorSection = document.getElementById('errorSection');
    const errorMessage = document.getElementById('errorMessage');
    
    errorMessage.textContent = message;
    showSection('errorSection');
}

function getKeyMatchDisplay(cert) {
    let html = '';
    
    // Key matching information
    if (cert.keyMatch) {
        if (cert.type === "Private Key") {
            if (cert.keyMatch.matched) {
                html += `<strong>Key Match:</strong> <span class="text-success">✓ Matches Certificate ${cert.keyMatch.certificateIndex}</span><br>`;
            } else if (cert.keyMatch.error) {
                html += `<strong>Key Match:</strong> <span class="text-warning">⚠ Verification Error</span><br>`;
            } else {
                html += `<strong>Key Match:</strong> <span class="text-danger">✗ No matching certificate found</span><br>`;
            }
        } else {
            // For certificates
            if (cert.keyMatch.matched) {
                html += `<strong>Private Key:</strong> <span class="text-success">✓ Matches Private Key ${cert.keyMatch.privateKeyIndex}</span><br>`;
            } else {
                html += `<strong>Private Key:</strong> <span class="text-muted">No matching private key</span><br>`;
            }
        }
    }
    
    // Certificate chain information
    if (cert.chainInfo && cert.type !== "Private Key") {
        if (cert.chainInfo.isRoot) {
            html += `<strong>Certificate Chain:</strong> <span class="text-primary">🏛️ Root Certificate (Self-signed)</span><br>`;
            if (cert.chainInfo.issuesOtherCerts) {
                html += `<strong>Issues:</strong> <span class="text-info">Other certificates in this set</span><br>`;
            }
        } else if (cert.chainInfo.issuedBy) {
            html += `<strong>Certificate Chain:</strong> <span class="text-success">📋 Issued by Certificate ${cert.chainInfo.issuedBy}</span><br>`;
        } else if (cert.chainInfo.issuerType === "External") {
            html += `<strong>Certificate Chain:</strong> <span class="text-warning">🌐 Issued by external CA</span><br>`;
        }
    }
    
    return html;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}