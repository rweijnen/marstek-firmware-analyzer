/**
 * Certificate Parser for Marstek Firmware Analyzer
 * 
 * Note: Advanced certificate parsing using node-forge could be added here.
 * For now, we use basic regex parsing in the UI handler.
 */

/**
 * Parse X.509 certificate using node-forge (if available)
 */
function parseX509Certificate(pemData) {
    // Check if node-forge is available
    if (typeof forge === 'undefined') {
        console.warn('node-forge not available, using basic parsing');
        return parseBasicCertificate(pemData);
    }
    
    try {
        // Remove any extra whitespace and normalize line endings
        const cleanPem = pemData.trim().replace(/\r\n/g, '\n');
        
        if (cleanPem.includes('BEGIN CERTIFICATE')) {
            const cert = forge.pki.certificateFromPem(cleanPem);
            
            // Calculate thumbprint (SHA-1 hash of the certificate)
            let thumbprint = null;
            try {
                const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
                const sha1 = forge.md.sha1.create();
                sha1.update(certDer.getBytes());
                thumbprint = sha1.digest().toHex().toUpperCase().replace(/(.{2})/g, '$1:').slice(0, -1);
            } catch (e) {
                console.warn('Error calculating thumbprint:', e);
            }
            
            return {
                subject: cert.subject.attributes.map(attr => `${attr.shortName}=${attr.value}`).join(', '),
                issuer: cert.issuer.attributes.map(attr => `${attr.shortName}=${attr.value}`).join(', '),
                serialNumber: cert.serialNumber,
                validFrom: cert.validity.notBefore.toISOString().split('T')[0],
                validTo: cert.validity.notAfter.toISOString().split('T')[0],
                keySize: cert.publicKey.n ? cert.publicKey.n.bitLength() + ' bits' : 'Unknown',
                signatureAlgorithm: cert.siginfo ? cert.siginfo.algorithmOid : 'Unknown',
                thumbprint: thumbprint,
                extensions: cert.extensions.map(ext => ({
                    name: ext.name || ext.id,
                    critical: ext.critical
                }))
            };
        } else if (cleanPem.includes('BEGIN RSA PRIVATE KEY') || cleanPem.includes('BEGIN PRIVATE KEY')) {
            try {
                const privateKey = forge.pki.privateKeyFromPem(cleanPem);
                return {
                    type: 'RSA Private Key',
                    keySize: privateKey.n ? privateKey.n.bitLength() + ' bits' : 'Unknown'
                };
            } catch (e) {
                return {
                    type: 'Private Key',
                    error: 'Could not parse private key details'
                };
            }
        }
    } catch (error) {
        console.warn('Error parsing certificate with forge:', error);
        return parseBasicCertificate(pemData);
    }
    
    return {};
}

/**
 * Basic certificate parsing using regex (fallback)
 */
function parseBasicCertificate(pemData) {
    const details = {};
    
    try {
        if (pemData.includes('BEGIN CERTIFICATE')) {
            // Look for common certificate fields
            const lines = pemData.split('\n');
            
            for (const line of lines) {
                const trimmed = line.trim();
                
                if (trimmed.startsWith('Subject:')) {
                    details.subject = trimmed.substring(8).trim();
                } else if (trimmed.startsWith('Issuer:')) {
                    details.issuer = trimmed.substring(7).trim();
                } else if (trimmed.includes('Not Before:')) {
                    const match = trimmed.match(/Not Before:\s*(.+)/);
                    if (match) details.validFrom = match[1];
                } else if (trimmed.includes('Not After:')) {
                    const match = trimmed.match(/Not After:\s*(.+)/);
                    if (match) details.validTo = match[1];
                } else if (trimmed.includes('Serial Number:')) {
                    const match = trimmed.match(/Serial Number:\s*(.+)/);
                    if (match) details.serialNumber = match[1];
                }
            }
            
            // Try to determine key size
            if (pemData.includes('2048 bit')) {
                details.keySize = '2048 bits';
            } else if (pemData.includes('4096 bit')) {
                details.keySize = '4096 bits';
            } else if (pemData.includes('1024 bit')) {
                details.keySize = '1024 bits';
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
        console.warn('Error in basic certificate parsing:', error);
        details.error = error.message;
    }
    
    return details;
}