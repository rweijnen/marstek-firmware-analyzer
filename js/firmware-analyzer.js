/**
 * Marstek Firmware Analyzer - Main Analysis Logic
 */

class FirmwareAnalyzer {
    constructor() {
        this.strings = [];
        this.certificates = [];
        this.keyCandidates = [];
        this.workingKey = null;
        this.decryptedCerts = [];
        this.awsEndpoints = [];
    }

    /**
     * Apply Caesar shift within printable ASCII range (32-126)
     */
    caesarShift(text, shift) {
        let result = '';
        for (let char of text) {
            const asciiVal = char.charCodeAt(0);
            if (asciiVal >= 32 && asciiVal <= 126) {
                // Apply shift within printable range with modular arithmetic
                const shiftedVal = ((asciiVal - 32 + shift) % 95) + 32;
                result += String.fromCharCode(shiftedVal);
            } else {
                result += char;
            }
        }
        return result;
    }

    /**
     * Extract ASCII strings from binary data
     */
    extractStrings(data, minLength = 4) {
        const strings = [];
        let currentString = [];
        let startOffset = 0;

        for (let i = 0; i < data.length; i++) {
            const byte = data[i];
            // Check if byte is printable ASCII (0x20-0x7E)
            if (byte >= 0x20 && byte <= 0x7E) {
                if (currentString.length === 0) {
                    startOffset = i;
                }
                currentString.push(String.fromCharCode(byte));
            } else {
                if (currentString.length >= minLength) {
                    const string = currentString.join('');
                    strings.push({ offset: startOffset, string: string });
                }
                currentString = [];
            }
        }

        // Don't forget the last string
        if (currentString.length >= minLength) {
            const string = currentString.join('');
            strings.push({ offset: startOffset, string: string });
        }

        return strings;
    }

    /**
     * Find Base64 encoded certificates
     */
    findCertificates(strings) {
        const certificates = [];
        const base64Regex = /^[A-Za-z0-9+/]{400,}={0,2}$/;
        
        for (const item of strings) {
            if (base64Regex.test(item.string)) {
                certificates.push({
                    offset: item.offset,
                    data: item.string,
                    length: item.string.length
                });
            }
        }
        
        return certificates;
    }

    /**
     * Generate potential AES key candidates
     */
    generateKeyCandidates(strings) {
        const candidates = new Set(); // Use Set to avoid duplicates
        
        for (const item of strings) {
            const string = item.string;
            const len = string.length;
            
            // Exact 16-byte strings
            if (len === 16) {
                candidates.add(string);
            }
            // Strings that can be repeated to make 16 bytes
            else if (len === 8) { // repeat 2x
                candidates.add(string + string);
            } else if (len === 4) { // repeat 4x
                candidates.add(string.repeat(4));
            } else if (len === 2) { // repeat 8x
                candidates.add(string.repeat(8));
            } else if (len === 1) { // repeat 16x
                candidates.add(string.repeat(16));
            }
        }
        
        return Array.from(candidates);
    }

    /**
     * Try to decrypt Base64 data with given AES key using ECB mode
     */
    decryptWithKey(encryptedBase64, keyBytes) {
        try {
            // Check if CryptoJS is available
            if (typeof CryptoJS === 'undefined') {
                console.error('CryptoJS library not loaded');
                return null;
            }
            
            // Add padding to base64 if needed
            const paddedBase64 = encryptedBase64 + '='.repeat((4 - encryptedBase64.length % 4) % 4);
            
            // Convert key bytes to CryptoJS format
            const keyHex = Array.from(keyBytes, byte => byte.toString(16).padStart(2, '0')).join('');
            const key = CryptoJS.enc.Hex.parse(keyHex);
            
            // Parse the Base64 ciphertext
            const ciphertext = CryptoJS.enc.Base64.parse(paddedBase64);
            
            // Decrypt using AES-ECB
            const decrypted = CryptoJS.AES.decrypt(
                { ciphertext: ciphertext }, 
                key, 
                { 
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.NoPadding
                }
            );
            
            // Convert to Uint8Array
            const decryptedHex = decrypted.toString(CryptoJS.enc.Hex);
            if (!decryptedHex) return null;
            
            const result = new Uint8Array(decryptedHex.length / 2);
            for (let i = 0; i < decryptedHex.length; i += 2) {
                result[i / 2] = parseInt(decryptedHex.substr(i, 2), 16);
            }
            
            return result;
        } catch (error) {
            console.warn('Decryption error:', error);
            return null;
        }
    }

    /**
     * Brute force the AES key (now async to allow UI updates)
     */
    async bruteForceKey(certificateData, progressCallback) {
        const totalCombinations = this.keyCandidates.length * 94;
        let testCount = 0;
        
        progressCallback(10, `Testing ${this.keyCandidates.length} key candidates...`);
        
        for (let i = 0; i < this.keyCandidates.length; i++) {
            const candidate = this.keyCandidates[i];
            
            // Update progress and yield control every 50 candidates
            if (i % 50 === 0) {
                const progress = 10 + (i / this.keyCandidates.length) * 70;
                progressCallback(progress, `Progress: ${i}/${this.keyCandidates.length} candidates...`);
                // Yield control to UI thread
                await new Promise(resolve => setTimeout(resolve, 0));
            }
            
            // Test shifts from -47 to +47 (covers full printable range)
            for (let shift = -47; shift <= 47; shift++) {
                if (shift === 0) continue;
                
                testCount++;
                
                // Apply Caesar shift to candidate
                const shiftedKey = this.caesarShift(candidate, shift);
                const keyBytes = new Uint8Array(16);
                
                // Convert string to bytes, pad/truncate to 16 bytes
                for (let j = 0; j < 16; j++) {
                    if (j < shiftedKey.length) {
                        keyBytes[j] = shiftedKey.charCodeAt(j);
                    } else {
                        keyBytes[j] = 0;
                    }
                }
                
                // Try to decrypt
                const decrypted = this.decryptWithKey(certificateData, keyBytes);
                if (decrypted) {
                    // Check if it contains certificate markers
                    const decryptedStr = new TextDecoder('utf-8', { fatal: false }).decode(decrypted);
                    const markers = [
                        'BEGIN CERTIFICATE', 'BEGIN RSA PRIVATE KEY', 'BEGIN PRIVATE KEY',
                        'Certificate:', 'Private-Key:', 'RSA Private-Key'
                    ];
                    
                    if (markers.some(marker => decryptedStr.includes(marker))) {
                        progressCallback(80, `SUCCESS! Found working key after ${testCount} attempts`);
                        return { key: shiftedKey, shift: shift };
                    }
                }
                
                // Yield control periodically during shift testing
                if (testCount % 1000 === 0) {
                    await new Promise(resolve => setTimeout(resolve, 0));
                }
            }
        }
        
        return null;
    }

    /**
     * Decrypt all certificates with the found key
     */
    decryptAllCertificates(key, progressCallback) {
        const results = [];
        const keyBytes = new Uint8Array(16);
        
        // Convert key to bytes
        for (let i = 0; i < 16; i++) {
            if (i < key.length) {
                keyBytes[i] = key.charCodeAt(i);
            } else {
                keyBytes[i] = 0;
            }
        }
        
        for (let i = 0; i < this.certificates.length; i++) {
            progressCallback(85 + (i / this.certificates.length) * 10, 
                           `Decrypting certificate ${i + 1}/${this.certificates.length}...`);
            
            const cert = this.certificates[i];
            const decrypted = this.decryptWithKey(cert.data, keyBytes);
            
            if (decrypted) {
                const decryptedStr = new TextDecoder('utf-8', { fatal: false }).decode(decrypted);
                
                // Classify certificate type
                let certType = "Unknown";
                if (decryptedStr.includes("BEGIN CERTIFICATE")) {
                    // Extract Subject and Issuer for proper classification
                    const subjectMatch = decryptedStr.match(/Subject:\s*([^\n\r]+)/);
                    const issuerMatch = decryptedStr.match(/Issuer:\s*([^\n\r]+)/);
                    
                    if (subjectMatch && issuerMatch) {
                        const subject = subjectMatch[1].trim();
                        const issuer = issuerMatch[1].trim();
                        
                        // Check if it's a Root CA (self-signed: Subject = Issuer)
                        if (subject === issuer && (subject.includes("Root CA") || subject.includes("Amazon Root CA"))) {
                            certType = "Root CA Certificate";
                        }
                        // Check if it's an Amazon Root CA even if not self-signed
                        else if (subject.includes("Amazon Root CA") || subject.includes("Root CA")) {
                            certType = "Root CA Certificate"; 
                        }
                        // Check for device certificates
                        else if (subject.includes("amazonaws.com") || subject.includes("iot.")) {
                            certType = "Device Certificate";
                        }
                        // Default to device certificate for other certs
                        else {
                            certType = "Device Certificate";
                        }
                    } else {
                        // Fallback to simple string matching if regex fails
                        if (decryptedStr.includes("Amazon Root CA") || decryptedStr.includes("Root CA")) {
                            certType = "Root CA Certificate";
                        } else {
                            certType = "Device Certificate";
                        }
                    }
                } else if (decryptedStr.includes("BEGIN RSA PRIVATE KEY") || decryptedStr.includes("BEGIN PRIVATE KEY")) {
                    certType = "Private Key";
                }
                
                results.push({
                    index: i + 1,
                    type: certType,
                    offset: cert.offset,
                    decrypted: decryptedStr,
                    filename: this.getFilename(certType, i + 1)
                });
            }
        }
        
        return results;
    }

    /**
     * Find AWS IoT endpoints
     */
    findAwsEndpoints(strings) {
        const endpoints = [];
        
        // Find strings that could be AWS endpoints (minimum 20 chars)
        const candidates = strings.filter(item => item.string.length >= 20);
        
        for (const candidate of candidates) {
            // Test Caesar shifts from -47 to +47
            for (let shift = -47; shift <= 47; shift++) {
                if (shift === 0) continue;
                
                const shifted = this.caesarShift(candidate.string, shift);
                const shiftedLower = shifted.toLowerCase();
                
                // Look for AWS patterns
                if (shiftedLower.includes('amazonaws.com') || 
                    (shiftedLower.includes('amazonaws') && shiftedLower.includes('.com')) ||
                    (shiftedLower.includes('iot.') && shiftedLower.includes('.amazonaws.')) ||
                    shiftedLower.includes('a40nr6osvmmaw')) {
                    
                    endpoints.push({
                        offset: candidate.offset,
                        original: candidate.string,
                        shift: shift,
                        decoded: shifted
                    });
                }
            }
        }
        
        return endpoints;
    }

    /**
     * Get appropriate filename for certificate type
     */
    getFilename(certType, index) {
        if (certType.includes("Private Key")) {
            return `private_key_${index}.pem`;
        } else if (certType.includes("Root CA")) {
            return `root_ca_${index}.pem`;
        } else {
            return `certificate_${index}.pem`;
        }
    }

    /**
     * Main analysis function
     */
    async analyze(fileData, progressCallback) {
        try {
            // Step 1: Extract strings
            progressCallback(5, "Extracting strings...");
            this.strings = this.extractStrings(new Uint8Array(fileData));
            
            // Step 2: Find certificates
            progressCallback(8, "Finding certificates...");
            this.certificates = this.findCertificates(this.strings);
            
            if (this.certificates.length === 0) {
                throw new Error("No Base64 certificate candidates found in firmware");
            }
            
            // Step 3: Generate key candidates
            progressCallback(10, "Generating key candidates...");
            this.keyCandidates = this.generateKeyCandidates(this.strings);
            
            // Step 4: Brute force key
            const keyResult = await this.bruteForceKey(this.certificates[0].data, progressCallback);
            if (!keyResult) {
                throw new Error("Could not find working AES key");
            }
            this.workingKey = keyResult.key;
            
            // Step 5: Decrypt all certificates
            this.decryptedCerts = this.decryptAllCertificates(this.workingKey, progressCallback);
            
            // Step 6: Find AWS endpoints
            progressCallback(95, "Finding AWS IoT endpoints...");
            this.awsEndpoints = this.findAwsEndpoints(this.strings);
            
            progressCallback(100, "Analysis complete!");
            
            return {
                certificates: this.decryptedCerts,
                awsEndpoints: this.awsEndpoints,
                summary: {
                    certificatesFound: this.decryptedCerts.length,
                    awsEndpointsFound: this.awsEndpoints.length
                }
            };
            
        } catch (error) {
            throw new Error(`Analysis failed: ${error.message}`);
        }
    }
}