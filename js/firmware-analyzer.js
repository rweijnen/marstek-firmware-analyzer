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
                
                // Initial classification - will be refined by certificate chain analysis
                let certType = "Unknown";
                if (decryptedStr.includes("BEGIN CERTIFICATE")) {
                    certType = "Certificate"; // Generic - will be classified later
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
     * Verify if private keys match their corresponding certificates
     */
    verifyPrivateKeyMatches() {
        try {
            // Check if node-forge is available
            if (typeof forge === 'undefined') {
                console.warn('node-forge not available, skipping key verification');
                return;
            }

            const privateKeys = this.decryptedCerts.filter(cert => cert.type === "Private Key");
            const certificates = this.decryptedCerts.filter(cert => cert.type !== "Private Key");
            
            for (const privKey of privateKeys) {
                try {
                    // Parse the private key
                    const privateKeyPem = privKey.decrypted;
                    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
                    
                    // Find matching certificate by comparing public keys
                    for (const cert of certificates) {
                        try {
                            const certPem = cert.decrypted;
                            const certificate = forge.pki.certificateFromPem(certPem);
                            
                            // Compare the public key from certificate with private key
                            const publicKeyFromCert = certificate.publicKey;
                            
                            // Check if private key matches public key (compare modulus for RSA)
                            if (privateKey.n && publicKeyFromCert.n && 
                                privateKey.n.equals(publicKeyFromCert.n)) {
                                
                                // Mark both as matching
                                privKey.keyMatch = {
                                    matched: true,
                                    certificateIndex: cert.index,
                                    certificateType: cert.type
                                };
                                cert.keyMatch = {
                                    matched: true,
                                    privateKeyIndex: privKey.index
                                };
                                
                                console.log(`Private Key ${privKey.index} matches Certificate ${cert.index}`);
                            }
                        } catch (certError) {
                            console.warn(`Error parsing certificate ${cert.index}:`, certError);
                        }
                    }
                    
                    // If no match found, mark as unmatched
                    if (!privKey.keyMatch) {
                        privKey.keyMatch = {
                            matched: false,
                            certificateIndex: null,
                            certificateType: null
                        };
                    }
                    
                } catch (keyError) {
                    console.warn(`Error parsing private key ${privKey.index}:`, keyError);
                    privKey.keyMatch = {
                        matched: false,
                        error: keyError.message
                    };
                }
            }
        } catch (error) {
            console.warn('Error during private key verification:', error);
        }
    }

    /**
     * Analyze certificate chain and properly classify certificates
     */
    analyzeCertificateChain() {
        try {
            // Check if node-forge is available
            if (typeof forge === 'undefined') {
                console.warn('node-forge not available, using fallback classification');
                this.fallbackCertificateClassification();
                return;
            }

            const certificates = this.decryptedCerts.filter(cert => cert.type === "Certificate");
            
            for (const cert of certificates) {
                try {
                    const certificate = forge.pki.certificateFromPem(cert.decrypted);
                    
                    // Check if it's a root certificate
                    const isRootCertificate = this.isRootCertificate(certificate);
                    
                    if (isRootCertificate) {
                        cert.type = "Root CA Certificate";
                        cert.chainInfo = {
                            isRoot: true,
                            isSelfSigned: true,
                            issuesOtherCerts: false
                        };
                    } else {
                        // Check if it's issued by one of our root certificates
                        const issuer = this.findIssuer(certificate, certificates);
                        
                        if (issuer) {
                            // Mark the issuer as issuing other certificates
                            if (issuer.chainInfo) {
                                issuer.chainInfo.issuesOtherCerts = true;
                            }
                            
                            cert.type = "Device Certificate";
                            cert.chainInfo = {
                                isRoot: false,
                                isSelfSigned: false,
                                issuedBy: issuer.index,
                                issuerType: issuer.type
                            };
                        } else {
                            // No issuer found in our set
                            cert.type = "Device Certificate";
                            cert.chainInfo = {
                                isRoot: false,
                                isSelfSigned: false,
                                issuerType: "External"
                            };
                        }
                    }
                    
                } catch (error) {
                    console.warn(`Error analyzing certificate ${cert.index}:`, error);
                    // Fallback classification for this certificate
                    this.fallbackSingleCertificateClassification(cert);
                }
            }
            
        } catch (error) {
            console.warn('Error during certificate chain analysis:', error);
            this.fallbackCertificateClassification();
        }
    }

    /**
     * Check if a certificate is a root certificate
     */
    isRootCertificate(certificate) {
        try {
            // Check if subject equals issuer (self-signed)
            const subject = certificate.subject;
            const issuer = certificate.issuer;
            
            // Compare DN attributes
            if (subject.attributes.length !== issuer.attributes.length) {
                return false;
            }
            
            for (let i = 0; i < subject.attributes.length; i++) {
                const subjectAttr = subject.attributes[i];
                const issuerAttr = issuer.attributes[i];
                
                if (subjectAttr.type !== issuerAttr.type || 
                    subjectAttr.value !== issuerAttr.value) {
                    return false;
                }
            }
            
            // Check for CA basic constraints
            const basicConstraints = certificate.getExtension('basicConstraints');
            if (basicConstraints && basicConstraints.cA === true) {
                return true;
            }
            
            // Check for key usage extension indicating CA
            const keyUsage = certificate.getExtension('keyUsage');
            if (keyUsage && keyUsage.keyCertSign === true) {
                return true;
            }
            
            // Fallback: check if subject contains Root CA indicators
            const subjectCN = subject.getField('CN');
            if (subjectCN && (subjectCN.value.includes('Root CA') || 
                             subjectCN.value.includes('Root Certificate Authority'))) {
                return true;
            }
            
            return true; // If self-signed, likely a root
            
        } catch (error) {
            console.warn('Error checking if certificate is root:', error);
            return false;
        }
    }

    /**
     * Find the issuer certificate for a given certificate
     */
    findIssuer(certificate, certificates) {
        try {
            const issuerDN = certificate.issuer;
            
            for (const candidateCert of certificates) {
                try {
                    const candidateCertificate = forge.pki.certificateFromPem(candidateCert.decrypted);
                    const candidateSubject = candidateCertificate.subject;
                    
                    // Compare DN attributes
                    if (this.compareDNs(issuerDN, candidateSubject)) {
                        return candidateCert;
                    }
                } catch (error) {
                    continue;
                }
            }
            
            return null;
        } catch (error) {
            console.warn('Error finding issuer:', error);
            return null;
        }
    }

    /**
     * Compare two Distinguished Names
     */
    compareDNs(dn1, dn2) {
        if (dn1.attributes.length !== dn2.attributes.length) {
            return false;
        }
        
        for (let i = 0; i < dn1.attributes.length; i++) {
            const attr1 = dn1.attributes[i];
            const attr2 = dn2.attributes[i];
            
            if (attr1.type !== attr2.type || attr1.value !== attr2.value) {
                return false;
            }
        }
        
        return true;
    }

    /**
     * Fallback certificate classification using regex
     */
    fallbackCertificateClassification() {
        const certificates = this.decryptedCerts.filter(cert => cert.type === "Certificate");
        
        for (const cert of certificates) {
            this.fallbackSingleCertificateClassification(cert);
        }
    }

    /**
     * Fallback classification for a single certificate
     */
    fallbackSingleCertificateClassification(cert) {
        try {
            const decryptedStr = cert.decrypted;
            
            // Extract Subject and Issuer
            const subjectMatch = decryptedStr.match(/Subject:\s*([^\n\r]+)/);
            const issuerMatch = decryptedStr.match(/Issuer:\s*([^\n\r]+)/);
            
            if (subjectMatch && issuerMatch) {
                const subject = subjectMatch[1].trim();
                const issuer = issuerMatch[1].trim();
                
                // Check if self-signed and contains Root CA
                if (subject === issuer && (subject.includes("Root CA") || subject.includes("Amazon Root CA"))) {
                    cert.type = "Root CA Certificate";
                } else if (subject.includes("Root CA") || subject.includes("Amazon Root CA")) {
                    cert.type = "Root CA Certificate";
                } else {
                    cert.type = "Device Certificate";
                }
            } else {
                cert.type = "Device Certificate";
            }
        } catch (error) {
            cert.type = "Device Certificate";
        }
    }

    /**
     * Extract firmware version information using ARM Thumb-2 instruction analysis
     */
    extractFirmwareVersion(data) {
        try {
            // Initialize firmware info object
            const firmwareInfo = {
                type: "Unknown",
                version: null,
                buildDate: null,
                buildTime: null,
                checksum: null
            };
            
            // Determine firmware type
            const venusCPos = this.findInData(data, "VenusC");
            firmwareInfo.type = venusCPos !== -1 ? "EMS/Control" : "BMS";
            
            // Find SOFT_VERSION string
            const softVersionPos = this.findInData(data, "SOFT_VERSION");
            if (softVersionPos === -1) {
                console.warn("SOFT_VERSION string not found");
                return firmwareInfo;
            }
            
            // Extract version using ARM instruction patterns
            const version = this.findVersionPatterns(data, softVersionPos);
            firmwareInfo.version = version;
            
            // Extract build date and time
            const { date, time } = this.extractDateTimeNearVersion(data, softVersionPos);
            firmwareInfo.buildDate = date;
            firmwareInfo.buildTime = time;
            
            // Calculate checksum
            firmwareInfo.checksum = this.calculateFirmwareChecksum(data);
            
            return firmwareInfo;
            
        } catch (error) {
            console.warn("Error extracting firmware version:", error);
            return {
                type: "Unknown",
                version: null,
                buildDate: null,
                buildTime: null,
                checksum: null
            };
        }
    }
    
    /**
     * Find byte pattern in data
     */
    findInData(data, searchString) {
        const searchBytes = new TextEncoder().encode(searchString);
        
        for (let i = 0; i <= data.length - searchBytes.length; i++) {
            let found = true;
            for (let j = 0; j < searchBytes.length; j++) {
                if (data[i + j] !== searchBytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return -1;
    }
    
    /**
     * Decode ARM Thumb-2 MOV instructions
     */
    decodeThumb2MovtMovw(data, offset) {
        if (offset + 3 >= data.length) {
            return { register: null, immediate: null, type: null };
        }
        
        // Read as two 16-bit little-endian halfwords
        const word1 = data[offset] | (data[offset + 1] << 8);
        const word2 = data[offset + 2] | (data[offset + 3] << 8);
        
        // Check for MOV.W immediate (T2 encoding)
        if ((word1 & 0xFBEF) === 0xF04F) {
            const i = (word1 >> 10) & 1;
            const s = (word1 >> 4) & 1;
            const imm3 = (word2 >> 12) & 0x7;
            const rd = (word2 >> 8) & 0xF;
            const imm8 = word2 & 0xFF;
            
            // ThumbExpandImm(i:imm3:imm8)
            const imm12 = (i << 11) | (imm3 << 8) | imm8;
            
            let immediate;
            if ((imm12 & 0xC00) === 0) {
                // Simple cases
                if ((imm12 & 0x300) === 0x000) {
                    immediate = imm8;
                } else if ((imm12 & 0x300) === 0x100) {
                    immediate = (imm8 << 16) | imm8;
                } else if ((imm12 & 0x300) === 0x200) {
                    immediate = (imm8 << 24) | (imm8 << 8);
                } else { // 0x300
                    immediate = (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8;
                }
            } else {
                // Rotated form
                const unrotatedValue = 0x80 | (imm8 & 0x7F);
                const rotation = (imm12 >> 7) & 0x1F;
                immediate = ((unrotatedValue >>> rotation) | (unrotatedValue << (32 - rotation))) >>> 0;
            }
            
            return { register: rd, immediate: immediate, type: 'MOV.W' };
        }
        
        // Check for MOVW (T3 encoding)
        if ((word1 & 0xFB50) === 0xF040) {
            const i = (word1 >> 10) & 1;
            const imm4 = word1 & 0xF;
            const imm3 = (word2 >> 12) & 0x7;
            const rd = (word2 >> 8) & 0xF;
            const imm8 = word2 & 0xFF;
            
            const immediate = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8;
            return { register: rd, immediate: immediate, type: 'MOVW' };
        }
        
        return { register: null, immediate: null, type: null };
    }
    
    /**
     * Find version patterns using ARM instruction analysis
     */
    findVersionPatterns(data, softVersionPos) {
        const searchStart = Math.max(0, softVersionPos - 0x1000);
        const searchEnd = softVersionPos;
        
        // Pattern 1: PUSH {R4,LR} + MOV.W/MOVW R1 + ADR R0
        for (let offset = searchStart; offset < searchEnd - 8; offset++) {
            if (data[offset] === 0x10 && data[offset + 1] === 0xB5) { // PUSH {R4,LR}
                const movResult = this.decodeThumb2MovtMovw(data, offset + 2);
                
                if (movResult.register === 1 && movResult.immediate !== null) { // R1
                    if (offset + 7 < data.length && data[offset + 7] === 0xA0) {
                        const adrReg = (data[offset + 7] >> 0) & 0x7;
                        
                        if (adrReg === 0) { // R0
                            const adrImm = data[offset + 6] & 0xFF;
                            const adrPc = ((offset + 6 + 4) & ~3);
                            
                            // Try different base addresses
                            for (const base of [0x08000000, 0x08020000, 0]) {
                                const runtimePc = base + adrPc;
                                const target = runtimePc + (adrImm * 4);
                                const fileOffset = target - base;
                                
                                if (Math.abs(fileOffset - softVersionPos) < 50) {
                                    return movResult.immediate;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Pattern 2: Just MOV.W/MOVW R1 + ADR R0 (no PUSH)
        for (let offset = searchStart; offset < searchEnd - 6; offset++) {
            const movResult = this.decodeThumb2MovtMovw(data, offset);
            
            if (movResult.register === 1 && movResult.immediate !== null) {
                if (offset + 5 < data.length && data[offset + 5] === 0xA0) {
                    const adrReg = (data[offset + 5] >> 0) & 0x7;
                    
                    if (adrReg === 0) {
                        const adrImm = data[offset + 4] & 0xFF;
                        const adrPc = ((offset + 4 + 4) & ~3);
                        
                        for (const base of [0x08000000, 0x08020000, 0]) {
                            const runtimePc = base + adrPc;
                            const target = runtimePc + (adrImm * 4);
                            const fileOffset = target - base;
                            
                            if (Math.abs(fileOffset - softVersionPos) < 50) {
                                return movResult.immediate;
                            }
                        }
                    }
                }
            }
        }
        
        // Pattern 3: MOVS R1 + ADR R0 (8-bit immediate)
        for (let offset = searchStart; offset < searchEnd - 4; offset++) {
            if (offset + 1 < data.length && data[offset + 1] === 0x21) {
                const immediate = data[offset];
                
                if (data[offset + 3] === 0xA0) {
                    const adrImm = data[offset + 2];
                    const adrPc = ((offset + 2 + 4) & ~3);
                    
                    for (const base of [0x08000000, 0x08020000, 0]) {
                        const runtimePc = base + adrPc;
                        const target = runtimePc + (adrImm * 4);
                        const fileOffset = target - base;
                        
                        if (Math.abs(fileOffset - softVersionPos) < 50) {
                            return immediate;
                        }
                    }
                }
            }
        }
        
        return null;
    }
    
    /**
     * Extract date and time strings near version
     */
    extractDateTimeNearVersion(data, versionOffset) {
        const searchStart = versionOffset;
        const searchEnd = Math.min(versionOffset + 200, data.length);
        
        // Look for " time:" string
        const timeMarker = new TextEncoder().encode(" time:");
        let timePos = -1;
        
        for (let i = searchStart; i <= searchEnd - timeMarker.length; i++) {
            let found = true;
            for (let j = 0; j < timeMarker.length; j++) {
                if (data[i + j] !== timeMarker[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                timePos = i;
                break;
            }
        }
        
        if (timePos === -1) {
            return { date: null, time: null };
        }
        
        // Look for month names
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                       'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        
        let dateStr = null;
        let timeStr = null;
        
        for (const month of months) {
            const monthBytes = new TextEncoder().encode(month);
            let monthPos = -1;
            
            for (let i = timePos; i <= timePos + 50 - monthBytes.length; i++) {
                let found = true;
                for (let j = 0; j < monthBytes.length; j++) {
                    if (data[i + j] !== monthBytes[j]) {
                        found = false;
                        break;
                    }
                }
                if (found) {
                    monthPos = i;
                    break;
                }
            }
            
            if (monthPos !== -1) {
                // Extract date string
                let dateEnd = monthPos;
                while (dateEnd < data.length && dateEnd < monthPos + 20 && data[dateEnd] !== 0) {
                    dateEnd++;
                }
                
                try {
                    const dateBytes = data.slice(monthPos, dateEnd);
                    dateStr = new TextDecoder('ascii').decode(dateBytes);
                } catch (e) {
                    // Ignore decode errors
                }
                
                // Look for time string (HH:MM:SS pattern)
                const timeSearch = data.slice(dateEnd, dateEnd + 20);
                const timePattern = /\d{1,2}:\d{2}:\d{2}/;
                const timeSearchStr = new TextDecoder('ascii', { fatal: false }).decode(timeSearch);
                const timeMatch = timeSearchStr.match(timePattern);
                
                if (timeMatch) {
                    timeStr = timeMatch[0];
                }
                
                break;
            }
        }
        
        return { date: dateStr, time: timeStr };
    }
    
    /**
     * Calculate firmware checksum
     */
    calculateFirmwareChecksum(data) {
        let sum = 0;
        for (let i = 0; i < data.length; i++) {
            sum = (sum + data[i]) >>> 0; // Keep as 32-bit unsigned
        }
        const checksum = (~sum) >>> 0; // Bitwise NOT and keep as 32-bit unsigned
        return `0x${checksum.toString(16).toUpperCase().padStart(8, '0')}`;
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
            
            // Step 7: Verify private key matches certificates
            progressCallback(98, "Verifying private key matches...");
            this.verifyPrivateKeyMatches();
            
            // Step 8: Analyze certificate chain
            progressCallback(99, "Analyzing certificate chain...");
            this.analyzeCertificateChain();
            
            // Step 9: Extract firmware version information
            progressCallback(99.5, "Extracting firmware version...");
            this.firmwareInfo = this.extractFirmwareVersion(new Uint8Array(fileData));
            
            progressCallback(100, "Analysis complete!");
            
            return {
                certificates: this.decryptedCerts,
                awsEndpoints: this.awsEndpoints,
                firmwareInfo: this.firmwareInfo,
                summary: {
                    certificatesFound: this.decryptedCerts.length,
                    awsEndpointsFound: this.awsEndpoints.length,
                    firmwareVersion: this.firmwareInfo.version,
                    firmwareType: this.firmwareInfo.type
                }
            };
            
        } catch (error) {
            throw new Error(`Analysis failed: ${error.message}`);
        }
    }
}