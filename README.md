# Marstek Firmware Analyzer

A web-based tool for analyzing Marstek firmware files to extract certificates and security information.

## Features

- **Client-side Analysis**: All processing happens in your browser - no data is uploaded to servers
- **Certificate Extraction**: Automatically finds and decrypts embedded certificates
- **AWS IoT Discovery**: Locates AWS IoT endpoints and connection information  
- **Secure Processing**: Uses modern Web Crypto API for decryption
- **Easy Downloads**: Download individual certificates or all files at once

## Usage

1. Visit the [Marstek Firmware Analyzer](https://rweijnen.github.io/marstek-firmware-analyzer/)
2. Upload your Marstek firmware `.bin` file
3. Click "Analyze Firmware" and wait for processing to complete
4. Download the extracted certificates and endpoints

## Supported Firmware

This tool is designed for Marstek energy storage system firmware files. It automatically:

- Extracts string data from binary firmware
- Discovers encrypted certificate storage
- Decrypts AES-encrypted certificates and keys
- Identifies AWS IoT connection endpoints

## Security & Privacy

- **No server uploads**: All analysis is performed locally in your browser
- **No data retention**: Files and results are not stored anywhere
- **Open source**: Full source code available for review

## Browser Compatibility

Requires a modern browser with support for:
- Web Crypto API
- File API
- ES6 JavaScript features

Tested on:
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Development

To run locally:

1. Clone the repository
2. Serve the files using any local web server
3. Open `index.html` in your browser

Example using Python:
```bash
python -m http.server 8000
```

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is for security research and analysis purposes. Only analyze firmware files that you own or have permission to analyze.