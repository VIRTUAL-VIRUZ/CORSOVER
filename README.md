# CORSOVER

```
╔═════════════════════════════════════════════════════════════════════╗
║                                                                     ║
║  ██████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██╗   ██╗███████╗██████╗  ║
║ ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗ ║
║ ██║     ██║   ██║██████╔╝███████╗██║   ██║██║   ██║█████╗  ██████╔╝ ║
║ ██║     ██║   ██║██╔══██╗╚════██║██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗ ║
║ ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝ ╚████╔╝ ███████╗██║  ██║ ║
║  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ║
║                                                                     ║
║                 Advanced CORS Vulnerability Scanner                 ║
║                    Professional Security Tool                       ║
║                                                                     ║
╚═════════════════════════════════════════════════════════════════════╝
```

**CORSOVER** is a production-grade Cross-Origin Resource Sharing (CORS) vulnerability scanner designed for bug bounty hunters and security professionals. It provides comprehensive CORS misconfiguration detection with zero false positives through intelligent request/response analysis.

## 🚀 Features

- **Advanced Subdomain Enumeration**: Leverages crt.sh and subfinder for comprehensive subdomain discovery
- **Intelligent Live Domain Filtering**: Efficiently identifies active domains and endpoints  
- **Smart Endpoint Discovery**: Crawls common API and web endpoints automatically
- **Zero False Positives**: Advanced analysis engine eliminates false positive results
- **Comprehensive Vulnerability Detection**: Detects all major CORS misconfiguration types
- **Professional Reporting**: Generates detailed JSON reports with PoC examples
- **High-Performance Scanning**: Asynchronous architecture with configurable concurrency
- **Rich Terminal Interface**: Beautiful progress bars and real-time vulnerability display

## 🎯 Vulnerability Detection

CORSOVER detects the following CORS misconfigurations:

### High Severity
- **Wildcard Origin with Credentials**: `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- **Null Origin Reflection with Credentials**: Server reflects `null` origin with credentials enabled
- **Arbitrary Origin Reflection with Credentials**: Server reflects attacker-controlled origins with credentials

### Medium Severity  
- **Subdomain Wildcard with Credentials**: Subdomain wildcards with credentials enabled
- **HTTP Origin Accepted**: HTTPS sites accepting HTTP origins (MITM vulnerability)

### Low Severity
- **Weak CORS Configuration**: CORS enabled without proper restrictions

## 📋 Requirements

### Python Dependencies
```bash
pip install aiohttp rich asyncio pathlib
```

### External Tools (Optional)
- **subfinder**: Enhanced subdomain enumeration
  ```bash
  # Install subfinder for better results
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ```

## 🔧 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/virtual-viruz/corsover.git
   cd corsover
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install external tools** (optional but recommended):
   ```bash
   # Install subfinder
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   ```

4. **Make executable**:
   ```bash
   chmod +x corsover.py
   ```

## 🚀 Usage

### Basic Usage
```bash
python corsover.py -d example.com
```

### Advanced Usage
```bash
# Scan with custom concurrency
python corsover.py -d example.com -c 100

# Full parameter specification
python corsover.py --domain example.com --max-concurrent 75
```

### Command Line Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-d, --domain` | Target domain to scan (required) | - |
| `-c, --max-concurrent` | Maximum concurrent requests | 50 |

## 📊 Scanning Process

CORSOVER follows a systematic 5-phase approach:

1. **Phase 1: Subdomain Enumeration**
   - Queries crt.sh certificate transparency logs
   - Runs subfinder for additional subdomain discovery
   - Includes common subdomain patterns

2. **Phase 2: Live Domain Filtering**
   - Tests HTTP/HTTPS connectivity for all discovered subdomains
   - Filters out non-responsive domains
   - Optimizes scanning scope

3. **Phase 3: Endpoint Discovery**
   - Crawls common API endpoints and paths
   - Extracts URLs from HTML content
   - Builds comprehensive target list

4. **Phase 4: CORS Vulnerability Scanning**
   - Tests 25+ different origin payloads
   - Analyzes CORS headers with precision
   - Real-time vulnerability detection and display

5. **Phase 5: Report Generation**
   - Creates detailed JSON reports
   - Provides exploit proof-of-concepts
   - Generates summary statistics

## 📖 Example Output

```
🎯 Target Domain: example.com
🚀 Max Concurrent: 50

Phase 1: Subdomain Enumeration
✅ Found 147 subdomains

Phase 2: Live Domain Filtering  
✅ Found 23 live domains

Phase 3: Endpoint Discovery
✅ Discovered 89 URLs to test

Phase 4: CORS Vulnerability Scanning
🚨 CORS Vulnerability Found
┌─────────────────────────────────────────────────┐
│ URL: https://api.example.com/v1/users           │
│ Vulnerability: Arbitrary Origin Reflection      │  
│ Severity: High                                  │
│                                                 │
│ Details:                                        │
│ • Origin Sent: https://evil.com                 │
│ • ACAO Response: https://evil.com               │
│ • Credentials: true                             │
│                                                 │
│ Proof of Concept:                               │
│ fetch("https://api.example.com/v1/users", {     │
│   credentials: "include",                       │
│   mode: "cors"                                  │
│ })                                              │
└─────────────────────────────────────────────────┘

🎉 Scan completed in 45.32 seconds
```

## 📄 Report Format

CORSOVER generates detailed JSON reports containing:

```json
{
  "scan_info": {
    "target_domain": "example.com",
    "timestamp": "2024-01-15 14:30:22",
    "total_urls_tested": 89,
    "total_vulnerabilities": 3
  },
  "summary": {
    "high_severity": 2,
    "medium_severity": 1,
    "low_severity": 0
  },
  "vulnerabilities": [
    {
      "url": "https://api.example.com/v1/users",
      "vulnerability_type": "Arbitrary Origin Reflection with Credentials",
      "severity": "High",
      "origin_sent": "https://evil.com",
      "access_control_allow_origin": "https://evil.com",
      "access_control_allow_credentials": "true",
      "description": "Server reflects arbitrary origin with credentials enabled",
      "poc": "fetch(\"https://api.example.com/v1/users\", {credentials: \"include\", mode: \"cors\"})",
      "response_headers": {...},
      "timestamp": "2024-01-15 14:30:45"
    }
  ]
}
```

## ⚡ Performance Optimization

- **Concurrent Processing**: Adjustable concurrency levels (default: 50)
- **Intelligent Filtering**: Skips 404 responses and invalid endpoints
- **Memory Efficient**: Streams processing for large domain sets
- **Timeout Management**: Configurable timeouts prevent hanging requests
- **Resource Limiting**: Connection pooling and rate limiting

## 🛡️ Security Considerations

- **Ethical Use Only**: Use only on domains you own or have explicit permission to test
- **Rate Limiting**: Built-in concurrency controls to avoid overwhelming targets
- **Stealth Mode**: Realistic User-Agent headers and request patterns
- **No Exploitation**: Tool only identifies vulnerabilities, does not exploit them

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-feature`
3. **Commit changes**: `git commit -am 'Add new feature'`
4. **Push to branch**: `git push origin feature/new-feature`  
5. **Submit Pull Request**

### Areas for Contribution
- Additional vulnerability detection patterns
- New subdomain enumeration sources
- Performance optimizations
- Output format enhancements
- Integration with other security tools

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**CORSOVER is intended for authorized security testing only.** Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse of this tool.

- Only test domains you own or have explicit written permission to test
- Respect rate limits and avoid overwhelming target systems
- Follow responsible disclosure practices for any vulnerabilities found
- Comply with all applicable local and international laws

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/virtual-viruz/corsover/issues)
- **Discussions**: [GitHub Discussions](https://github.com/virtual-viruz/corsover/discussions)  
- **Security**: For security-related issues, please create a security advisory on GitHub

## 🏆 Acknowledgments

- Certificate Transparency logs (crt.sh)
- ProjectDiscovery team for subfinder
- Bug bounty community for testing and feedback
- Security researchers who identified CORS attack vectors

---

**Made with ❤️ for the bug bounty and security testing community**
