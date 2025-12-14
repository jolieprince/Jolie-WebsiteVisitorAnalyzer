# Jolie-WebsiteVisitorAnalyzer
Analyze the quality of the visitor with Deep Fingerprint Inspection

# Visitor Traffic Quality Analyzer

A comprehensive Flask-based web application that analyzes visitor authenticity and detects bots, proxies, VPNs, and manipulated browser fingerprints in real-time.

## Features

### 🎯 Comprehensive Visitor Analysis

- **Real-time Analysis**: Instant visitor quality assessment
- **Beautiful Dark UI**: Modern Bootstrap 5 dark theme interface
- **Comprehensive Checks**: 22 analysis modules (8 basic + 14 advanced)
- **50+ Basic Signals**: Traditional fingerprinting techniques
- **14 Advanced Techniques**: Mouse dynamics, keyboard biometrics, VM detection
- **Risk Scoring**: Automatic risk calculation with confidence levels
- **Color-Coded Results**: Red for risky, green for genuine parameters

### 🔍 Detection Capabilities

#### **Basic Fingerprinting (50+ signals)**

#### 1. **Browser Fingerprinting**
- Canvas fingerprinting
- WebGL fingerprinting
- Audio fingerprinting
- Font detection (14 common fonts)
- Plugin enumeration
- Screen & device information
- Hardware concurrency
- Device memory
- Battery information
- Connection information
- Media devices enumeration
- Timezone detection

#### 2. **Proxy & VPN Detection**
- Proxy header analysis
- X-Forwarded-For chain detection
- WebRTC IP leak detection
- Datacenter IP detection
- VPN service identification
- Tor exit node detection

#### 3. **Automation Detection**
- Selenium/WebDriver detection
- PhantomJS detection
- Headless browser detection
- Chrome automation detection
- Puppeteer/Playwright detection
- Nightmare detection
- Automation property checks

#### 4. **Header Analysis**
- HTTP header validation
- Missing standard headers
- Suspicious patterns
- Bot signatures
- Header consistency

#### 5. **User-Agent Analysis**
- Browser parsing
- OS detection
- Device type identification
- Bot keyword detection
- Version validation

#### 6. **Consistency Checks**
- OS consistency (UA vs fingerprint)
- Language consistency
- Timezone validation
- Hardware validation

#### 7. **Threat Detection**
- SQL injection tool detection
- Scanner detection
- Suspicious path access
- Unusual HTTP methods

#### 8. **Behavioral Analysis**
- Mouse movement tracking
- Keyboard input detection
- Scroll behavior
- Touch support
- Page focus

---

### 🚀 Advanced Detection Techniques (14 techniques) ⭐ NEW

#### 9. **Advanced Mouse Tracking**
- Mouse velocity calculation (px/s)
- Mouse acceleration tracking
- Human curve detection (vs straight bot movements)
- Movement pattern analysis
- Direction changes
- Natural trajectory validation
- **Bot Detection:** Flags velocity > 3000 px/s

#### 10. **Click Rhythm Analysis**
- Click timestamps collection
- Inter-click interval calculation
- Click rhythm variance
- Consistency detection
- **Bot Detection:** Variance < 50ms indicates bot

#### 11. **Keyboard Dynamics**
- Dwell time (key press duration)
- Flight time (time between key releases)
- Typing rhythm analysis
- Natural typing pattern validation

#### 12. **Scroll Behavior Analysis**
- Scroll velocity tracking
- Scroll direction changes
- Scroll pattern regularity
- Natural scrolling detection

#### 13. **Enhanced Canvas Fingerprinting**
- Gradient rendering
- Emoji rendering (OS-specific)
- Complex path drawing
- Pixel data hashing
- Anti-tampering detection

#### 14. **CSS Media Queries (25+ features)**
- Pointer type (fine/coarse)
- Hover capability
- Color gamut (sRGB/P3/rec2020)
- Dynamic range (standard/high)
- Color scheme preference
- Contrast preference
- Reduced motion preference
- Reduced transparency preference
- Inverted colors detection
- Device type (screen/print/speech)
- Orientation (portrait/landscape)
- And 15+ more features

#### 15. **Speech Synthesis Fingerprinting**
- TTS voice enumeration
- Voice count
- Voice languages
- Default voice detection
- Local service identification
- OS-specific voice signatures

#### 16. **Gamepad API Detection**
- Connected gamepad count
- Gamepad IDs
- Controller type identification

#### 17. **Sensor APIs Detection**
- Accelerometer availability
- Gyroscope availability
- Magnetometer availability
- Ambient light sensor
- Proximity sensor

#### 18. **Performance API Fingerprinting**
- Memory usage (jsHeapSizeLimit, totalJSHeapSize, usedJSHeapSize)
- Navigation timing
- Resource timing
- Paint timing
- Performance metrics

#### 19. **Client Hints (User-Agent Client Hints)**
- Browser brands and versions
- Mobile flag
- Platform
- Architecture (x86, ARM, etc.)
- Bitness (32-bit, 64-bit)
- Model
- Platform version
- Full UA version

#### 20. **Virtual Machine Detection (6 indicators)**
- WebGL vendor signatures (VMware, VirtualBox)
- CPU core count (< 4 cores suspicious)
- Device memory (< 4GB suspicious)
- Render performance testing
- Generic GPU detection (llvmpipe, SwiftShader)
- **VM Likelihood:** Low/Medium/High scoring

#### 21. **Browser Extension Detection**
- Ad blocker detection (common ad URLs)
- DevTools detection (console timing, debugger traps)
- Extension-specific resource loading

#### 22. **Advanced Timing Analysis**
- Time to first click
- Time to first keypress
- Time to first scroll
- Interaction speed patterns
- **Bot Detection:** First interaction < 100ms indicates bot

## Installation

### Prerequisites

- Python 3.7+
- pip

### Setup

1. **Navigate to the directory:**
   ```bash
   cd VisitorAnalyzer
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python app.py
   ```

4. **Open your browser:**
   ```
   http://localhost:5000
   ```

## Usage

### For Website Owners

Simply run the application and share the URL with visitors. When someone accesses the page:

1. The system automatically collects browser fingerprint
2. Analyzes all security aspects
3. Displays comprehensive results with risk assessment
4. Shows exactly what's wrong with suspicious visitors

### Understanding Results

#### Risk Levels

- 🔴 **Critical (70-100)**: Very likely bot/malicious
- 🟠 **High (50-69)**: Likely bot or suspicious activity
- 🟡 **Medium (30-49)**: Some suspicious indicators
- 🟢 **Low (15-29)**: Minor concerns
- 🔵 **Minimal (0-14)**: Likely genuine visitor

#### Visitor Quality

- **Good**: Genuine visitor, all checks passed
- **Acceptable**: Legitimate but with minor inconsistencies
- **Suspicious**: Multiple red flags detected
- **Bad**: High likelihood of bot/fraud

#### Color Coding

- 🟢 **Green**: Parameter is genuine/good
- 🟡 **Yellow**: Warning/suspicious parameter
- 🔴 **Red**: Bad/risky parameter detected

## Analysis Modules

### 1. Overall Risk Assessment
- Total risk score (0-100)
- Visitor quality rating
- Authenticity status
- Confidence percentage
- Red flags list
- Green flags list

### 2. Basic Information
- IP address
- Timestamp
- Request method
- Protocol version
- Secure connection status

### 3. Header Analysis
- Header quality score
- Missing headers
- Suspicious patterns
- Proxy headers

### 4. User-Agent Analysis
- Parsed browser information
- OS and device detection
- Bot signature detection
- Suspicious patterns

### 5. Browser Fingerprint
- Manipulation indicators
- Inconsistencies
- Device information
- Browser features

### 6. Proxy/VPN Detection
- Risk level
- Proxy headers
- Detection indicators
- IP chain analysis

### 7. Automation Detection
- Detection confidence
- Automation tools identified
- Automation indicators

### 8. Consistency Checks
- Passed/Warning/Failed counts
- Individual check results
- Inconsistency details

### 9. Threat Indicators
- Threat level
- Detected threats
- Risk factors

### 10. Behavioral Signals
- Mouse movement
- Keyboard input
- Touch support
- Scroll behavior

### 11. Advanced Mouse & Click Analysis ⭐ NEW
- Human likelihood score
- Velocity and acceleration metrics
- Human curve detection
- Click rhythm analysis
- Bot indicators

### 12. Keyboard & Scroll Behavior ⭐ NEW
- Dwell time (key press duration)
- Flight time (time between releases)
- Typing rhythm
- Scroll velocity and patterns

### 13. Timing Analysis ⭐ NEW
- Time to first interaction
- Interaction speed patterns
- Suspicion level detection

### 14. Virtual Machine Detection ⭐ NEW
- VM likelihood score
- 6 detection indicators
- Environment analysis

### 15. Browser Extensions ⭐ NEW
- Ad blocker detection
- DevTools detection
- Extension analysis

### 16. CSS Media Features ⭐ NEW
- 25+ CSS media query features
- Device capabilities
- Environment detection

### 17. Speech Synthesis & Client Hints ⭐ NEW
- TTS voice enumeration
- Client Hints data
- Architecture and platform info

## Detection Methods

### Strongest Detection Techniques

1. **WebDriver Detection**: Checks `navigator.webdriver` and automation properties
2. **Canvas Fingerprinting**: Generates unique canvas signature
3. **WebGL Fingerprinting**: Analyzes GPU information
4. **Proxy Header Analysis**: Detects X-Forwarded-For chains
5. **WebRTC IP Leak**: Captures real IP behind VPN
6. **Headless Detection**: Multiple headless browser checks
7. **Consistency Validation**: Cross-validates multiple data points
8. **Behavioral Tracking**: Monitors human-like interactions

## Technical Details

### Backend (Python/Flask)

- **Framework**: Flask 3.0.0
- **User-Agent Parsing**: user-agents library
- **Security**: Built-in Flask security features

### Frontend

- **UI Framework**: Bootstrap 5.3.2 (Dark theme)
- **Icons**: Bootstrap Icons 1.11.2
- **JavaScript**: Vanilla JS (no dependencies)
- **Responsive**: Mobile-friendly design

### Architecture

```
VisitorAnalyzer/
├── app.py                      # Flask application
├── requirements.txt            # Python dependencies
├── README.md                   # Documentation
├── templates/
│   └── index.html              # Main page template
└── static/
    ├── css/
    │   └── style.css           # Custom dark theme
    └── js/
        ├── fingerprint.js      # Basic fingerprint collection (50+ signals)
        ├── fingerprint_advanced.js  # Advanced techniques (14 methods) ⭐
        └── analysis.js         # Results display & rendering
```
## Security Considerations

- No visitor data is stored permanently
- All analysis happens in real-time
- No external API calls (privacy-focused)
- Client-side fingerprinting only
- HTTPS recommended for production

## Customization

### Adjust Risk Scoring

Edit `app.py` in the `calculate_risk_score()` method:

```python
# Adjust scoring weights
if header_quality == 'bad':
    risk['total_score'] += 25  # Change this value
```

### Modify Detection Thresholds

Edit detection methods in `app.py`:

```python
# Example: Stricter automation detection
if indicator_count > 1:  # Change from 3 to 1
    detection['confidence'] = 'high'
```

## Troubleshooting

### Port Already in Use
```bash
# Change port in app.py
app.run(debug=True, host='0.0.0.0', port=5001)
```

### Missing Dependencies
```bash
pip install --upgrade -r requirements.txt
```

### WebRTC Not Working
WebRTC requires HTTPS in production. Use a reverse proxy or SSL certificate.

## Version History

### v1.0 - Initial Release
- Basic fingerprinting (50+ signals)
- Dark-themed UI
- Real-time analysis
- Risk scoring

### v2.0 - Enhanced Detection
- Proxy/VPN detection
- Improved consistency checks
- Better User-Agent analysis
- Enhanced behavioral tracking

### v3.0 - Advanced Features ⭐ CURRENT
- 14 new advanced techniques
- Mouse velocity/acceleration tracking
- Human curve detection
- Click rhythm analysis
- Keyboard dynamics (dwell time, flight time)
- Enhanced canvas fingerprinting
- 25+ CSS media query features
- Speech synthesis fingerprinting
- Gamepad and Sensor API detection
- Performance API metrics
- Client Hints (modern User-Agent)
- VM detection (6 indicators)
- Browser extension detection
- Advanced timing analysis
- Scroll behavior tracking
- 7 new UI sections to display advanced data
- Improved risk scoring algorithm
- Enhanced bot detection accuracy

## Future Enhancements

- [ ] IP geolocation lookup
- [ ] IP reputation database integration
- [ ] Machine learning-based scoring
- [ ] Historical visitor tracking
- [ ] Export analysis reports
- [ ] Admin dashboard
- [ ] Rate limiting
- [ ] API authentication
- [ ] Database logging (SQLite/PostgreSQL)
- [ ] Webhook notifications
- [ ] Real-time WebSocket updates
- [ ] TLS/JA3 fingerprinting
- [ ] HTTP/2 fingerprinting

## License

This project is for educational and authorized security testing purposes only.

## Credits

Built with Flask, Bootstrap, and comprehensive browser fingerprinting techniques.
