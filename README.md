# Smart Scam & Phishing Risk Detector

This project is for educational purpose only

A privacy-first educational tool built with Flask. It analyzes messages for phishing indicators using pattern matching and heuristic scoring, providing detailed explanations to help users recognize scams.”

## Overview

This project addresses the growing problem of online scams and phishing attacks. Unlike tools that promise "AI detection," this application uses rule-based analysis to provide transparent, explainable risk assessments that educate users on suspicious patterns.

## Features

- **Advanced Text Analysis**: Detects urgency keywords, threats, rewards, capitalization anomalies, grammar issues, credential harvesting, lookalike domains, fake urgency, prize scams, and impersonation attempts.
- **Comprehensive URL Analysis**: Checks for link shorteners, IP addresses, suspicious TLDs (.tk, .ml, .ga, .cf), excessive subdomains, and unusual characters.
- **Weighted Risk Scoring**: Outputs Low/Medium/High risk levels with dynamic confidence indicators based on pattern severity.
- **Explainability**: Highlights suspicious patterns and provides plain-language explanations.
- **User Education**: Offers safety tips, awareness suggestions, and educational content about common scams.
- **Interactive UI**: Includes visual risk indicators, example messages for testing, and export functionality.
- **Security & Validation**: Input sanitization, length limits, and XSS prevention.
- **Ethical Design**: Includes clear disclaimers, does not store user data, and promotes critical thinking.
- **Testing**: Comprehensive unit tests ensure reliability.

## Tech Stack

- **Backend**: Python with Flask, MarkupSafe for input sanitization
- **Frontend**: HTML, CSS (Bootstrap), JavaScript
- **Analysis**: Advanced rule-based pattern matching with weighted scoring
- **Testing**: Unit tests with Python's unittest framework
- **Security**: Input validation and XSS prevention

## Setup Instructions

1. **Clone the repository**:

   ```bash
   git clone <https://github.com/Code-id70/smart-scam-phishing-detector.git >
   cd smart-scam-phishing-detector
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:

   ```bash
   python app.py
   ```

4. **Access the app**:
   Open your browser and go to `http://localhost:5000`

## Usage

1. Paste the message content into the text area.
2. Optionally, enter a URL if present.
3. Click "Analyze" to get the risk assessment.
4. Review the risk level (with visual indicator), explanations, and safety tips.
5. Use "Try Example Messages" to test with sample phishing, suspicious, or legitimate content.
6. Learn about common scams in the educational section.
7. Export results as a text file if needed.

## Testing

Run the unit tests to verify functionality:

```bash
python test_detector.py
```

## Ethical Considerations

- **Transparency**: All analysis rules are visible in the code.
- **No False Promises**: Clearly states limitations and uncertainty.
- **User Empowerment**: Educates users rather than making decisions for them.
- **Privacy**: Does not store or transmit user-submitted content.
- **Responsible AI**: Avoids fear-based language and promotes critical thinking.

## Limitations

- Rule-based system may miss sophisticated scams.
- Does not perform real-time URL checks or malware scanning.
- Confidence indicators are approximate and based on heuristics.
- Not a substitute for professional security advice.

## Architecture Overview

- `app.py`: Flask application with input validation, routes for home and analysis, and logging.
- `analysis.py`: Core logic for advanced pattern detection and weighted risk scoring.
- `test_detector.py`: Unit tests for validation and reliability.
- `templates/index.html`: Frontend interface with educational content and examples.
- `static/style.css` & `static/script.js`: Styling and client-side functionality with export features.
- `requirements.txt`: Dependencies including Flask and MarkupSafe.

## Success Criteria

- Non-technical users can understand flagged patterns.
- System clearly communicates uncertainty.
- Provides practical educational value.
- Demonstrates responsible AI principles.

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please ensure changes align with ethical guidelines and add tests for new features.
