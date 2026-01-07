import re
from urllib.parse import urlparse

PHISHING_PATTERNS = {
    "credential_harvesting": r"(verify|confirm|update).*(account|password|payment)",
    "lookalike_domains": r"(paypa1|g00gle|micros0ft)",
    "fake_urgency": r"(suspended|locked|expires?.*(24|48)\s*hours)",
    "prize_scams": r"(congratulations|winner|claim.*prize)",
    "impersonation": r"(IRS|FBI|tax.*refund|social.*security)",
}


def analyze_message(message, url):
    risk_score = 0
    explanations = []
    tips = []

    # Text analysis
    message_lower = message.lower()

    # Keywords indicating urgency
    urgency_keywords = ["urgent", "immediate", "act now", "limited time", "deadline"]
    urgency_count = sum(1 for word in urgency_keywords if word in message_lower)
    if urgency_count > 0:
        risk_score += urgency_count * 2
        explanations.append(
            f"Detected {urgency_count} urgency keyword(s): {', '.join([word for word in urgency_keywords if word in message_lower])}"
        )
        tips.append(
            "Be cautious of messages that pressure you to act quickly without thinking. Scammers use urgency to bypass careful consideration—take time to verify the sender and content independently."
        )
        tips.append(
            "Next time, be aware that legitimate organizations rarely demand immediate action without prior notice."
        )

    # Threats or rewards
    threat_keywords = ["account suspended", "legal action", "virus detected"]
    reward_keywords = ["free money", "win prize", "inheritance"]
    threat_count = sum(1 for word in threat_keywords if word in message_lower)
    reward_count = sum(1 for word in reward_keywords if word in message_lower)
    if threat_count > 0:
        risk_score += threat_count * 3
        explanations.append(
            f"Detected {threat_count} threat-related phrase(s): {', '.join([word for word in threat_keywords if word in message_lower])}"
        )
        tips.append(
            "Scammers often use threats to create fear and prompt hasty responses. Contact the supposed sender through official channels to confirm any issues."
        )
        tips.append(
            "Be aware that real threats from legitimate sources are usually communicated via multiple methods, not just unsolicited messages."
        )
    if reward_count > 0:
        risk_score += reward_count * 2
        explanations.append(
            f"Detected {reward_count} reward-related phrase(s): {', '.join([word for word in reward_keywords if word in message_lower])}"
        )
        tips.append(
            "If it sounds too good to be true, it probably is. Unsolicited offers of money or prizes are common scam tactics."
        )
        tips.append(
            "Next time, remember that trustworthy organizations don't promise rewards without clear terms and prior interaction."
        )

    # Capitalization anomalies
    caps_ratio = sum(1 for c in message if c.isupper()) / len(message) if message else 0
    if caps_ratio > 0.5:
        risk_score += 2
        explanations.append("High use of capital letters detected.")
        tips.append(
            "Legitimate messages rarely use excessive capitalization. This technique is often used to grab attention or convey urgency."
        )
        tips.append(
            "In the future, be wary of messages that shout through all caps—it may be an attempt to manipulate your emotions."
        )

    # Grammar anomalies (simple check: multiple exclamation marks)
    exclamation_count = message.count("!")
    if exclamation_count > 3:
        risk_score += 1
        explanations.append("Excessive use of exclamation marks.")
        tips.append(
            "Overuse of punctuation can indicate excitement or urgency, common in scams. It may be used to build hype or pressure."
        )
        tips.append(
            "Going forward, notice how excessive punctuation can be a red flag for manipulative communication tactics."
        )

    # Advanced phishing pattern detection
    for pattern_name, pattern in PHISHING_PATTERNS.items():
        if re.search(pattern, message_lower, re.IGNORECASE):
            if pattern_name == "credential_harvesting":
                risk_score += 5
                explanations.append(
                    "Detected language requesting credential verification or updates."
                )
                tips.append(
                    "Never provide sensitive information in response to unsolicited requests."
                )
                tips.append(
                    "Legitimate organizations won't ask for passwords via email or SMS."
                )
            elif pattern_name == "lookalike_domains":
                risk_score += 3
                explanations.append(
                    "Detected lookalike domain patterns (e.g., paypa1 instead of paypal)."
                )
                tips.append("Check URLs carefully for subtle misspellings.")
            elif pattern_name == "fake_urgency":
                risk_score += 3
                explanations.append(
                    "Detected fake urgency tactics (account suspension, expiration)."
                )
                tips.append(
                    "Scammers use time pressure to prevent careful consideration."
                )
            elif pattern_name == "prize_scams":
                risk_score += 2
                explanations.append("Detected prize or lottery scam language.")
                tips.append("If you didn't enter a contest, you didn't win anything.")
            elif pattern_name == "impersonation":
                risk_score += 4
                explanations.append(
                    "Detected impersonation of authorities or government agencies."
                )
                tips.append(
                    "Government agencies don't demand immediate payment via unusual methods."
                )
                tips.append(
                    "Verify official communications through known contact channels."
                )

    # URL analysis
    if url:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Check for IP addresses instead of domains
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            risk_score += 6
            explanations.append("URL uses an IP address instead of a domain name.")
            tips.append(
                "Legitimate websites typically use domain names, not raw IP addresses."
            )
            tips.append("IP-based links are often used in malicious redirects.")

        # Shorteners
        shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co"]
        if any(short in domain for short in shorteners):
            risk_score += 3
            explanations.append(
                "URL uses a link shortener, which can hide the true destination."
            )
            tips.append(
                "Hover over links or use URL expanders to see the full address. Shorteners are often used to obscure malicious sites."
            )
            tips.append(
                "Be cautious of shortened links in unsolicited messages; scammers use them to avoid detection."
            )

        # Suspicious TLDs
        suspicious_tlds = [
            ".xyz",
            ".top",
            ".club",
            ".online",
            ".tk",
            ".ml",
            ".ga",
            ".cf",
        ]
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            risk_score += 2
            explanations.append(
                f"Domain uses a potentially suspicious TLD: {parsed.netloc}"
            )
            tips.append(
                "Research the domain's reputation before clicking. Some TLDs are associated with higher scam activity."
            )
            tips.append(
                "Next time, check if the domain matches the official website of the organization."
            )

        # Excessive subdomains
        if domain.count(".") > 3:
            risk_score += 1
            explanations.append("Excessive subdomain nesting detected.")
            tips.append(
                "Too many subdomains can indicate an attempt to mimic legitimate sites."
            )

        # Unusual characters
        if re.search(r"[^\w.-]", domain):
            risk_score += 1
            explanations.append("Domain contains unusual characters.")
            tips.append(
                "Legitimate domains usually use standard characters. Unusual ones may indicate phishing attempts."
            )
            tips.append(
                "In future communications, verify URLs by typing them manually rather than clicking links."
            )

    # General tips for awareness
    if not tips:  # If no specific tips, add general ones
        tips.append(
            "Even if no red flags are detected, stay vigilant—scams evolve constantly."
        )
    tips.append(
        "Build awareness by learning common scam tactics; knowledge is your best defense."
    )
    tips.append(
        "When in doubt, consult trusted sources or professionals for verification."
    )

    # Determine risk level with weighted scoring
    if risk_score >= 6:
        risk_level = "High"
        confidence = min(95, 60 + risk_score * 2)
    elif risk_score >= 4:
        risk_level = "Medium"
        confidence = min(80, 50 + risk_score * 3)
    else:
        risk_level = "Low"
        confidence = min(75, 40 + risk_score * 5)

    return {
        "risk_level": risk_level,
        "confidence": confidence,
        "explanations": explanations,
        "tips": tips,
    }
