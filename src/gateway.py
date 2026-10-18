from .parser import parse_email_file
from .auth_checker import verify_authentication
from .url_checker import scan_urls
from .attachment_checker import scan_attachments
from .ml_detector import TextPhishingClassifier

# classifier instance
nlp_engine = TextPhishingClassifier()


def evaluate_email(file_path):
    # 1. parse email headers, text body, links, and attachments
    email_data = parse_email_file(file_path)
    headers = email_data["headers"]

    # 2. run each security check
    auth_report = verify_authentication(headers)
    url_report = scan_urls(email_data["urls"])
    att_report = scan_attachments(email_data["attachments"])
    ml_report = nlp_engine.analyze_text(email_data["body"])

    # 3. sum up penalties from all modules and cap at 100
    raw_score = (
        auth_report["total_penalty"] +
        url_report["total_penalty"] +
        att_report["total_penalty"] +
        ml_report["penalty"]
    )
    final_score = min(max(raw_score, 0), 100)

    # 4. set verdict based on score threshold
    if final_score >= 70:
        verdict = "MALICIOUS"
        action = "BLOCK (Quarantined at Gateway)"
    elif final_score >= 35:
        verdict = "SUSPICIOUS"
        action = "FLAG (Warning Banner Appended)"
    else:
        verdict = "CLEAN"
        action = "ALLOW (Delivered to Inbox)"

    # 5. collect all findings to display in terminal
    reasons = []
    if auth_report["spf"]["status"] == "FAIL":
        reasons.append("SPF authentication failed")
    if auth_report["dkim"]["status"] == "FAIL":
        reasons.append("DKIM cryptographic signature check failed")
    reasons.extend(auth_report["mismatches"])

    for u in url_report["results"]:
        reasons.extend(u["findings"])

    for a in att_report["results"]:
        reasons.extend(a["findings"])

    if ml_report["triggers_found"]:
        reasons.append(f"Social engineering triggers detected: {', '.join(ml_report['triggers_found'])}")

    return {
        "file": file_path,
        "subject": headers["subject"],
        "from": headers["from_raw"],
        "sender_address": headers["sender_address"],
        "risk_score": final_score,
        "verdict": verdict,
        "action": action,
        "findings": reasons,
        "auth_details": auth_report,
        "url_details": url_report,
        "attachment_details": att_report,
        "ml_details": ml_report
    }
