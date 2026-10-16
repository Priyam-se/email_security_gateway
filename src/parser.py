import email
from email import policy
from email.utils import parseaddr
import re
import os


def extract_links(content):
    # regex pattern to find web addresses
    link_pattern = r'https?://[^\s<>"\']+'
    return re.findall(link_pattern, content)


def parse_email_file(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    # read primary headers
    raw_from = msg.get("From", "")
    sender_name, sender_addr = parseaddr(raw_from)
    sender_domain = sender_addr.split("@")[-1].lower() if "@" in sender_addr else ""

    header_data = {
        "subject": msg.get("Subject", "(No Subject)"),
        "from_raw": raw_from,
        "sender_name": sender_name,
        "sender_address": sender_addr,
        "sender_domain": sender_domain,
        "to": msg.get("To", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "auth_results": msg.get("Authentication-Results", ""),
        "received_hops": msg.get_all("Received", [])
    }

    body_plain = ""
    attachments = []

    # traverse mime parts
    if msg.is_multipart():
        for item in msg.walk():
            ctype = item.get_content_type()
            disposition = str(item.get("Content-Disposition", ""))

            if "attachment" in disposition:
                name = item.get_filename() or "unnamed_file"
                data = item.get_payload(decode=True) or b""
                attachments.append({
                    "filename": name,
                    "size": len(data),
                    "bytes": data
                })
            elif ctype == "text/plain":
                data = item.get_payload(decode=True)
                if data:
                    body_plain += data.decode("utf-8", errors="ignore")
    else:
        data = msg.get_payload(decode=True)
        if data:
            body_plain = data.decode("utf-8", errors="ignore")

    detected_urls = list(set(extract_links(body_plain)))

    return {
        "headers": header_data,
        "body": body_plain,
        "urls": detected_urls,
        "attachments": attachments
    }
