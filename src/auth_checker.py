import re


def check_spf(auth_results_header):
    """
    extracts spf status from Authentication-Results or Received-SPF header
    """
    header_lower = auth_results_header.lower()
    
    if "spf=pass" in header_lower:
        return {"status": "PASS", "score_impact": 0, "reason": "SPF aligned and passed"}
    elif "spf=fail" in header_lower or "spf=softfail" in header_lower:
        return {"status": "FAIL", "score_impact": 25, "reason": "SPF authentication failed"}
    elif "spf=neutral" in header_lower or "spf=none" in header_lower:
        return {"status": "NONE", "score_impact": 10, "reason": "No strict SPF record published"}
    
    return {"status": "UNKNOWN", "score_impact": 5, "reason": "No SPF verification header present"}


def check_dkim(auth_results_header):
    """
    extracts dkim signature validation status
    """
    header_lower = auth_results_header.lower()
    
    if "dkim=pass" in header_lower:
        return {"status": "PASS", "score_impact": 0, "reason": "DKIM signature verified"}
    elif "dkim=fail" in header_lower:
        return {"status": "FAIL", "score_impact": 25, "reason": "DKIM cryptographic signature invalid"}
    
    return {"status": "NONE", "score_impact": 5, "reason": "No DKIM signature found"}


def check_sender_mismatch(headers):
    """
    detects display name spoofing or mismatches between visible From and Return-Path
    """
    from_addr = headers.get("sender_address", "").lower()
    return_path = headers.get("return_path", "").lower()
    reply_to = headers.get("reply_to", "").lower()

    findings = []
    penalty = 0

    # check return-path mismatch if present
    if return_path:
        # clean return-path brackets e.g. <bounce@domain.com>
        clean_return = re.sub(r"[<>]", "", return_path).strip()
        from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
        return_domain = clean_return.split("@")[-1] if "@" in clean_return else ""

        if from_domain and return_domain and from_domain != return_domain:
            findings.append(f"Envelope sender mismatch: From '{from_domain}' vs Return-Path '{return_domain}'")
            penalty += 20

    # check reply-to mismatch
    if reply_to:
        clean_reply = re.sub(r"[<>]", "", reply_to).strip()
        from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
        reply_domain = clean_reply.split("@")[-1] if "@" in clean_reply else ""

        if from_domain and reply_domain and from_domain != reply_domain:
            findings.append(f"Reply-To mismatch: replies directed to external domain '{reply_domain}'")
            penalty += 15

    return {
        "mismatches": findings,
        "score_impact": penalty
    }


def verify_authentication(headers):
    """
    combines spf, dkim, and header spoof checks into a unified auth report
    """
    auth_header = headers.get("auth_results", "")
    
    spf_res = check_spf(auth_header)
    dkim_res = check_dkim(auth_header)
    mismatch_res = check_sender_mismatch(headers)

    total_auth_penalty = spf_res["score_impact"] + dkim_res["score_impact"] + mismatch_res["score_impact"]

    return {
        "spf": spf_res,
        "dkim": dkim_res,
        "mismatches": mismatch_res["mismatches"],
        "total_penalty": total_auth_penalty
    }
