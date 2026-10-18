import hashlib
import os

# file extensions commonly leveraged for malware delivery
DANGEROUS_EXTENSIONS = {
    ".exe": 45,
    ".scr": 45,
    ".vbs": 40,
    ".js": 35,
    ".bat": 35,
    ".cmd": 35,
    ".ps1": 40,
    ".iso": 35,
    ".hta": 40,
    ".jar": 30,
    ".xlsm": 25,  # macro-enabled excel
    ".docm": 25   # macro-enabled word
}


def compute_sha256(byte_data):
    h = hashlib.sha256()
    h.update(byte_data)
    return h.hexdigest()


def inspect_attachment(att_dict):
    filename = att_dict.get("filename", "")
    data = att_dict.get("bytes", b"")

    findings = []
    penalty = 0

    # compute file hash
    file_hash = compute_sha256(data) if data else "empty"

    # check for double extensions e.g. document.pdf.exe
    name_parts = filename.lower().split(".")
    if len(name_parts) > 2:
        secondary_ext = f".{name_parts[-2]}"
        final_ext = f".{name_parts[-1]}"
        if final_ext in DANGEROUS_EXTENSIONS:
            findings.append(f"Double extension masquerade detected: '{filename}' disguises executable as '{secondary_ext}'")
            penalty += 50

    # check primary extension
    _, ext = os.path.splitext(filename.lower())
    if ext in DANGEROUS_EXTENSIONS:
        findings.append(f"High-risk executable extension: '{ext}'")
        penalty = max(penalty, DANGEROUS_EXTENSIONS[ext])

    return {
        "filename": filename,
        "size_bytes": len(data),
        "sha256": file_hash,
        "findings": findings,
        "penalty": penalty
    }


def scan_attachments(attachment_list):
    results = []
    total_penalty = 0

    for item in attachment_list:
        res = inspect_attachment(item)
        results.append(res)
        total_penalty += res["penalty"]

    # cap attachment penalty at 60 points
    return {
        "count": len(attachment_list),
        "results": results,
        "total_penalty": min(total_penalty, 60)
    }
