#!/usr/bin/env python3
import argparse
import os
import sys
from src.gateway import evaluate_email

# terminal colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"{CYAN}{BOLD}")
    print("=========================================================")
    print("        Email Security Gateway & Phishing Analyzer       ")
    print("=========================================================")
    print(f"{RESET}")


def format_report(result):
    verdict = result["verdict"]
    score = result["risk_score"]

    if verdict == "MALICIOUS":
        color = RED
    elif verdict == "SUSPICIOUS":
        color = YELLOW
    else:
        color = GREEN

    print(f"File       : {os.path.basename(result['file'])}")
    print(f"Subject    : {result['subject']}")
    print(f"From       : {result['from']}")
    print(f"Risk Score : {color}{BOLD}{score}/100 ({verdict}){RESET}")
    print(f"Action     : {color}{result['action']}{RESET}")

    if result["findings"]:
        print(f"\n{BOLD}Threat Indicators Flagged:{RESET}")
        for item in result["findings"]:
            print(f"  {color}[!] {item}{RESET}")
    else:
        print(f"\n{GREEN}[+] No malicious indicators detected.{RESET}")

    print("-" * 57)


def scan_single(file_path):
    if not os.path.exists(file_path):
        print(f"{RED}[-] Error: File not found: {file_path}{RESET}")
        return

    print(f"\n{BOLD}[*] Scanning: {file_path}...{RESET}\n")
    report = evaluate_email(file_path)
    format_report(report)


def scan_directory(dir_path):
    if not os.path.exists(dir_path):
        print(f"{RED}[-] Error: Directory not found: {dir_path}{RESET}")
        return

    # find all .eml files in target directory
    files = [os.path.join(dir_path, f) for f in os.listdir(dir_path) if f.endswith(".eml")]
    if not files:
        print(f"{YELLOW}[!] No .eml files found in {dir_path}{RESET}")
        return

    print(f"\n{BOLD}[*] Batch scanning {len(files)} email(s) in: {dir_path}...{RESET}\n")
    print("-" * 57)

    summary = {"CLEAN": 0, "SUSPICIOUS": 0, "MALICIOUS": 0}

    for f in sorted(files):
        rep = evaluate_email(f)
        format_report(rep)
        summary[rep["verdict"]] += 1

    # summary report
    print(f"\n{BOLD}=== Scan Summary ==={RESET}")
    print(f"  {GREEN}Clean Emails       : {summary['CLEAN']}{RESET}")
    print(f"  {YELLOW}Suspicious Emails  : {summary['SUSPICIOUS']}{RESET}")
    print(f"  {RED}Blocked / Malicious: {summary['MALICIOUS']}{RESET}")
    print(f"  Total Processed    : {len(files)}\n")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Scan .eml email files for phishing, spoofing, and malicious links."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to a single .eml file to scan")
    group.add_argument("-d", "--dir", help="Directory of .eml files to batch scan")

    args = parser.parse_args()

    if args.file:
        scan_single(args.file)
    elif args.dir:
        scan_directory(args.dir)


if __name__ == "__main__":
    main()
