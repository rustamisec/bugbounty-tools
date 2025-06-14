# Bug Bounty Tools by RostamiSec

This repository contains a collection of my personal automation scripts for bug bounty hunting and security reconnaissance.

---

## 1. recon-weblist

* **Version:** 4.0
* **Author:** Hossein Rostami
* **Description:** This script automates the first phases of reconnaissance. It takes a target domain, finds all associated subdomains, probes for live web servers, and runs a quick port scan on the live hosts.
* **Usage:** `recon-weblist` (The script is interactive and will prompt for a domain).
* **Dependencies:** `subfinder`, `httpx`, `nmap`.

## 2. csrf-scanner
* **Version:** 1.0 (In Development)
* **Description:** A Python script to scan a given URL for forms that may be vulnerable to CSRF.
* **Usage:** `csrf-scanner.py <URL>`
* **Dependencies:** `python3-requests`, `python3-bs4`.# bugbounty-tools
