<h1 align="center">
  <img src="logo.png" width="20%" height="30%" style="vertical-align: middle;">
</h1>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com/?lines=ASRX;&font=Fira%20Code&center=true&width=380&height=50&duration=4000&pause=1000" alt="Example Usage - README Typing SVG">
</p>

# ASRX

**An advanced Active Directory security auditing tool designed to automate the AS-REP Roasting attack vector.**

*Developed by **Davud Qasimov***

---
### ‼️Prerequisites

ASRX requires **Impacket** and **pyasn1** to handle LDAP and Kerberos communication.

## 🚀 Overview

**ASRX** is a next-generation security auditing utility built for penetration testers, Red Team operators, and enterprise security engineers. By deeply leveraging the inner workings of the **Kerberos** authentication protocol and **LDAP** directory services, ASRX automates the entire lifecycle of the **AS-REP Roasting** attack—from initial discovery to parsing and exporting hashes for offline cracking.

---

## 🛠️ How It Works

1. **Reconnaissance & Enumeration:** Queries the Domain Controller via LDAP to locate user accounts configured with the dangerous security flag: `DONT_REQ_PREAUTH` (*"Do not require Kerberos pre-authentication"*).
2. **Ticket Harvesting:** Automatically sends legitimate Ticket Granting Ticket (`TGT`) requests for every discovered vulnerable account. Because pre-authentication is disabled, the DC responds with a ticket without requiring an encrypted timestamp.
3. **Export & Formatting:** Captures and packages the harvested blobs directly into formats fully compatible with modern offline cracking tools like **Hashcat** and **John the Ripper**.

---

## ⚙️ Key Features

* **High Automation:** Say goodbye to manually crafting complex LDAP filters or chaining multiple disparate scripts.
* **Precision Targeting:** Quickly isolates misconfigured, high-risk user objects in large-scale enterprise domains.
* **Streamlined Offline Cracking:** Outputs clean hash formats ready for GPU-accelerated brute-force workflows.

---

## ⚠️ The Threat Vector

AS-REP Roasting risks typically stem from legacy compatibility requirements, administrative oversights, or improper default templates. Discovering even a single user account with pre-authentication disabled allows an adversary to perform **entirely offline password cracking**, completely bypassing network-based detection systems and avoiding account lockout policies on the Domain Controller.

---

## 📦 Documentation & Links

* **Notion (EN):** [View English Guide](https://app.notion.com/p/ASRX-3c7e38fe4d54802ea36bf1b59f892770?source=copy_link)
* **Notion (RU):** [View Russian Guide](https://app.notion.com/p/ASRX-ru-3c7e38fe4d548078a2f3fcc323ea0a3b?source=copy_link)
* **Notion (AZ):** [View Azerbaijani Guide](https://app.notion.com/p/ASRX-az-3c7e38fe4d548068be04fcc2af47bd51?source=copy_link)

---

## 🛡️ Remediation & Defense

To secure your environment against the risks highlighted by ASRX:

* **Enforce Pre-Authentication:** Ensure that the *"Do not require Kerberos pre-authentication"* setting is disabled for all user accounts (unless strictly required by legacy applications).
* **Strong Passwords:** Enforce complex, lengthy password policies for any service or user accounts that cannot have pre-authentication enabled.
* **Monitoring:** Monitor for abnormal volumes of Kerberos TGT requests (Event ID 4768) originating from a single source without pre-authentication flags.

 ## ASRX Configuration & Global Setup Guide
This guide covers how to set up ASRX so it can be executed globally from any directory on your system.
### 🌍Making ASRX Globally Accessible
To run asrx as a system-wide command from any path in your terminal, follow these steps:
### 1. Make the Script Executable
Navigate to your project directory and grant execution permissions to the main script:
chmod +x asrx.py

### 2. Create a Global Symbolic Link
Create a symlink in /usr/local/bin so the system recognizes asrx as a global command. This ensures that any updates you pull or push in your local repository will instantly apply to the global command:
sudo ln -s /full/path/to/your/ASRX/asrx.py /usr/local/bin/asrx

(Replace /full/path/to/your/ASRX/asrx.py with the absolute path to your file).
### 3. Verify the Installation
Open a new terminal window in any random directory (e.g., your home directory) and run:
asrx -h

#### If the help menu appears successfully, the global configuration is complete.
For authorized security auditing and educational purposes only.
