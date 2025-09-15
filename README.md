# CIS Benchmark Ubuntu 24 Compliance Script

![Ubuntu](https://img.shields.io/badge/OS-Ubuntu%2024-blue) ![Bash](https://img.shields.io/badge/Language-Bash-yellow) ![CIS](https://img.shields.io/badge/CIS-Benchmark-red)

---

## Overview

This **Bash script** automates the auditing and compliance checking of Ubuntu 24 servers according to the **CIS (Center for Internet Security) Benchmark**. It is designed to help system administrators, DevSecOps engineers, and security auditors verify that critical security and hardening configurations are correctly applied on their servers.

The script performs **online scanning** and checks multiple security areas including user permissions, SSH hardening, kernel module restrictions, password policies, and firewall configurations.

With this tool, you can ensure your Ubuntu 24 servers follow **industry-standard best practices**, reduce misconfigurations, and improve overall system security posture.

---

## Features

The script verifies and validates several key areas, including:

### 1. **Kernel Module & Service Hardening**

* Ensures `usb-storage` module is disabled and blacklisted.
* Checks unwanted services and applications are not installed.
* Validates AppArmor and firewall (UFW/nftables) are installed and configured.

### 2. **User & Permission Management**

* Checks file permissions for sensitive system files:

  * `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/shells`, `/etc/security/opasswd`
* Ensures no duplicate UIDs or GIDs exist.
* Ensures correct sudoers configuration with only authorized users.

### 3. **Password Policy Enforcement**

* Validates `pam_unix`, `pam_pwquality`, `pam_pwhistory`, and `pam_faillock` modules.
* Checks minimum password length, complexity, and history enforcement.
* Verifies account lockout policies and unlock times.

### 4. **SSH Hardening**

* Confirms the following settings in `/etc/ssh/sshd_config`:

  * `PermitRootLogin no`
  * `PermitEmptyPasswords no`
  * `PermitUserEnvironment no`
  * Proper `ClientAliveInterval` and `ClientAliveCountMax`
  * Correct ciphers, MACs, and KexAlgorithms

### 5. **System Security Policies**

* Validates message of the day (`/etc/issue` & `/etc/issue.net`) settings.
* Confirms GNOME/GDM screen lock configurations.
* Ensures system inactivity timeouts (TMOUT) are set.
* Checks firewall rules (iptables, ufw, nftables).
* Validates crontab restrictions and audit logging configurations.

### 6. **Audit & Logging**

* Generates clear **PASS** or **FAIL** output for each setting.
* Supports counting total compliant and non-compliant configurations.
* Provides actionable feedback for remediation.


### **Key Features**

* Checks for installed services that should not be present
* Validates SSH security settings
* Verifies file permissions for critical system files
* Ensures password policies and account lockout mechanisms
* Checks for duplicate UIDs/GIDs and usernames
* Confirms kernel modules like usb-storage are disabled
* Inspects firewall and network hardening settings
* Outputs clear PASS/FAIL results for each configuration
---


### **Table of Settings Checked**

| #  | Setting Area       | Specific Setting Checked                                                                         | Description                                                                       |
| -- | ------------------ | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| 1  | Services           | tnftp, iptables-persistent, ufw, nftables                                                        | Ensures unnecessary services are not installed                                    |
| 2  | Cron               | /etc/cron.allow, /etc/cron.deny                                                                  | Ensures cron access is restricted to authorized users                             |
| 3  | SSH                | PermitEmptyPasswords, PermitRootLogin, PermitUserEnvironment, Ciphers, MACs, ClientAliveInterval | Validates SSH configuration for secure remote access                              |
| 4  | PAM                | pam\_unix, pam\_faillock, pam\_pwquality, pam\_pwhistory                                         | Ensures authentication modules enforce password policies                          |
| 5  | Password Policies  | PASS\_MAX\_DAYS, PASS\_MIN\_DAYS, PASS\_WARN\_AGE, TMOUT, minimum password length, complexity    | Checks password expiration, inactivity, and strength requirements                 |
| 6  | Kernel Modules     | usb-storage                                                                                      | Ensures unnecessary kernel modules are disabled                                   |
| 7  | File Permissions   | /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow, /etc/shells, /etc/security/opasswd           | Verifies that critical files have secure permissions                              |
| 8  | Duplicate Accounts | UID/GID, usernames                                                                               | Checks that there are no duplicate IDs or usernames in /etc/passwd and /etc/group |
| 9  | Shell Settings     | /etc/profile, /etc/bashrc, /etc/profile.d                                                        | Ensures TMOUT and session timeout settings are configured                         |
| 10 | Firewall           | ufw, iptables, nftables                                                                          | Checks firewall installation and proper service configuration                     |
| 11 | AppArmor           | apparmor                                                                                         | Ensures AppArmor is installed and active                                          |
| 12 | GNOME/GDM          | Screen lock and inactivity timeout                                                               | Ensures desktop screensaver and lock settings are secure                          |
| 13 | Banner Messages    | /etc/issue, /etc/issue.net                                                                       | Ensures login banners are properly displayed                                      |



## Example Usage

```bash
# Clone the repository
git clone https://github.com/Hirishikesan-DevSecOps/cis-ubuntu24-compliance-scripts.git
cd cis-ubuntu24-compliance-scripts

# Give execution permission
chmod +x cis_benchmark_check.sh

# Run the script as root
sudo ./cis_benchmark_check.sh
```

**Output Example:**

```
[PASS] TMOUT is present in /etc/profile.d/timeout.sh
[FAIL] PASS_MAX_DAYS 60 is not present in /etc/login.defs
[PASS] No duplicate IDs present in /etc/passwd
```

---

## Why Use This Script?

* **Time-saving:** Automates hundreds of manual CIS benchmark checks.
* **Accuracy:** Detects misconfigurations that might be missed manually.
* **Portable:** Runs on any Ubuntu 24 server with Bash.
* **Security-first:** Ensures your system adheres to industry best practices.
* **Audit-ready:** Ideal for compliance reports and DevSecOps pipelines.

---

## Contribution

Contributions are welcome! If you find any missing CIS benchmarks or have suggestions for additional checks, feel free to fork the repository and submit a pull request.

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## Contact

* **GitHub:** [Hirishikesan](https://github.com/Hirishikesan)
* **LinkedIn:** [Hirishikesan BS](https://www.linkedin.com/in/hirishikesan-b-s-)

---

> **Disclaimer:** This script is intended for educational and auditing purposes. Always review changes before applying to production systems.
