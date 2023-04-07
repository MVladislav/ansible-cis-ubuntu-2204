# CIS - Ubuntu 22.04

- [CIS - Ubuntu 22.04](#cis---ubuntu-2204)
  - [Requirements](#requirements)
  - [Role Variables](#role-variables)
  - [Dependencies](#dependencies)
  - [Example Playbook](#example-playbook)
  - [CIS - List of Recommendations](#cis---list-of-recommendations)
  - [License](#license)

---

Configure Ubuntu 22.04 to be CIS compliant.

Tested with:

- Ubuntu 22.04
- Ubuntu 23.04

This role **will make changes to the system** that could break things. \
This is not an auditing tool but rather a remediation tool to be used after an audit has been conducted.

Based on [CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0](https://downloads.cisecurity.org/#/).

## Requirements

...

## Role Variables

...

## Dependencies

Developed and testes with Ansible 2.14.4

## Example Playbook

...

## CIS - List of Recommendations

| #         | CIS Benchmark Recommendation Set                                                                | Yes | No  |
| :-------- | :---------------------------------------------------------------------------------------------- | :-- | :-- |
| 1         | **Initial Setup**                                                                               |     |     |
| 1.1       | **Filesystem Configuration**                                                                    |     |     |
| 1.1.1     | **Disable unused filesystems**                                                                  |     |     |
| 1.1.1.1   | Ensure mounting of cramfs filesystems is disabled (Automated)                                   |     |     |
| 1.1.1.2   | Ensure mounting of squashfs filesystems is disabled (Automated)                                 |     |     |
| 1.1.1.3   | Ensure mounting of udf filesystems is disabled (Automated)                                      |     |     |
| 1.1.2     | **Configure /tmp**                                                                              |     |     |
| 1.1.2.1   | Ensure /tmp is a separate partition (Automated)                                                 |     |     |
| 1.1.2.2   | Ensure nodev option set on /tmp partition (Automated)                                           |     |     |
| 1.1.2.3   | Ensure noexec option set on /tmp partition (Automated)                                          |     |     |
| 1.1.2.4   | Ensure nosuid option set on /tmp partition (Automated)                                          |     |     |
| 1.1.3     | **Configure /var**                                                                              |     |     |
| 1.1.3.1   | Ensure separate partition exists for /var (Automated)                                           |     |     |
| 1.1.3.2   | Ensure nodev option set on /var partition (Automated)                                           |     |     |
| 1.1.3.3   | Ensure nosuid option set on /var partition (Automated)                                          |     |     |
| 1.1.4     | **Configure /var/tmp**                                                                          |     |     |
| 1.1.4.1   | Ensure separate partition exists for /var/tmp (Automated)                                       |     |     |
| 1.1.4.2   | Ensure noexec option set on /var/tmp partition (Automated)                                      |     |     |
| 1.1.4.3   | Ensure nosuid option set on /var/tmp partition (Automated)                                      |     |     |
| 1.1.4.4   | Ensure nodev option set on /var/tmp partition (Automated)                                       |     |     |
| 1.1.5     | **Configure /var/log**                                                                          |     |     |
| 1.1.5.1   | Ensure separate partition exists for /var/log (Automated)                                       |     |     |
| 1.1.5.2   | Ensure nodev option set on /var/log partition (Automated)                                       |     |     |
| 1.1.5.3   | Ensure noexec option set on /var/log partition (Automated)                                      |     |     |
| 1.1.5.4   | Ensure nosuid option set on /var/log partition (Automated)                                      |     |     |
| 1.1.6     | **Configure /var/log/audit**                                                                    |     |     |
| 1.1.6.1   | Ensure separate partition exists for /var/log/audit (Automated)                                 |     |     |
| 1.1.6.2   | Ensure noexec option set on /var/log/audit partition (Automated)                                |     |     |
| 1.1.6.3   | Ensure nodev option set on /var/log/audit partition (Automated)                                 |     |     |
| 1.1.6.4   | Ensure nosuid option set on /var/log/audit partition (Automated)                                |     |     |
| 1.1.7     | **Configure /home**                                                                             |     |     |
| 1.1.7.1   | Ensure separate partition exists for /home (Automated)                                          |     |     |
| 1.1.7.2   | Ensure nodev option set on /home partition (Automated)                                          |     |     |
| 1.1.7.3   | Ensure nosuid option set on /home partition (Automated)                                         |     |     |
| 1.1.8     | **Configure /dev/shm**                                                                          |     |     |
| 1.1.8.1   | Ensure nodev option set on /dev/shm partition (Automated)                                       |     |     |
| 1.1.8.2   | Ensure noexec option set on /dev/shm partition (Automated)                                      |     |     |
| 1.1.8.3   | Ensure nosuid option set on /dev/shm partition (Automated)                                      |     |     |
| 1.1.9     | Disable Automounting (Automated)                                                                |     |     |
| 1.1.10    | Disable USB Storage (Automated)                                                                 |     |     |
| 1.2       | **Configure Software Updates**                                                                  |     |     |
| 1.2.1     | Ensure package manager repositories are configured (Manual)                                     |     |     |
| 1.2.2     | Ensure GPG keys are configured (Manual)                                                         |     |     |
| 1.3       | **Filesystem Integrity Checking**                                                               |     |     |
| 1.3.1     | Ensure AIDE is installed (Automated)                                                            |     |     |
| 1.3.2     | Ensure filesystem integrity is regularly checked (Automated)                                    |     |     |
| 1.4       | **Secure Boot Settings**                                                                        |     |     |
| 1.4.1     | Ensure bootloader password is set (Automated)                                                   |     |     |
| 1.4.2     | Ensure permissions on bootloader config are configured (Automated)                              |     |     |
| 1.4.3     | Ensure authentication required for single user mode (Automated)                                 |     |     |
| 1.5       | **Additional Process Hardening**                                                                |     |     |
| 1.5.1     | Ensure address space layout randomization (ASLR) is enabled (Automated)                         |     |     |
| 1.5.2     | Ensure prelink is not installed (Automated)                                                     |     |     |
| 1.5.3     | Ensure Automatic Error Reporting is not enabled (Automated)                                     |     |     |
| 1.5.4     | Ensure core dumps are restricted (Automated)                                                    |     |     |
| 1.6       | **Mandatory Access Control**                                                                    |     |     |
| 1.6.1     | **Configure AppArmor**                                                                          |     |     |
| 1.6.1.1   | Ensure AppArmor is installed (Automated)                                                        |     |     |
| 1.6.1.2   | Ensure AppArmor is enabled in the bootloader configuration (Automated)                          |     |     |
| 1.6.1.3   | Ensure all AppArmor Profiles are in enforce or complain mode (Automated)                        |     |     |
| 1.6.1.4   | Ensure all AppArmor Profiles are enforcing (Automated)                                          |     |     |
| 1.7       | **Command Line Warning Banners**                                                                |     |     |
| 1.7.1     | Ensure message of the day is configured properly (Automated)                                    |     |     |
| 1.7.2     | Ensure local login warning banner is configured properly (Automated)                            |     |     |
| 1.7.3     | Ensure remote login warning banner is configured properly (Automated)                           |     |     |
| 1.7.4     | Ensure permissions on /etc/motd are configured (Automated)                                      |     |     |
| 1.7.5     | Ensure permissions on /etc/issue are configured (Automated)                                     |     |     |
| 1.7.6     | Ensure permissions on /etc/issue.net are configured (Automated)                                 |     |     |
| 1.8       | **GNOME Display Manager**                                                                       |     |     |
| 1.8.1     | Ensure GNOME Display Manager is removed (Automated)                                             |     |     |
| 1.8.2     | Ensure GDM login banner is configured (Automated)                                               |     |     |
| 1.8.3     | Ensure GDM disable-user-list option is enabled (Automated)                                      |     |     |
| 1.8.4     | Ensure GDM screen locks when the user is idle (Automated)                                       |     |     |
| 1.8.5     | Ensure GDM screen locks cannot be overridden (Automated)                                        |     |     |
| 1.8.6     | Ensure GDM automatic mounting of removable media is disabled (Automated)                        |     |     |
| 1.8.7     | Ensure GDM disabling automatic mounting of removable media is not overridden (Automated)        |     |     |
| 1.8.8     | Ensure GDM autorun-never is enabled (Automated)                                                 |     |     |
| 1.8.9     | Ensure GDM autorun-never is not overridden (Automated)                                          |     |     |
| 1.8.10    | Ensure XDCMP is not enabled (Automated)                                                         |     |     |
| 1.9       | Ensure updates, patches, and additional security software are installed (Manual)                |     |     |
| 2         | **Services**                                                                                    |     |     |
| 2.1       | **Configure Time Synchronization**                                                              |     |     |
| 2.1.1     | **Ensure time synchronization is in use**                                                       |     |     |
| 2.1.1.1   | Ensure a single time synchronization daemon is in use (Automated)                               |     |     |
| 2.1.2     | **Configure chrony**                                                                            |     |     |
| 2.1.2.1   | Ensure chrony is configured with authorized timeserver (Manual)                                 |     |     |
| 2.1.2.2   | Ensure chrony is running as user \_chrony (Automated)                                           |     |     |
| 2.1.2.3   | Ensure chrony is enabled and running (Automated)                                                |     |     |
| 2.1.3     | **Configure systemd-timesyncd**                                                                 |     |     |
| 2.1.3.1   | Ensure systemd-timesyncd configured with authorized timeserver (Manual)                         |     |     |
| 2.1.3.2   | Ensure systemd-timesyncd is enabled and running (Automated)                                     |     |     |
| 2.1.4     | **Configure ntp**                                                                               |     |     |
| 2.1.4.1   | Ensure ntp access control is configured (Automated)                                             |     |     |
| 2.1.4.2   | Ensure ntp is configured with authorized timeserver (Manual)                                    |     |     |
| 2.1.4.3   | Ensure ntp is running as user ntp (Automated)                                                   |     |     |
| 2.1.4.4   | Ensure ntp is enabled and running (Automated)                                                   |     |     |
| 2.2       | **Special Purpose Services**                                                                    |     |     |
| 2.2.1     | Ensure X Window System is not installed (Automated)                                             |     |     |
| 2.2.2     | Ensure Avahi Server is not installed (Automated)                                                |     |     |
| 2.2.3     | Ensure CUPS is not installed (Automated)                                                        |     |     |
| 2.2.4     | Ensure DHCP Server is not installed (Automated)                                                 |     |     |
| 2.2.5     | Ensure LDAP server is not installed (Automated)                                                 |     |     |
| 2.2.6     | Ensure NFS is not installed (Automated)                                                         |     |     |
| 2.2.7     | Ensure DNS Server is not installed (Automated)                                                  |     |     |
| 2.2.8     | Ensure FTP Server is not installed (Automated)                                                  |     |     |
| 2.2.9     | Ensure HTTP server is not installed (Automated)                                                 |     |     |
| 2.2.10    | Ensure IMAP and POP3 server are not installed (Automated)                                       |     |     |
| 2.2.11    | Ensure Samba is not installed (Automated)                                                       |     |     |
| 2.2.12    | Ensure HTTP Proxy Server is not installed (Automated)                                           |     |     |
| 2.2.13    | Ensure SNMP Server is not installed (Automated)                                                 |     |     |
| 2.2.14    | Ensure NIS Server is not installed (Automated)                                                  |     |     |
| 2.2.15    | Ensure mail transfer agent is configured for local-only mode (Automated)                        |     |     |
| 2.2.16    | Ensure rsync service is either not installed or masked (Automated)                              |     |     |
| 2.3       | **Service Clients**                                                                             |     |     |
| 2.3.1     | Ensure NIS Client is not installed (Automated)                                                  |     |     |
| 2.3.2     | Ensure rsh client is not installed (Automated)                                                  |     |     |
| 2.3.3     | Ensure talk client is not installed (Automated)                                                 |     |     |
| 2.3.4     | Ensure telnet client is not installed (Automated)                                               |     |     |
| 2.3.5     | Ensure LDAP client is not installed (Automated)                                                 |     |     |
| 2.3.6     | Ensure RPC is not installed (Automated)                                                         |     |     |
| 2.4       | Ensure nonessential services are removed or masked (Manual)                                     |     |     |
| 3         | **Network Configuration**                                                                       |     |     |
| 3.1       | **Disable unused network protocols and devices**                                                |     |     |
| 3.1.1     | Ensure system is checked to determine if IPv6 is enabled (Manual)                               |     |     |
| 3.1.2     | Ensure wireless interfaces are disabled (Automated)                                             |     |     |
| 3.2       | **Network Parameters (Host Only)**                                                              |     |     |
| 3.2.1     | Ensure packet redirect sending is disabled (Automated)                                          |     |     |
| 3.2.2     | Ensure IP forwarding is disabled (Automated)                                                    |     |     |
| 3.3       | **Network Parameters (Host and Router)**                                                        |     |     |
| 3.3.1     | Ensure source routed packets are not accepted (Automated)                                       |     |     |
| 3.3.2     | Ensure ICMP redirects are not accepted (Automated)                                              |     |     |
| 3.3.3     | Ensure secure ICMP redirects are not accepted (Automated)                                       |     |     |
| 3.3.4     | Ensure suspicious packets are logged (Automated)                                                |     |     |
| 3.3.5     | Ensure broadcast ICMP requests are ignored (Automated)                                          |     |     |
| 3.3.6     | Ensure bogus ICMP responses are ignored (Automated)                                             |     |     |
| 3.3.7     | Ensure Reverse Path Filtering is enabled (Automated)                                            |     |     |
| 3.3.8     | Ensure TCP SYN Cookies is enabled (Automated)                                                   |     |     |
| 3.3.9     | Ensure IPv6 router advertisements are not accepted (Automated)                                  |     |     |
| 3.4       | **Uncommon Network Protocols**                                                                  |     |     |
| 3.4.1     | Ensure DCCP is disabled (Automated)                                                             |     |     |
| 3.4.2     | Ensure SCTP is disabled (Automated)                                                             |     |     |
| 3.4.3     | Ensure RDS is disabled (Automated)                                                              |     |     |
| 3.4.4     | Ensure TIPC is disabled (Automated)                                                             |     |     |
| 3.5       | **Firewall Configuration**                                                                      |     |     |
| 3.5.1     | **Configure UncomplicatedFirewall**                                                             |     |     |
| 3.5.1.1   | Ensure ufw is installed (Automated)                                                             |     |     |
| 3.5.1.2   | Ensure iptables-persistent is not installed with ufw (Automated)                                |     |     |
| 3.5.1.3   | Ensure ufw service is enabled (Automated)                                                       |     |     |
| 3.5.1.4   | Ensure ufw loopback traffic is configured (Automated)                                           |     |     |
| 3.5.1.5   | Ensure ufw outbound connections are configured (Manual)                                         |     |     |
| 3.5.1.6   | Ensure ufw firewall rules exist for all open ports (Automated)                                  |     |     |
| 3.5.1.7   | Ensure ufw default deny firewall policy (Automated)                                             |     |     |
| 3.5.2     | **Configure nftables**                                                                          |     |     |
| 3.5.2.1   | Ensure nftables is installed (Automated)                                                        |     |     |
| 3.5.2.2   | Ensure ufw is uninstalled or disabled with nftables (Automated)                                 |     |     |
| 3.5.2.3   | Ensure iptables are flushed with nftables (Manual)                                              |     |     |
| 3.5.2.4   | Ensure a nftables table exists (Automated)                                                      |     |     |
| 3.5.2.5   | Ensure nftables base chains exist (Automated)                                                   |     |     |
| 3.5.2.6   | Ensure nftables loopback traffic is configured (Automated)                                      |     |     |
| 3.5.2.7   | Ensure nftables outbound and established connections are configured (Manual)                    |     |     |
| 3.5.2.8   | Ensure nftables default deny firewall policy (Automated)                                        |     |     |
| 3.5.2.9   | Ensure nftables service is enabled (Automated)                                                  |     |     |
| 3.5.2.10  | Ensure nftables rules are permanent (Automated)                                                 |     |     |
| 3.5.3     | **Configure iptables**                                                                          |     |     |
| 3.5.3.1   | **Configure iptables software**                                                                 |     |     |
| 3.5.3.1.1 | Ensure iptables packages are installed (Automated)                                              |     |     |
| 3.5.3.1.2 | Ensure nftables is not installed with iptables (Automated)                                      |     |     |
| 3.5.3.1.3 | Ensure ufw is uninstalled or disabled with iptables (Automated)                                 |     |     |
| 3.5.3.2   | **Configure IPv4 iptables**                                                                     |     |     |
| 3.5.3.2.1 | Ensure iptables default deny firewall policy (Automated)                                        |     |     |
| 3.5.3.2.2 | Ensure iptables loopback traffic is configured (Automated)                                      |     |     |
| 3.5.3.2.3 | Ensure iptables outbound and established connections are configured (Manual)                    |     |     |
| 3.5.3.2.4 | Ensure iptables firewall rules exist for all open ports (Automated)                             |     |     |
| 3.5.3.3   | **Configure IPv6 ip6tables**                                                                    |     |     |
| 3.5.3.3.1 | Ensure ip6tables default deny firewall policy (Automated)                                       |     |     |
| 3.5.3.3.2 | Ensure ip6tables loopback traffic is configured (Automated)                                     |     |     |
| 3.5.3.3.3 | Ensure ip6tables outbound and established connections are configured (Manual)                   |     |     |
| 3.5.3.3.4 | Ensure ip6tables firewall rules exist for all open ports (Automated)                            |     |     |
| 4         | **Logging and Auditing**                                                                        |     |     |
| 4.1       | **Configure System Accounting (auditd)**                                                        |     |     |
| 4.1.1     | **Ensure auditing is enabled**                                                                  |     |     |
| 4.1.1.1   | Ensure auditd is installed (Automated)                                                          |     |     |
| 4.1.1.2   | Ensure auditd service is enabled and active (Automated)                                         |     |     |
| 4.1.1.3   | Ensure auditing for processes that start prior to auditd is enabled (Automated)                 |     |     |
| 4.1.1.4   | Ensure audit_backlog_limit is sufficient (Automated)                                            |     |     |
| 4.1.2     | **Configure Data Retention**                                                                    |     |     |
| 4.1.2.1   | Ensure audit log storage size is configured (Automated)                                         |     |     |
| 4.1.2.2   | Ensure audit logs are not automatically deleted (Automated)                                     |     |     |
| 4.1.2.3   | Ensure system is disabled when audit logs are full (Automated)                                  |     |     |
| 4.1.3     | **Configure auditd rules**                                                                      |     |     |
| 4.1.3.1   | Ensure changes to system administration scope (sudoers) is collected (Automated)                |     |     |
| 4.1.3.2   | Ensure actions as another user are always logged (Automated)                                    |     |     |
| 4.1.3.3   | Ensure events that modify the sudo log file are collected (Automated)                           |     |     |
| 4.1.3.4   | Ensure events that modify date and time information are collected (Automated)                   |     |     |
| 4.1.3.5   | Ensure events that modify the system's network environment are collected (Automated)            |     |     |
| 4.1.3.6   | Ensure use of privileged commands are collected (Automated)                                     |     |     |
| 4.1.3.7   | Ensure unsuccessful file access attempts are collected (Automated)                              |     |     |
| 4.1.3.8   | Ensure events that modify user/group information are collected (Automated)                      |     |     |
| 4.1.3.9   | Ensure discretionary access control permission modification events are collected (Automated)    |     |     |
| 4.1.3.10  | Ensure successful file system mounts are collected (Automated)                                  |     |     |
| 4.1.3.11  | Ensure session initiation information is collected (Automated)                                  |     |     |
| 4.1.3.12  | Ensure login and logout events are collected (Automated)                                        |     |     |
| 4.1.3.13  | Ensure file deletion events by users are collected (Automated)                                  |     |     |
| 4.1.3.14  | Ensure events that modify the system's Mandatory Access Controls are collected (Automated)      |     |     |
| 4.1.3.15  | Ensure successful and unsuccessful attempts to use the chcon command are recorded (Automated)   |     |     |
| 4.1.3.16  | Ensure successful and unsuccessful attempts to use the setfacl command are recorded (Automated) |     |     |
| 4.1.3.17  | Ensure successful and unsuccessful attempts to use the chacl command are recorded (Automated)   |     |     |
| 4.1.3.18  | Ensure successful and unsuccessful attempts to use the usermod command are recorded (Automated) |     |     |
| 4.1.3.19  | Ensure kernel module loading unloading and modification is collected (Automated)                |     |     |
| 4.1.3.20  | Ensure the audit configuration is immutable (Automated)                                         |     |     |
| 4.1.3.21  | Ensure the running and on disk configuration is the same (Manual)                               |     |     |
| 4.1.4     | **Configure auditd file access**                                                                |     |     |
| 4.1.4.1   | Ensure audit log files are mode 0640 or less permissive (Automated)                             |     |     |
| 4.1.4.2   | Ensure only authorized users own audit log files (Automated)                                    |     |     |
| 4.1.4.3   | Ensure only authorized groups are assigned ownership of audit log files (Automated)             |     |     |
| 4.1.4.4   | Ensure the audit log directory is 0750 or more restrictive (Automated)                          |     |     |
| 4.1.4.5   | Ensure audit configuration files are 640 or more restrictive (Automated)                        |     |     |
| 4.1.4.6   | Ensure audit configuration files are owned by root (Automated)                                  |     |     |
| 4.1.4.7   | Ensure audit configuration files belong to group root (Automated)                               |     |     |
| 4.1.4.8   | Ensure audit tools are 755 or more restrictive (Automated)                                      |     |     |
| 4.1.4.9   | Ensure audit tools are owned by root (Automated)                                                |     |     |
| 4.1.4.10  | Ensure audit tools belong to group root (Automated)                                             |     |     |
| 4.1.4.11  | Ensure cryptographic mechanisms are used to protect the integrity of audit tools (Automated)    |     |     |
| 4.2       | **Configure Logging**                                                                           |     |     |
| 4.2.1     | **Configure journald**                                                                          |     |     |
| 4.2.1.1   | **Ensure journald is configured to send logs to a remote log host**                             |     |     |
| 4.2.1.1.1 | Ensure systemd-journal-remote is installed (Automated)                                          |     |     |
| 4.2.1.1.2 | Ensure systemd-journal-remote is configured (Manual)                                            |     |     |
| 4.2.1.1.3 | Ensure systemd-journal-remote is enabled (Manual)                                               |     |     |
| 4.2.1.1.4 | Ensure journald is not configured to recieve logs from a remote client (Automated)              |     |     |
| 4.2.1.2   | Ensure journald service is enabled (Automated)                                                  |     |     |
| 4.2.1.3   | Ensure journald is configured to compress large log files (Automated)                           |     |     |
| 4.2.1.4   | Ensure journald is configured to write logfiles to persistent disk (Automated)                  |     |     |
| 4.2.1.5   | Ensure journald is not configured to send logs to rsyslog (Manual)                              |     |     |
| 4.2.1.6   | Ensure journald log rotation is configured per site policy (Manual)                             |     |     |
| 4.2.1.7   | Ensure journald default file permissions configured (Manual)                                    |     |     |
| 4.2.2     | **Configure rsyslog**                                                                           |     |     |
| 4.2.2.1   | Ensure rsyslog is installed (Automated)                                                         |     |     |
| 4.2.2.2   | Ensure rsyslog service is enabled (Automated)                                                   |     |     |
| 4.2.2.3   | Ensure journald is configured to send logs to rsyslog (Manual)                                  |     |     |
| 4.2.2.4   | Ensure rsyslog default file permissions are configured (Automated)                              |     |     |
| 4.2.2.5   | Ensure logging is configured (Manual)                                                           |     |     |
| 4.2.2.6   | Ensure rsyslog is configured to send logs to a remote log host (Manual)                         |     |     |
| 4.2.2.7   | Ensure rsyslog is not configured to receive logs from a remote client (Automated)               |     |     |
| 4.2.3     | Ensure all logfiles have appropriate permissions and ownership (Automated)                      |     |     |
| 5         | **Access, Authentication and Authorization**                                                    |     |     |
| 5.1       | **Configure time-based job schedulers**                                                         |     |     |
| 5.1.1     | Ensure cron daemon is enabled and running (Automated)                                           |     |     |
| 5.1.2     | Ensure permissions on /etc/crontab are configured (Automated)                                   |     |     |
| 5.1.3     | Ensure permissions on /etc/cron.hourly are configured (Automated)                               |     |     |
| 5.1.4     | Ensure permissions on /etc/cron.daily are configured (Automated)                                |     |     |
| 5.1.5     | Ensure permissions on /etc/cron.weekly are configured (Automated)                               |     |     |
| 5.1.6     | Ensure permissions on /etc/cron.monthly are configured (Automated)                              |     |     |
| 5.1.7     | Ensure permissions on /etc/cron.d are configured (Automated)                                    |     |     |
| 5.1.8     | Ensure cron is restricted to authorized users (Automated)                                       |     |     |
| 5.1.9     | Ensure at is restricted to authorized users (Automated)                                         |     |     |
| 5.2       | **Configure SSH Server**                                                                        |     |     |
| 5.2.1     | Ensure permissions on /etc/ssh/sshd_config are configured (Automated)                           |     |     |
| 5.2.2     | Ensure permissions on SSH private host key files are configured (Automated)                     |     |     |
| 5.2.3     | Ensure permissions on SSH public host key files are configured (Automated)                      |     |     |
| 5.2.4     | Ensure SSH access is limited (Automated)                                                        |     |     |
| 5.2.5     | Ensure SSH LogLevel is appropriate (Automated)                                                  |     |     |
| 5.2.6     | Ensure SSH PAM is enabled (Automated)                                                           |     |     |
| 5.2.7     | Ensure SSH root login is disabled (Automated)                                                   |     |     |
| 5.2.8     | Ensure SSH HostbasedAuthentication is disabled (Automated)                                      |     |     |
| 5.2.9     | Ensure SSH PermitEmptyPasswords is disabled (Automated)                                         |     |     |
| 5.2.10    | Ensure SSH PermitUserEnvironment is disabled (Automated)                                        |     |     |
| 5.2.11    | Ensure SSH IgnoreRhosts is enabled (Automated)                                                  |     |     |
| 5.2.12    | Ensure SSH X11 forwarding is disabled (Automated)                                               |     |     |
| 5.2.13    | Ensure only strong Ciphers are used (Automated)                                                 |     |     |
| 5.2.14    | Ensure only strong MAC algorithms are used (Automated)                                          |     |     |
| 5.2.15    | Ensure only strong Key Exchange algorithms are used (Automated)                                 |     |     |
| 5.2.16    | Ensure SSH AllowTcpForwarding is disabled (Automated)                                           |     |     |
| 5.2.17    | Ensure SSH warning banner is configured (Automated)                                             |     |     |
| 5.2.18    | Ensure SSH MaxAuthTries is set to 4 or less (Automated)                                         |     |     |
| 5.2.19    | Ensure SSH MaxStartups is configured (Automated)                                                |     |     |
| 5.2.20    | Ensure SSH MaxSessions is set to 10 or less (Automated)                                         |     |     |
| 5.2.21    | Ensure SSH LoginGraceTime is set to one minute or less (Automated)                              |     |     |
| 5.2.22    | Ensure SSH Idle Timeout Interval is configured (Automated)                                      |     |     |
| 5.3       | **Configure privilege escalation**                                                              |     |     |
| 5.3.1     | Ensure sudo is installed (Automated)                                                            |     |     |
| 5.3.2     | Ensure sudo commands use pty (Automated)                                                        |     |     |
| 5.3.3     | Ensure sudo log file exists (Automated)                                                         |     |     |
| 5.3.4     | Ensure users must provide password for privilege escalation (Automated)                         |     |     |
| 5.3.5     | Ensure re-authentication for privilege escalation is not disabled globally (Automated)          |     |     |
| 5.3.6     | Ensure sudo authentication timeout is configured correctly (Automated)                          |     |     |
| 5.3.7     | Ensure access to the su command is restricted (Automated)                                       |     |     |
| 5.4       | **Configure PAM**                                                                               |     |     |
| 5.4.1     | Ensure password creation requirements are configured (Automated)                                |     |     |
| 5.4.2     | Ensure lockout for failed password attempts is configured (Automated)                           |     |     |
| 5.4.3     | Ensure password reuse is limited (Automated)                                                    |     |     |
| 5.4.4     | Ensure password hashing algorithm is up to date with the latest standards (Automated)           |     |     |
| 5.4.5     | Ensure all current passwords uses the configured hashing algorithm (Manual)                     |     |     |
| 5.5       | **User Accounts and Environment**                                                               |     |     |
| 5.5.1     | **Set Shadow Password Suite Parameters**                                                        |     |     |
| 5.5.1.1   | Ensure minimum days between password changes is configured (Automated)                          |     |     |
| 5.5.1.2   | Ensure password expiration is 365 days or less (Automated)                                      |     |     |
| 5.5.1.3   | Ensure password expiration warning days is 7 or more (Automated)                                |     |     |
| 5.5.1.4   | Ensure inactive password lock is 30 days or less (Automated)                                    |     |     |
| 5.5.1.5   | Ensure all users last password change date is in the past (Automated)                           |     |     |
| 5.5.2     | Ensure system accounts are secured (Automated)                                                  |     |     |
| 5.5.3     | Ensure default group for the root account is GID 0 (Automated)                                  |     |     |
| 5.5.4     | Ensure default user umask is 027 or more restrictive (Automated)                                |     |     |
| 5.5.5     | Ensure default user shell timeout is 900 seconds or less (Automated)                            |     |     |
| 6         | **System Maintenance**                                                                          |     |     |
| 6.1       | **System File Permissions**                                                                     |     |     |
| 6.1.1     | Ensure permissions on /etc/passwd are configured (Automated)                                    |     |     |
| 6.1.2     | Ensure permissions on /etc/passwd- are configured (Automated)                                   |     |     |
| 6.1.3     | Ensure permissions on /etc/group are configured (Automated)                                     |     |     |
| 6.1.4     | Ensure permissions on /etc/group- are configured (Automated)                                    |     |     |
| 6.1.5     | Ensure permissions on /etc/shadow are configured (Automated)                                    |     |     |
| 6.1.6     | Ensure permissions on /etc/shadow- are configured (Automated)                                   |     |     |
| 6.1.7     | Ensure permissions on /etc/gshadow are configured (Automated)                                   |     |     |
| 6.1.8     | Ensure permissions on /etc/gshadow- are configured (Automated)                                  |     |     |
| 6.1.9     | Ensure no world writable files exist (Automated)                                                |     |     |
| 6.1.10    | Ensure no unowned files or directories exist (Automated)                                        |     |     |
| 6.1.11    | Ensure no ungrouped files or directories exist (Automated)                                      |     |     |
| 6.1.12    | Audit SUID executables (Manual)                                                                 |     |     |
| 6.1.13    | Audit SGID executables (Manual)                                                                 |     |     |
| 6.2       | **Local User and Group Settings**                                                               |     |     |
| 6.2.1     | Ensure accounts in /etc/passwd use shadowed passwords (Automated)                               |     |     |
| 6.2.2     | Ensure /etc/shadow password fields are not empty (Automated)                                    |     |     |
| 6.2.3     | Ensure all groups in /etc/passwd exist in /etc/group (Automated)                                |     |     |
| 6.2.4     | Ensure shadow group is empty (Automated)                                                        |     |     |
| 6.2.5     | Ensure no duplicate UIDs exist (Automated)                                                      |     |     |
| 6.2.6     | Ensure no duplicate GIDs exist (Automated)                                                      |     |     |
| 6.2.7     | Ensure no duplicate user names exist (Automated)                                                |     |     |
| 6.2.8     | Ensure no duplicate group names exist (Automated)                                               |     |     |
| 6.2.9     | Ensure root PATH Integrity (Automated)                                                          |     |     |
| 6.2.10    | Ensure root is the only UID 0 account (Automated)                                               |     |     |
| 6.2.11    | Ensure local interactive user home directories exist (Automated)                                |     |     |
| 6.2.12    | Ensure local interactive users own their home directories (Automated)                           |     |     |
| 6.2.13    | Ensure local interactive user home directories are mode 750 or more restrictive (Automated)     |     |     |
| 6.2.14    | Ensure no local interactive user has .netrc files (Automated)                                   |     |     |
| 6.2.15    | Ensure no local interactive user has .forward files (Automated)                                 |     |     |
| 6.2.16    | Ensure no local interactive user has .rhosts files (Automated)                                  |     |     |
| 6.2.17    | **Ensure local interactive user dot files are not group or world writable (Automated)**         |     |     |

## License

MIT
