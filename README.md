# CIS - Ubuntu 22.04

[![Ansible Lint](https://github.com/MVladislav/ansible-cis-ubuntu-2204/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/MVladislav/ansible-cis-ubuntu-2204/actions/workflows/ansible-lint.yml)
[![Ansible Molecule Test](https://github.com/MVladislav/ansible-cis-ubuntu-2204/actions/workflows/ci.yml/badge.svg)](https://github.com/MVladislav/ansible-cis-ubuntu-2204/actions/workflows/ci.yml)

- [CIS - Ubuntu 22.04](#cis---ubuntu-2204)
  - [Disclaimer](#disclaimer)
  - [Notes](#notes)
  - [Requirements](#requirements)
  - [Role Variables](#role-variables)
    - [Run only setup per section](#run-only-setup-per-section)
    - [Variables not included in CIS as additional extend](#variables-not-included-in-cis-as-additional-extend)
    - [Variables which are recommended by CIS, but disable in this role by default](#variables-which-are-recommended-by-cis-but-disable-in-this-role-by-default)
    - [Variable for special usage between server and client](#variable-for-special-usage-between-server-and-client)
    - [Variables to check and set for own purpose](#variables-to-check-and-set-for-own-purpose)
    - [Variable rules implemented, but only print information for manual check](#variable-rules-implemented-but-only-print-information-for-manual-check)
  - [Dependencies](#dependencies)
  - [Example Playbook](#example-playbook)
  - [Definitions](#definitions)
    - [Profile](#profile)
  - [CIS - List of Recommendations](#cis---list-of-recommendations)
  - [License](#license)
  - [Resources](#resources)

---

This Ansible role is designed to configure **Ubuntu 22.04** to **comply** with the **CIS Ubuntu Linux Benchmark v2.0.0**. \
It automates the application of hardening recommendations to enhance system security. \
While this role can help mitigate common security risks, it is essential to tailor the configurations to your specific environment.

Based on **[CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0](https://downloads.cisecurity.org/#/)**.

Tested with:

- Ubuntu 22.04
- Ubuntu 23.04

## Disclaimer

> [!DANGER]
>
> This role makes **significant changes to your system** that **could break functionality**. \
> This is not an auditing tool but rather a remediation tool to be used after an audit has been conducted. \
> While based on industry-standard security guidelines (CIS), it is recommended to review these changes, especially when applied to existing systems.

This role was **developed against a clean install** of the Operating System. \
If you are **implementing to an existing system** please **review thoroughly** this role for any **site specific changes** before applying them to production systems.

Strongly advise testing in a staging environment before applying in production.

## Notes

- section :: 6.2.1.2 **Configure systemd-journal-remote**
  - is configured, but not in deep tested _(default not setup with remote logging)_
- section :: 4.2 **Configure nftables**
  - is configured, but not in deep tested _(default ufw is used from section 4.1)_
- section :: 4.3 **Configure iptables**
  - is configured, but not in deep tested _(default ufw is used from section 4.1)_
- section :: 5.3 **Pluggable Authentication Modules** :: 5.4 **User Accounts and Environment**
  - could be tested deeper, base tests are performed and for secure only used for fresh os install

## Requirements

Before using this role, ensure that your system meets the following requirements:

- Python >= 3.12
- Ansible >= 2.16
- SSH access to the target machine.

Install required tools and libraries:

```sh
$sudo apt install python3 python3-pip sshpass
$python3 -m pip install ansible ansible-lint yamllint --break-system-packages
```

For run **tests** with **molecule**, you need also to **install**:

```sh
$python3 -m pip install molecule molecule-plugins[docker] --break-system-packages
```

## Role Variables

### Run only setup per section

> _Default all section are active and will performed_

```yaml
cis_ubuntu2204_section1: true
cis_ubuntu2204_section2: true
cis_ubuntu2204_section3: true
cis_ubuntu2204_section4: true
cis_ubuntu2204_section5: true
cis_ubuntu2204_section6: true
cis_ubuntu2204_section7: true
```

### Variables not included in CIS as additional extend

```yaml
# Extend the default sshd_config hardening to remove unnecessary comments and empty lines.
# 'true' by default.
cis_ubuntu2204_rule_5_1_0: true

# Extend the default sshd_config hardening, which not defined within CIS,
# by include more configuration based on https://infosec.mozilla.org/guidelines/openssh.html.
# 'true' by default, but only runs if
#  - 'cis_ubuntu2204_rule_5_1_24_ssh_pub_key' is defined or
#  - 'cis_ubuntu2204_ssh_password_authentication' is equals 'yes'
cis_ubuntu2204_rule_5_1_23: true

# Avoid SSH login lockout by specifying the user and public key for SSH access.
# Lockout will happen when 'cis_ubuntu2204_rule_5_1_19', 'cis_ubuntu2204_rule_5_1_20' and 'cis_ubuntu2204_rule_5_1_23' are used.
# Ensure that a valid SSH public key is provided, or set this rule to false.
# 'true' by default, but not executed when 'cis_ubuntu2204_rule_5_1_24_ssh_pub_key' is not defined.
cis_ubuntu2204_rule_5_1_24: true
cis_ubuntu2204_rule_5_1_24_ssh_user: "{{ ansible_user }}"
cis_ubuntu2204_rule_5_1_24_ssh_pub_key: "<ADD_PUB_KEY>"

# Set for auditd inside auditd.conf the key for 'log_file' to be save in upcoming configurations
# 'true' by default.
cis_ubuntu2204_rule_6_3_4_0: true
```

### Variables which are recommended by CIS, but disable in this role by default

> _change default configured values, to be CIS recommended if needed_

```yaml
# Ensure all AppArmor Profiles are complain
# NOTE: will perform Profiles into complain mode
cis_ubuntu2204_rule_1_3_1_3: true
# Ensure all AppArmor Profiles are enforcing
# NOTE: will perform Profiles into enforcing mode
cis_ubuntu2204_rule_1_3_1_4: false

# Ensure bootloader password is set
cis_ubuntu2204_set_boot_pass: false
cis_ubuntu2204_disable_boot_pass: true

# Ensure wireless interfaces are not available
cis_ubuntu2204_rule_3_1_2: false

# Active journal send logs to a remote log host
# do not forget set related variables 'cis_ubuntu2204_set_journal_upload_*'
cis_ubuntu2204_set_journal_upload: false
cis_ubuntu2204_set_journal_upload_url: <SET_REMOTE_URL>
```

### Variable for special usage between server and client

> _Check services which will removed or disabled,
> which maybe needed, for example especial for client usage_

```yaml
# will disable USB storage, if USB storage is needed set to 'false'
cis_ubuntu2204_rule_1_1_1_9: true

# will remove bluetooth service, if bluetooth is needed set to 'false'
cis_ubuntu2204_rule_3_1_3: true
cis_ubuntu2204_rule_3_1_3_remove: true

# will disable auto mount, if auto mount is needed set to 'true'
cis_ubuntu2204_allow_autofs: false

# will purge gdm/gui, if gui is needed set to 'true'
# if 'true' is set, recommended configs will perform in rules 1.7.2 - 1.7.10
cis_ubuntu2204_allow_gdm_gui: false

# will purge printer service, if printer service is need set to 'true'
cis_ubuntu2204_allow_cups: false

# will disable ipv6 complete, if ipv6 is needed set to 'true'
cis_ubuntu2204_required_ipv6: false

# will install and config AIDE, if not needed set to 'false'
cis_ubuntu2204_install_aide: true
cis_ubuntu2204_config_aide: true
```

### Variables to check and set for own purpose

```yaml
# With rule 'cis_ubuntu2204_rule_1_1_1_10' multiple filesystem will be disabled if they are vulnerable
# if you know you would need filesystem, from vulnerable list 'cis_ubuntu2204_fs_known_vulnerable', which not listed below,
# update the list as needed.
# By default the tasks will check which filesystem are current in use and will not disable them, also if not listed in 'cis_ubuntu2204_fs_ignored'
cis_ubuntu2204_fs_ignored: # these filesystem won't be disabled
  - xfs
  - vfat
  - ext2
  - ext3
  - ext4

# list will be auto gathered if unset (cis_ubuntu2204_rule_1_3_1_3)
# you can define profiles by your own, which should be set as complain profile
cis_ubuntu2204_apparmor_update_to_complain_profiles: []
# list will be auto gathered if unset (cis_ubuntu2204_rule_1_3_1_4)
# you can define profiles by your own, which should be set as enforce profile
cis_ubuntu2204_apparmor_update_to_enforce_profiles: []

# choose time synchronization (cis_ubuntu2204_rule_2_3_1_1)
cis_ubuntu2204_time_synchronization_service: chrony # chrony | systemd-timesyncd
cis_ubuntu2204_time_synchronization_time_server:
  - uri: time.cloudflare.com
    config: iburst
  - uri: ntp.ubuntu.com
    config: iburst

# cron allow users  (cis_ubuntu2204_rule_2_4_1_9)
cis_ubuntu2204_cron_allow_users:
  - root
# at allow users  (cis_ubuntu2204_rule_2_4_2_1)
cis_ubuntu2204_at_allow_users:
  - root

# choose firewall (cis_ubuntu2204_rule_4_*)
cis_ubuntu2204_firewall: ufw # ufw | nftables | iptables

# allows/denies for users/groups (4 possible variables can be used/activated)
# put 'null' or list of users (comma separated user list)
# default set to add ssh as group to allow use ssh (do not forget add group to user)
#cis_ubuntu2204_ssh_allow_users: root,user
#cis_ubuntu2204_ssh_allow_groups: root,ssh
#cis_ubuntu2204_ssh_deny_users: root,user
#cis_ubuntu2204_ssh_deny_groups: root,ssh

cis_ubuntu2204_ssh_permit_root_login: "no"
cis_ubuntu2204_ssh_port: 22
cis_ubuntu2204_ssh_authentication_methods: "publickey"
cis_ubuntu2204_ssh_password_authentication: "no"

# pw quality policies
cis_ubuntu2204_faillock_deny: 5
cis_ubuntu2204_faillock_unlock_time: 900
cis_ubuntu2204_faillock_minlen: 14
cis_ubuntu2204_password_complexity:
  - key: "minclass"
    value: "3"
  - key: "dcredit"
    value: "-1"
  - key: "ucredit"
    value: "-1"
  - key: "ocredit"
    value: "-1"
  - key: "lcredit"
    value: "-1"

# AIDE cron settings (cis_ubuntu2204_rule_6_1_2)
cis_ubuntu2204_aide_cron:
  cron_user: root
  cron_file: aide
  aide_job: "/usr/bin/aide.wrapper --config /etc/aide/aide.conf --check"
  aide_minute: 0
  aide_hour: 5
  aide_day: "*"
  aide_month: "*"
  aide_weekday: "*"

# journald log file rotation (cis_ubuntu2204_rule_6_2_1_1_3)
cis_ubuntu2204_journald_system_max_use: 4G
cis_ubuntu2204_journald_system_keep_free: 8G
cis_ubuntu2204_journald_runtime_max_use: 256M
cis_ubuntu2204_journald_runtime_keep_free: 512M
cis_ubuntu2204_journald_max_file_sec: 1month
```

### Variable rules implemented, but only print information for manual check

```yaml
# SECTION1 | 1.2.1.1 | Ensure GPG keys are configured
cis_ubuntu2204_rule_1_2_1_1: true
# SECTION1 | 1.2.1.2 | Ensure package manager repositories are configured
cis_ubuntu2204_rule_1_2_1_2: true

# SECTION2 | 2.1.22 | Ensure only approved services are listening on a network interface
cis_ubuntu2204_rule_2_1_22: true

# SECTION5 | 5.4.2.1 | Ensure root is the only UID 0 account
cis_ubuntu2204_rule_5_4_2_1: true
# SECTION5 | 5.4.2.2 | Ensure root is the only GID 0 account
cis_ubuntu2204_rule_5_4_2_2: true
# SECTION5 | 5.4.2.3 | Ensure group root is the only GID 0 group
cis_ubuntu2204_rule_5_4_2_3: true
# SECTION5 | 5.4.2.5 | Ensure root path integrity
cis_ubuntu2204_rule_5_4_2_5: true
# SECTION5 | 5.4.2.7 | Ensure system accounts do not have a valid login shell
cis_ubuntu2204_rule_5_4_2_7: true

# SECTION7 | 7.1.12 | Ensure no files or directories without an owner and a group exist
cis_ubuntu2204_rule_7_1_12: true
# SECTION7 | 7.1.13 | Ensure SUID and SGID files are reviewed
cis_ubuntu2204_rule_7_1_13: true

# SECTION7 | 7.2.3 | Ensure all groups in /etc/passwd exist in /etc/group
cis_ubuntu2204_rule_7_2_3: true
# SECTION7 | 7.2.5 | Ensure no duplicate UIDs exist
cis_ubuntu2204_rule_7_2_5: true
# SECTION7 | 7.2.6 | Ensure no duplicate GIDs exist
cis_ubuntu2204_rule_7_2_6: true
# SECTION7 | 7.2.7 | Ensure no duplicate user names exist
cis_ubuntu2204_rule_7_2_7: true
# SECTION7 | 7.2.8 | Ensure no duplicate group names exist
cis_ubuntu2204_rule_7_2_8: true
```

## Dependencies

Developed and testes with Ansible 2.16

## Example Playbook

Example usage can be found also [here](https://github.com/MVladislav/ansible-env-setup).

```yaml
- name: CIS | install on clients
  become: true
  remote_user: "{{ ansible_user }}"
  hosts:
    - clients
  roles:
    - role: ansible-cis-ubuntu-2204
      cis_ubuntu2204_section1: true
      cis_ubuntu2204_section2: true
      cis_ubuntu2204_section3: true
      cis_ubuntu2204_section4: true
      cis_ubuntu2204_section5: true
      cis_ubuntu2204_section6: true
      cis_ubuntu2204_section7: true
      # -------------------------
      cis_ubuntu2204_rule_1_1_1_7: false # squashfs - IMPACT: Snap packages utilizes squashfs as a compressed filesystem, disabling squashfs will cause Snap packages to fail.
      # -------------------------
      cis_ubuntu2204_rule_5_1_24: true
      cis_ubuntu2204_rule_5_1_24_ssh_user: "{{ ansible_user }}"
      cis_ubuntu2204_rule_5_1_24_ssh_pub_key: "<ADD_PUB_KEY>"
      # -------------------------
      cis_ubuntu2204_rule_1_3_1_3: true # AppArmor complain mode
      cis_ubuntu2204_rule_1_3_1_4: false # AppArmor enforce mode
      # -------------------------
      cis_ubuntu2204_set_boot_pass: false # bootloader password (disabled)
      cis_ubuntu2204_disable_boot_pass: true # bootloader password (disabled with cis_ubuntu2204_set_boot_pass)
      # -------------------------
      cis_ubuntu2204_rule_3_1_3: false # bluetooth service
      cis_ubuntu2204_rule_3_1_3_remove: false # bluetooth service
      # -------------------------
      cis_ubuntu2204_allow_gdm_gui: true
      cis_ubuntu2204_allow_autofs: true # Disable auto mount, set to true to allow it and not disable
      cis_ubuntu2204_rule_1_1_1_9: false # Disable USB Storage, set to false to not disable
      cis_ubuntu2204_time_synchronization_service: chrony # chrony | systemd-timesyncd
      cis_ubuntu2204_time_synchronization_time_server:
        - uri: time.cloudflare.com
          config: iburst
        - uri: ntp.ubuntu.com
          config: iburst
      cis_ubuntu2204_allow_cups: true
      # -------------------------
      cis_ubuntu2204_install_aide: false
      cis_ubuntu2204_config_aide: false
      cis_ubuntu2204_aide_cron:
        cron_user: root
        cron_file: aide
        aide_job: "/usr/bin/aide.wrapper --config /etc/aide/aide.conf --check"
        aide_minute: 0
        aide_hour: 5
        aide_day: "*"
        aide_month: "*"
        aide_weekday: "*"
      # -------------------------
      cis_ubuntu2204_journald_system_max_use: 4G
      cis_ubuntu2204_journald_system_keep_free: 8G
      cis_ubuntu2204_journald_runtime_max_use: 256M
      cis_ubuntu2204_journald_runtime_keep_free: 512M
      cis_ubuntu2204_journald_max_file_sec: 1month
      # -------------------------
      cis_ubuntu2204_required_ipv6: true
      cis_ubuntu2204_firewall: ufw
      # -------------------------
      cis_ubuntu2204_cron_allow_users:
        - root
      cis_ubuntu2204_at_allow_users:
        - root
      # -------------------------
      cis_ubuntu2204_faillock_deny: 5
      cis_ubuntu2204_faillock_unlock_time: 900
      cis_ubuntu2204_faillock_minlen: 8
      cis_ubuntu2204_password_complexity:
        - key: "minclass"
          value: "3"
        - key: "dcredit"
          value: "-1"
        - key: "ucredit"
          value: "-1"
        - key: "ocredit"
          value: "-1"
        - key: "lcredit"
          value: "-1"
```

## Definitions

### Profile

A collection of recommendations for securing a technology or a supporting platform.
Most benchmarks include at least a **Level 1** and **Level 2** Profile.
**Level 2** extends **Level 1** recommendations and is not a standalone profile.
The Profile Definitions section in the benchmark provides the definitions
as they pertain to the recommendations included for the technology.

For **Level 1** and **Level 2** and the split into **Server** and **Workstation**,
are defined by **tags** in the tasks by:

- server_l1
- server_l2
- workstation_l1
- workstation_l2

For more specific description see the **CIS pdf** file on **page 18**.

## CIS - List of Recommendations

| Key                                                  | Count |
| :--------------------------------------------------- | :---- |
| 🟢 Implemented                                       | 266   |
| 🟡 Partly Implemented or print info for manual check | 14    |
| 🔴 Not Implemented                                   | 20    |
| Total                                                | 300   |
| Coverage (Implemented/Partly vs Total)               | 93.33 |

| ID        | CIS Benchmark Recommendation Set                                                                | Yes | Y/N | No  |
| :-------- | :---------------------------------------------------------------------------------------------- | :-: | :-: | :-: |
| 1         | **Initial Setup**                                                                               |     | 🟡  |     |
| 1.1       | **Filesystem**                                                                                  |     | 🟡  |     |
| 1.1.1     | **Configure Filesystem Kernel Modules**                                                         | 🟢  |     |     |
| 1.1.1.1   | Ensure cramfs kernel module is not available (Automated)                                        | 🟢  |     |     |
| 1.1.1.2   | Ensure freevxfs kernel module is not available (Automated)                                      | 🟢  |     |     |
| 1.1.1.3   | Ensure hfs kernel module is not available (Automated)                                           | 🟢  |     |     |
| 1.1.1.4   | Ensure hfsplus kernel module is not available (Automated)                                       | 🟢  |     |     |
| 1.1.1.5   | Ensure jffs2 kernel module is not available (Automated)                                         | 🟢  |     |     |
| 1.1.1.6   | Ensure overlay kernel module is not available (Automated)                                       | 🟢  |     |     |
| 1.1.1.7   | Ensure squashfs kernel module is not available (Automated)                                      | 🟢  |     |     |
| 1.1.1.8   | Ensure udf kernel module is not available (Automated)                                           | 🟢  |     |     |
| 1.1.1.9   | Ensure usb-storage kernel module is not available (Automated)                                   | 🟢  |     |     |
| 1.1.1.10  | Ensure unused filesystems kernel modules are not available (Automated)                          | 🟢  |     |     |
| 1.1.1.11  | Ensure firewire-core kernel module is not available (Automated)                                 | 🟢  |     |     |
| 1.1.2     | **Configure Filesystem Partitions**                                                             | 🟢  |     |     |
| 1.1.2.1   | **Configure /tmp**                                                                              | 🟢  |     |     |
| 1.1.2.1.1 | Ensure /tmp is tmpfs or a separate partition (Automated)                                        | 🟢  |     |     |
| 1.1.2.1.2 | Ensure nodev option set on /tmp partition (Automated)                                           | 🟢  |     |     |
| 1.1.2.1.3 | Ensure nosuid option set on /tmp partition (Automated)                                          | 🟢  |     |     |
| 1.1.2.1.4 | Ensure noexec option set on /tmp partition (Automated)                                          | 🟢  |     |     |
| 1.1.2.2   | **Configure /dev/shm**                                                                          | 🟢  |     |     |
| 1.1.2.2.1 | Ensure /dev/shm is tmpfs or a separate partition (Automated)                                    | 🟢  |     |     |
| 1.1.2.2.2 | Ensure nodev option set on /dev/shm partition (Automated)                                       | 🟢  |     |     |
| 1.1.2.2.3 | Ensure nosuid option set on /dev/shm partition (Automated)                                      | 🟢  |     |     |
| 1.1.2.2.4 | Ensure noexec option set on /dev/shm partition (Automated)                                      | 🟢  |     |     |
| 1.1.2.3   | **Configure /home**                                                                             |     |     | 🔴  |
| 1.1.2.3.1 | Ensure separate partition exists for /home (Automated)                                          |     |     | 🔴  |
| 1.1.2.3.2 | Ensure nodev option set on /home partition (Automated)                                          |     |     | 🔴  |
| 1.1.2.3.3 | Ensure nosuid option set on /home partition (Automated)                                         |     |     | 🔴  |
| 1.1.2.4   | **Configure /var**                                                                              |     |     | 🔴  |
| 1.1.2.4.1 | Ensure separate partition exists for /var (Automated)                                           |     |     | 🔴  |
| 1.1.2.4.2 | Ensure nodev option set on /var partition (Automated)                                           |     |     | 🔴  |
| 1.1.2.4.3 | Ensure nosuid option set on /var partition (Automated)                                          |     |     | 🔴  |
| 1.1.2.5   | **Configure /var/tmp**                                                                          |     |     | 🔴  |
| 1.1.2.5.1 | Ensure separate partition exists for /var/tmp (Automated)                                       |     |     | 🔴  |
| 1.1.2.5.2 | Ensure nodev option set on /var/tmp partition (Automated)                                       |     |     | 🔴  |
| 1.1.2.5.3 | Ensure nosuid option set on /var/tmp partition (Automated)                                      |     |     | 🔴  |
| 1.1.2.5.4 | Ensure noexec option set on /var/tmp partition (Automated)                                      |     |     | 🔴  |
| 1.1.2.6   | **Configure /var/log**                                                                          |     |     | 🔴  |
| 1.1.2.6.1 | Ensure separate partition exists for /var/log (Automated)                                       |     |     | 🔴  |
| 1.1.2.6.2 | Ensure nodev option set on /var/log partition (Automated)                                       |     |     | 🔴  |
| 1.1.2.6.3 | Ensure nosuid option set on /var/log partition (Automated)                                      |     |     | 🔴  |
| 1.1.2.6.4 | Ensure noexec option set on /var/log partition (Automated)                                      |     |     | 🔴  |
| 1.1.2.7   | **Configure /var/log/audit**                                                                    |     |     | 🔴  |
| 1.1.2.7.1 | Ensure separate partition exists for /var/log/audit (Automated)                                 |     |     | 🔴  |
| 1.1.2.7.2 | Ensure nodev option set on /var/log/audit partition (Automated)                                 |     |     | 🔴  |
| 1.1.2.7.3 | Ensure nosuid option set on /var/log/audit partition (Automated)                                |     |     | 🔴  |
| 1.1.2.7.4 | Ensure noexec option set on /var/log/audit partition (Automated)                                |     |     | 🔴  |
| 1.2       | **Package Management**                                                                          |     | 🟡  |     |
| 1.2.1     | **Configure Package Repositories**                                                              |     | 🟡  |     |
| 1.2.1.1   | Ensure GPG keys are configured (Manual)                                                         |     | 🟡  |     |
| 1.2.1.2   | Ensure package manager repositories are configured (Manual)                                     |     | 🟡  |     |
| 1.2.2     | **Configure Package Updates**                                                                   | 🟢  |     |     |
| 1.2.2.1   | Ensure updates, patches, and additional security software are installed (Manual)                | 🟢  |     |     |
| 1.3       | **Mandatory Access Control**                                                                    | 🟢  |     |     |
| 1.3.1     | **Configure AppArmor**                                                                          | 🟢  |     |     |
| 1.3.1.1   | Ensure the apparmor packages are installed (Automated)                                          | 🟢  |     |     |
| 1.3.1.2   | Ensure AppArmor is enabled (Automated)                                                          | 🟢  |     |     |
| 1.3.1.3   | Ensure all AppArmor Profiles are not disabled (Automated)                                       | 🟢  |     |     |
| 1.3.1.4   | Ensure all AppArmor Profiles are enforcing (Automated)                                          | 🟢  |     |     |
| 1.4       | **Configure Bootloader**                                                                        | 🟢  |     |     |
| 1.4.1     | Ensure bootloader password is set (Automated)                                                   | 🟢  |     |     |
| 1.4.2     | Ensure access to bootloader config is configured (Automated)                                    | 🟢  |     |     |
| 1.5       | **Configure Additional Process Hardening**                                                      | 🟢  |     |     |
| 1.5.1     | Ensure randomize_va_space is configured (Automated)                                             | 🟢  |     |     |
| 1.5.2     | Ensure ptrace_scope is configured (Automated)                                                   | 🟢  |     |     |
| 1.5.3     | Ensure suid_dumpable is configured (Automated)                                                  | 🟢  |     |     |
| 1.5.4     | Ensure core file size is configured (Automated)                                                 | 🟢  |     |     |
| 1.5.5     | Ensure prelink is not installed (Automated)                                                     | 🟢  |     |     |
| 1.5.6     | Ensure Automatic Error Reporting is configured (Automated)                                      | 🟢  |     |     |
| 1.6       | **Configure Command Line Warning Banners**                                                      | 🟢  |     |     |
| 1.6.1     | Ensure /etc/motd is configured (Automated)                                                      | 🟢  |     |     |
| 1.6.2     | Ensure /etc/issue is configured (Automated)                                                     | 🟢  |     |     |
| 1.6.3     | Ensure /etc/issue.net is configured (Automated)                                                 | 🟢  |     |     |
| 1.6.4     | Ensure access to /etc/motd is configured (Automated)                                            | 🟢  |     |     |
| 1.6.5     | Ensure access to /etc/issue is configured (Automated)                                           | 🟢  |     |     |
| 1.6.6     | Ensure access to /etc/issue.net is configured (Automated)                                       | 🟢  |     |     |
| 1.7       | **Configure GNOME Display Manager**                                                             | 🟢  |     |     |
| 1.7.1     | Ensure GDM is removed (Automated)                                                               | 🟢  |     |     |
| 1.7.2     | Ensure GDM login banner is configured (Automated)                                               | 🟢  |     |     |
| 1.7.3     | Ensure GDM disable-user-list option is enabled (Automated)                                      | 🟢  |     |     |
| 1.7.4     | Ensure GDM screen locks when the user is idle (Automated)                                       | 🟢  |     |     |
| 1.7.5     | Ensure GDM screen locks cannot be overridden (Automated)                                        | 🟢  |     |     |
| 1.7.6     | Ensure GDM automatic mounting of removable media is disabled (Automated)                        | 🟢  |     |     |
| 1.7.7     | Ensure GDM disabling automatic mounting of removable media is not overridden (Automated)        | 🟢  |     |     |
| 1.7.8     | Ensure GDM autorun-never is enabled (Automated)                                                 | 🟢  |     |     |
| 1.7.9     | Ensure GDM autorun-never is not overridden (Automated)                                          | 🟢  |     |     |
| 1.7.10    | Ensure XDMCP is not enabled (Automated)                                                         | 🟢  |     |     |
| 1.7.11    | Ensure Xwayland is configured (Automated)                                                       | 🟢  |     |     |
| 2         | **Services**                                                                                    | 🟢  |     |     |
| 2.1       | **Configure Server Services**                                                                   | 🟢  |     |     |
| 2.1.1     | Ensure autofs services are not in use (Automated)                                               | 🟢  |     |     |
| 2.1.2     | Ensure avahi daemon services are not in use (Automated)                                         | 🟢  |     |     |
| 2.1.3     | Ensure dhcp server services are not in use (Automated)                                          | 🟢  |     |     |
| 2.1.4     | Ensure dns server services are not in use (Automated)                                           | 🟢  |     |     |
| 2.1.5     | Ensure dnsmasq services are not in use (Automated)                                              | 🟢  |     |     |
| 2.1.6     | Ensure ftp server services are not in use (Automated)                                           | 🟢  |     |     |
| 2.1.7     | Ensure ldap server services are not in use (Automated)                                          | 🟢  |     |     |
| 2.1.8     | Ensure message access server services are not in use (Automated)                                | 🟢  |     |     |
| 2.1.9     | Ensure network file system services are not in use (Automated)                                  | 🟢  |     |     |
| 2.1.10    | Ensure nis server services are not in use (Automated)                                           | 🟢  |     |     |
| 2.1.11    | Ensure print server services are not in use (Automated)                                         | 🟢  |     |     |
| 2.1.12    | Ensure rpcbind services are not in use (Automated)                                              | 🟢  |     |     |
| 2.1.13    | Ensure rsync services are not in use (Automated)                                                | 🟢  |     |     |
| 2.1.14    | Ensure samba file server services are not in use (Automated)                                    | 🟢  |     |     |
| 2.1.15    | Ensure snmp services are not in use (Automated)                                                 | 🟢  |     |     |
| 2.1.16    | Ensure tftp server services are not in use (Automated)                                          | 🟢  |     |     |
| 2.1.17    | Ensure web proxy server services are not in use (Automated)                                     | 🟢  |     |     |
| 2.1.18    | Ensure web server services are not in use (Automated)                                           | 🟢  |     |     |
| 2.1.19    | Ensure xinetd services are not in use (Automated)                                               | 🟢  |     |     |
| 2.1.20    | Ensure X window server services are not in use (Automated)                                      | 🟢  |     |     |
| 2.1.21    | Ensure mail transfer agents are configured for local-only mode (Automated)                      | 🟢  |     |     |
| 2.1.22    | Ensure only approved services are listening on a network interface (Manual)                     | 🟢  |     |     |
| 2.2       | **Configure Client Services**                                                                   | 🟢  |     |     |
| 2.2.1     | Ensure nis Client is not installed (Automated)                                                  | 🟢  |     |     |
| 2.2.2     | Ensure rsh client is not installed (Automated)                                                  | 🟢  |     |     |
| 2.2.3     | Ensure talk client is not installed (Automated)                                                 | 🟢  |     |     |
| 2.2.4     | Ensure telnet client is not installed (Automated)                                               | 🟢  |     |     |
| 2.2.5     | Ensure ldap client is not installed (Automated)                                                 | 🟢  |     |     |
| 2.2.6     | Ensure ftp client is not installed (Automated)                                                  | 🟢  |     |     |
| 2.3       | **Configure Time Synchronization**                                                              | 🟢  |     |     |
| 2.3.1     | **Ensure time synchronization is in use**                                                       | 🟢  |     |     |
| 2.3.1.1   | Ensure a single time synchronization daemon is in use (Automated)                               | 🟢  |     |     |
| 2.3.2     | **Configure systemd-timesyncd**                                                                 | 🟢  |     |     |
| 2.3.2.1   | Ensure systemd-timesyncd configured with authorized timeserver (Automated)                      | 🟢  |     |     |
| 2.3.2.2   | Ensure systemd-timesyncd is enabled and running (Automated)                                     | 🟢  |     |     |
| 2.3.3     | **Configure chrony**                                                                            | 🟢  |     |     |
| 2.3.3.1   | Ensure chrony is configured with authorized timeserver (Manual)                                 | 🟢  |     |     |
| 2.3.3.2   | Ensure chrony is running as user \_chrony (Automated)                                           | 🟢  |     |     |
| 2.3.3.3   | Ensure chrony is enabled and running (Automated)                                                | 🟢  |     |     |
| 2.4       | **Job Schedulers**                                                                              | 🟢  |     |     |
| 2.4.1     | **Configure cron**                                                                              | 🟢  |     |     |
| 2.4.1.1   | Ensure cron daemon is enabled and active (Automated)                                            | 🟢  |     |     |
| 2.4.1.2   | Ensure access to /etc/crontab is configured (Automated)                                         | 🟢  |     |     |
| 2.4.1.3   | Ensure access to /etc/cron.hourly is configured (Automated)                                     | 🟢  |     |     |
| 2.4.1.4   | Ensure access to /etc/cron.daily is configured (Automated)                                      | 🟢  |     |     |
| 2.4.1.5   | Ensure access to /etc/cron.weekly is configured (Automated)                                     | 🟢  |     |     |
| 2.4.1.6   | Ensure access to /etc/cron.monthly is configured (Automated)                                    | 🟢  |     |     |
| 2.4.1.7   | Ensure access to /etc/cron.yearly is configured (Automated)                                     | 🟢  |     |     |
| 2.4.1.8   | Ensure access to /etc/cron.d is configured (Automated)                                          | 🟢  |     |     |
| 2.4.1.9   | Ensure access to crontab is configured (Automated)                                              | 🟢  |     |     |
| 2.4.2     | **Configure at**                                                                                | 🟢  |     |     |
| 2.4.2.1   | Ensure access to at is configured (Automated)                                                   | 🟢  |     |     |
| 3         | **Network**                                                                                     | 🟢  |     |     |
| 3.1       | **Configure Network Devices**                                                                   | 🟢  |     |     |
| 3.1.1     | Ensure IPv6 status is identified (Manual)                                                       | 🟢  |     |     |
| 3.1.2     | Ensure wireless interfaces are not available (Automated)                                        | 🟢  |     |     |
| 3.1.3     | Ensure bluetooth services are not in use (Automated)                                            | 🟢  |     |     |
| 3.2       | **Configure Network Kernel Modules**                                                            | 🟢  |     |     |
| 3.2.1     | Ensure dccp kernel module is not available (Automated)                                          | 🟢  |     |     |
| 3.2.2     | Ensure tipc kernel module is not available (Automated)                                          | 🟢  |     |     |
| 3.2.3     | Ensure rds kernel module is not available (Automated)                                           | 🟢  |     |     |
| 3.2.4     | Ensure sctp kernel module is not available (Automated)                                          | 🟢  |     |     |
| 3.3       | **Configure Network Kernel Parameters**                                                         | 🟢  |     |     |
| 3.3.1     | **Configure IPv4 parameters**                                                                   | 🟢  |     |     |
| 3.3.1.1   | Ensure net.ipv4.ip_forward is configured (Automated)                                            | 🟢  |     |     |
| 3.3.1.2   | Ensure net.ipv4.conf.all.forwarding is configured (Automated)                                   | 🟢  |     |     |
| 3.3.1.3   | Ensure net.ipv4.conf.default.forwarding is configured (Automated)                               | 🟢  |     |     |
| 3.3.1.4   | Ensure net.ipv4.conf.all.send_redirects is configured (Automated)                               | 🟢  |     |     |
| 3.3.1.5   | Ensure net.ipv4.conf.default.send_redirects is configured (Automated)                           | 🟢  |     |     |
| 3.3.1.6   | Ensure net.ipv4.icmp_ignore_bogus_error_responses is configured (Automated)                     | 🟢  |     |     |
| 3.3.1.7   | Ensure net.ipv4.icmp_echo_ignore_broadcasts is configured (Automated)                           | 🟢  |     |     |
| 3.3.1.8   | Ensure net.ipv4.conf.all.accept_redirects is configured (Automated)                             | 🟢  |     |     |
| 3.3.1.9   | Ensure net.ipv4.conf.default.accept_redirects is configured (Automated)                         | 🟢  |     |     |
| 3.3.1.10  | Ensure net.ipv4.conf.all.secure_redirects is configured (Automated)                             | 🟢  |     |     |
| 3.3.1.11  | Ensure net.ipv4.conf.default.secure_redirects is configured (Automated)                         | 🟢  |     |     |
| 3.3.1.12  | Ensure net.ipv4.conf.all.rp_filter is configured (Automated)                                    | 🟢  |     |     |
| 3.3.1.13  | Ensure net.ipv4.conf.default.rp_filter is configured (Automated)                                | 🟢  |     |     |
| 3.3.1.14  | Ensure net.ipv4.conf.all.accept_source_route is configured (Automated)                          | 🟢  |     |     |
| 3.3.1.15  | Ensure net.ipv4.conf.default.accept_source_route is configured (Automated)                      | 🟢  |     |     |
| 3.3.1.16  | Ensure net.ipv4.conf.all.log_martians is configured (Automated)                                 | 🟢  |     |     |
| 3.3.1.17  | Ensure net.ipv4.conf.default.log_martians is configured (Automated)                             | 🟢  |     |     |
| 3.3.1.18  | Ensure net.ipv4.tcp_syncookies is configured (Automated)                                        | 🟢  |     |     |
| 3.3.2     | **Configure IPv6 parameters**                                                                   | 🟢  |     |     |
| 3.3.2.1   | Ensure net.ipv6.conf.all.forwarding is configured (Automated)                                   | 🟢  |     |     |
| 3.3.2.2   | Ensure net.ipv6.conf.default.forwarding is configured (Automated)                               | 🟢  |     |     |
| 3.3.2.3   | Ensure net.ipv6.conf.all.accept_redirects is configured (Automated)                             | 🟢  |     |     |
| 3.3.2.4   | Ensure net.ipv6.conf.default.accept_redirects is configured (Automated)                         | 🟢  |     |     |
| 3.3.2.5   | Ensure net.ipv6.conf.all.accept_source_route is configured (Automated)                          | 🟢  |     |     |
| 3.3.2.6   | Ensure net.ipv6.conf.default.accept_source_route is configured (Automated)                      | 🟢  |     |     |
| 3.3.2.7   | Ensure net.ipv6.conf.all.accept_ra is configured (Automated)                                    | 🟢  |     |     |
| 3.3.2.8   | Ensure net.ipv6.conf.default.accept_ra is configured (Automated)                                | 🟢  |     |     |
| 4         | **Host Based Firewall**                                                                         | 🟢  |     |     |
| 4.1       | **Configure UncomplicatedFirewall**                                                             | 🟢  |     |     |
| 4.1.1     | Ensure ufw is installed (Automated)                                                             | 🟢  |     |     |
| 4.1.2     | Ensure iptables-persistent is not installed with ufw (Automated)                                | 🟢  |     |     |
| 4.1.3     | Ensure ufw service is enabled (Automated)                                                       | 🟢  |     |     |
| 4.1.4     | Ensure ufw loopback traffic is configured (Automated)                                           | 🟢  |     |     |
| 4.1.5     | Ensure ufw outbound connections are configured (Manual)                                         | 🟢  |     |     |
| 4.1.6     | Ensure ufw firewall rules exist for all open ports (Automated)                                  | 🟢  |     |     |
| 4.1.7     | Ensure ufw default deny firewall policy (Automated)                                             | 🟢  |     |     |
| 4.2       | **Configure nftables**                                                                          | 🟢  |     |     |
| 4.2.1     | Ensure nftables is installed (Automated)                                                        | 🟢  |     |     |
| 4.2.2     | Ensure ufw is uninstalled or disabled with nftables (Automated)                                 | 🟢  |     |     |
| 4.2.3     | Ensure iptables are flushed with nftables (Manual)                                              | 🟢  |     |     |
| 4.2.4     | Ensure a nftables table exists (Automated)                                                      | 🟢  |     |     |
| 4.2.5     | Ensure nftables base chains exist (Automated)                                                   | 🟢  |     |     |
| 4.2.6     | Ensure nftables loopback traffic is configured (Automated)                                      | 🟢  |     |     |
| 4.2.7     | Ensure nftables outbound and established connections are configured (Manual)                    | 🟢  |     |     |
| 4.2.8     | Ensure nftables default deny firewall policy (Automated)                                        | 🟢  |     |     |
| 4.2.9     | Ensure nftables service is enabled (Automated)                                                  | 🟢  |     |     |
| 4.2.10    | Ensure nftables rules are permanent (Automated)                                                 | 🟢  |     |     |
| 4.3       | **Configure iptables**                                                                          | 🟢  |     |     |
| 4.3.1     | **Configure iptables software**                                                                 | 🟢  |     |     |
| 4.3.1.1   | Ensure iptables packages are installed (Automated)                                              | 🟢  |     |     |
| 4.3.1.2   | Ensure nftables is not installed with iptables (Automated)                                      | 🟢  |     |     |
| 4.3.1.3   | Ensure ufw is uninstalled or disabled with iptables (Automated)                                 | 🟢  |     |     |
| 4.3.2     | **Configure IPv4 iptables**                                                                     | 🟢  |     |     |
| 4.3.2.1   | Ensure iptables default deny firewall policy (Automated)                                        | 🟢  |     |     |
| 4.3.2.2   | Ensure iptables loopback traffic is configured (Automated)                                      | 🟢  |     |     |
| 4.3.2.3   | Ensure iptables outbound and established connections are configured (Manual)                    | 🟢  |     |     |
| 4.3.2.4   | Ensure iptables firewall rules exist for all open ports (Automated)                             | 🟢  |     |     |
| 4.3.3     | **Configure IPv6 ip6tables**                                                                    | 🟢  |     |     |
| 4.3.3.1   | Ensure ip6tables default deny firewall policy (Automated)                                       | 🟢  |     |     |
| 4.3.3.2   | Ensure ip6tables loopback traffic is configured (Automated)                                     | 🟢  |     |     |
| 4.3.3.3   | Ensure ip6tables outbound and established connections are configured (Manual)                   | 🟢  |     |     |
| 4.3.3.4   | Ensure ip6tables firewall rules exist for all open ports (Automated)                            | 🟢  |     |     |
| 5         | **Access Control**                                                                              |     | 🟡  |     |
| 5.1       | **Configure SSH Server**                                                                        | 🟢  |     |     |
| 5.1.1     | Ensure access to /etc/ssh/sshd_config is configured (Automated)                                 | 🟢  |     |     |
| 5.1.2     | Ensure access to SSH private host key files is configured (Automated)                           | 🟢  |     |     |
| 5.1.3     | Ensure access to SSH public host key files is configured (Automated)                            | 🟢  |     |     |
| 5.1.4     | Ensure sshd access is configured (Automated)                                                    | 🟢  |     |     |
| 5.1.5     | Ensure sshd Banner is configured (Automated)                                                    | 🟢  |     |     |
| 5.1.6     | Ensure sshd Ciphers are configured (Automated)                                                  | 🟢  |     |     |
| 5.1.7     | Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured (Automated)              | 🟢  |     |     |
| 5.1.8     | Ensure sshd DisableForwarding is enabled (Automated)                                            | 🟢  |     |     |
| 5.1.9     | Ensure sshd GSSAPIAuthentication is disabled (Automated)                                        | 🟢  |     |     |
| 5.1.10    | Ensure sshd HostbasedAuthentication is disabled (Automated)                                     | 🟢  |     |     |
| 5.1.11    | Ensure sshd IgnoreRhosts is enabled (Automated)                                                 | 🟢  |     |     |
| 5.1.12    | Ensure sshd KexAlgorithms is configured (Automated)                                             | 🟢  |     |     |
| 5.1.13    | Ensure sshd LoginGraceTime is configured (Automated)                                            | 🟢  |     |     |
| 5.1.14    | Ensure sshd LogLevel is configured (Automated)                                                  | 🟢  |     |     |
| 5.1.15    | Ensure sshd MACs are configured (Automated)                                                     | 🟢  |     |     |
| 5.1.16    | Ensure sshd MaxAuthTries is configured (Automated)                                              | 🟢  |     |     |
| 5.1.17    | Ensure sshd MaxSessions is configured (Automated)                                               | 🟢  |     |     |
| 5.1.18    | Ensure sshd MaxStartups is configured (Automated)                                               | 🟢  |     |     |
| 5.1.19    | Ensure sshd PermitEmptyPasswords is disabled (Automated)                                        | 🟢  |     |     |
| 5.1.20    | Ensure sshd PermitRootLogin is disabled (Automated)                                             | 🟢  |     |     |
| 5.1.21    | Ensure sshd PermitUserEnvironment is disabled (Automated)                                       | 🟢  |     |     |
| 5.1.22    | Ensure sshd UsePAM is enabled (Automated)                                                       | 🟢  |     |     |
| 5.2       | **Configure privilege escalation**                                                              | 🟢  |     |     |
| 5.2.1     | Ensure sudo is installed (Automated)                                                            | 🟢  |     |     |
| 5.2.2     | Ensure sudo commands use pty (Automated)                                                        | 🟢  |     |     |
| 5.2.3     | Ensure sudo log file exists (Automated)                                                         | 🟢  |     |     |
| 5.2.4     | Ensure users must provide password for escalation (Automated)                                   | 🟢  |     |     |
| 5.2.5     | Ensure re-authentication for privilege escalation is not disabled globally (Automated)          | 🟢  |     |     |
| 5.2.6     | Ensure sudo timestamp_timeout is configured (Automated)                                         | 🟢  |     |     |
| 5.2.7     | Ensure access to the su command is restricted (Automated)                                       | 🟢  |     |     |
| 5.3       | **Pluggable Authentication Modules**                                                            | 🟢  |     |     |
| 5.3.1     | **Configure PAM software packages**                                                             | 🟢  |     |     |
| 5.3.1.1   | Ensure latest version of pam is installed (Automated)                                           | 🟢  |     |     |
| 5.3.1.2   | Ensure latest version of libpam-modules is installed (Automated)                                | 🟢  |     |     |
| 5.3.1.3   | Ensure latest version of libpam-pwquality is installed (Automated)                              | 🟢  |     |     |
| 5.3.2     | **Configure pam-auth-update profiles**                                                          | 🟢  |     |     |
| 5.3.2.1   | Ensure pam_unix module is enabled (Automated)                                                   | 🟢  |     |     |
| 5.3.2.2   | Ensure pam_faillock module is enabled (Automated)                                               | 🟢  |     |     |
| 5.3.2.3   | Ensure pam_pwquality module is enabled (Automated)                                              | 🟢  |     |     |
| 5.3.2.4   | Ensure pam_pwhistory module is enabled (Automated)                                              | 🟢  |     |     |
| 5.3.3     | **Configure PAM Arguments**                                                                     | 🟢  |     |     |
| 5.3.3.1   | **Configure pam_faillock module**                                                               | 🟢  |     |     |
| 5.3.3.1.1 | Ensure password failed attempts lockout is configured (Automated)                               | 🟢  |     |     |
| 5.3.3.1.2 | Ensure password unlock time is configured (Automated)                                           | 🟢  |     |     |
| 5.3.3.1.3 | Ensure password failed attempts lockout includes root account (Automated)                       | 🟢  |     |     |
| 5.3.3.2   | **Configure pam_pwquality module**                                                              | 🟢  |     |     |
| 5.3.3.2.1 | Ensure password number of changed characters is configured (Automated)                          | 🟢  |     |     |
| 5.3.3.2.2 | Ensure minimum password length is configured (Automated)                                        | 🟢  |     |     |
| 5.3.3.2.3 | Ensure password complexity is configured (Manual)                                               | 🟢  |     |     |
| 5.3.3.2.4 | Ensure password same consecutive characters is configured (Automated)                           | 🟢  |     |     |
| 5.3.3.2.5 | Ensure password maximum sequential characters is configured (Automated)                         | 🟢  |     |     |
| 5.3.3.2.6 | Ensure password dictionary check is enabled (Automated)                                         | 🟢  |     |     |
| 5.3.3.2.7 | Ensure password quality checking is enforced (Automated)                                        | 🟢  |     |     |
| 5.3.3.2.8 | Ensure password quality is enforced for the root user (Automated)                               | 🟢  |     |     |
| 5.3.3.3   | **Configure pam_pwhistory module**                                                              | 🟢  |     |     |
| 5.3.3.3.1 | Ensure password history remember is configured (Automated)                                      | 🟢  |     |     |
| 5.3.3.3.2 | Ensure password history is enforced for the root user (Automated)                               | 🟢  |     |     |
| 5.3.3.3.3 | Ensure pam_pwhistory includes use_authtok (Automated)                                           | 🟢  |     |     |
| 5.3.3.4   | **Configure pam_unix module**                                                                   | 🟢  |     |     |
| 5.3.3.4.1 | Ensure pam_unix does not include nullok (Automated)                                             | 🟢  |     |     |
| 5.3.3.4.2 | Ensure pam_unix does not include remember (Automated)                                           | 🟢  |     |     |
| 5.3.3.4.3 | Ensure pam_unix includes a strong password hashing algorithm (Automated)                        | 🟢  |     |     |
| 5.3.3.4.4 | Ensure pam_unix includes use_authtok (Automated)                                                | 🟢  |     |     |
| 5.4       | **User Accounts and Environment**                                                               |     | 🟡  |     |
| 5.4.1     | **Configure shadow password suite parameters**                                                  |     | 🟡  |     |
| 5.4.1.1   | Ensure password expiration is configured (Automated)                                            | 🟢  |     |     |
| 5.4.1.2   | Ensure minimum password days is configured (Manual)                                             | 🟢  |     |     |
| 5.4.1.3   | Ensure password expiration warning days is configured (Automated)                               | 🟢  |     |     |
| 5.4.1.4   | Ensure strong password hashing algorithm is configured (Automated)                              | 🟢  |     |     |
| 5.4.1.5   | Ensure inactive password lock is configured (Automated)                                         |     | 🟡  |     |
| 5.4.1.6   | Ensure all users last password change date is in the past (Automated)                           |     | 🟡  |     |
| 5.4.2     | **Configure root and system accounts and environment**                                          |     | 🟡  |     |
| 5.4.2.1   | Ensure root is the only UID 0 account (Automated)                                               | 🟢  |     |     |
| 5.4.2.2   | Ensure root is the only GID 0 account (Automated)                                               | 🟢  |     |     |
| 5.4.2.3   | Ensure group root is the only GID 0 group (Automated)                                           | 🟢  |     |     |
| 5.4.2.4   | Ensure root account access is controlled (Automated)                                            |     | 🟡  |     |
| 5.4.2.5   | Ensure root path integrity (Automated)                                                          |     | 🟡  |     |
| 5.4.2.6   | Ensure root user umask is configured (Automated)                                                | 🟢  |     |     |
| 5.4.2.7   | Ensure system accounts do not have a valid login shell (Automated)                              |     | 🟡  |     |
| 5.4.2.8   | Ensure accounts without a valid login shell are locked (Automated)                              | 🟢  |     |     |
| 5.4.3     | **Configure user default environment**                                                          | 🟢  |     |     |
| 5.4.3.1   | Ensure nologin is not listed in /etc/shells (Automated)                                         | 🟢  |     |     |
| 5.4.3.2   | Ensure default user shell timeout is configured (Automated)                                     | 🟢  |     |     |
| 5.4.3.3   | Ensure default user umask is configured (Automated)                                             | 🟢  |     |     |
| 6         | **Logging and Auditing**                                                                        | 🟢  |     |     |
| 6.1       | **Configure Filesystem Integrity Checking**                                                     | 🟢  |     |     |
| 6.1.1     | Ensure AIDE is installed (Automated)                                                            | 🟢  |     |     |
| 6.1.2     | Ensure filesystem integrity is regularly checked (Automated)                                    | 🟢  |     |     |
| 6.1.3     | Ensure cryptographic mechanisms are used to protect the integrity of audit tools (Automated)    | 🟢  |     |     |
| 6.2       | **System Logging**                                                                              | 🟢  |     |     |
| 6.2.1     | **Configure journald**                                                                          | 🟢  |     |     |
| 6.2.1.1   | **Configure systemd-journald service**                                                          | 🟢  |     |     |
| 6.2.1.1.1 | Ensure journald service is enabled and active (Automated)                                       | 🟢  |     |     |
| 6.2.1.1.2 | Ensure journald log file access is configured (Automated)                                       | 🟢  |     |     |
| 6.2.1.1.3 | Ensure journald log file rotation is configured (Automated)                                     | 🟢  |     |     |
| 6.2.1.1.4 | Ensure journald ForwardToSyslog is disabled (Automated)                                         | 🟢  |     |     |
| 6.2.1.1.5 | Ensure journald Storage is configured (Automated)                                               | 🟢  |     |     |
| 6.2.1.1.6 | Ensure journald Compress is configured (Automated)                                              | 🟢  |     |     |
| 6.2.1.2   | **Configure systemd-journal-remote**                                                            | 🟢  |     |     |
| 6.2.1.2.1 | Ensure systemd-journal-remote is installed (Automated)                                          | 🟢  |     |     |
| 6.2.1.2.2 | Ensure systemd-journal-remote authentication is configured (Manual)                             | 🟢  |     |     |
| 6.2.1.2.3 | Ensure systemd-journal-upload is enabled and active (Automated)                                 | 🟢  |     |     |
| 6.2.1.2.4 | Ensure systemd-journal-remote service is not in use (Automated)                                 | 🟢  |     |     |
| 6.2.2     | **Configure Logfiles**                                                                          | 🟢  |     |     |
| 6.2.2.1   | Ensure access to all logfiles has been configured (Automated)                                   | 🟢  |     |     |
| 6.3       | **System Auditing**                                                                             | 🟢  |     |     |
| 6.3.1     | **Configure auditd Service**                                                                    | 🟢  |     |     |
| 6.3.1.1   | Ensure auditd packages are installed (Automated)                                                | 🟢  |     |     |
| 6.3.1.2   | Ensure auditd service is enabled and active (Automated)                                         | 🟢  |     |     |
| 6.3.1.3   | Ensure auditing for processes that start prior to auditd is enabled (Automated)                 | 🟢  |     |     |
| 6.3.1.4   | Ensure audit_backlog_limit is sufficient (Automated)                                            | 🟢  |     |     |
| 6.3.2     | **Configure Data Retention**                                                                    | 🟢  |     |     |
| 6.3.2.1   | Ensure audit log storage size is configured (Automated)                                         | 🟢  |     |     |
| 6.3.2.2   | Ensure audit logs are not automatically deleted (Automated)                                     | 🟢  |     |     |
| 6.3.2.3   | Ensure system is disabled when audit logs are full (Automated)                                  | 🟢  |     |     |
| 6.3.2.4   | Ensure system warns when audit logs are low on space (Automated)                                | 🟢  |     |     |
| 6.3.3     | **Configure auditd Rules**                                                                      | 🟢  |     |     |
| 6.3.3.1   | Ensure changes to system administration scope (sudoers) is collected (Automated)                | 🟢  |     |     |
| 6.3.3.2   | Ensure actions as another user are always logged (Automated)                                    | 🟢  |     |     |
| 6.3.3.3   | Ensure events that modify the sudo log file are collected (Automated)                           | 🟢  |     |     |
| 6.3.3.4   | Ensure events that modify date and time information are collected (Automated)                   | 🟢  |     |     |
| 6.3.3.5   | Ensure events that modify the system's network environment are collected (Automated)            | 🟢  |     |     |
| 6.3.3.6   | Ensure use of privileged commands are collected (Automated)                                     | 🟢  |     |     |
| 6.3.3.7   | Ensure unsuccessful file access attempts are collected (Automated)                              | 🟢  |     |     |
| 6.3.3.8   | Ensure events that modify user/group information are collected (Automated)                      | 🟢  |     |     |
| 6.3.3.9   | Ensure discretionary access control permission modification events are collected (Automated)    | 🟢  |     |     |
| 6.3.3.10  | Ensure successful file system mounts are collected (Automated)                                  | 🟢  |     |     |
| 6.3.3.11  | Ensure session initiation information is collected (Automated)                                  | 🟢  |     |     |
| 6.3.3.12  | Ensure login and logout events are collected (Automated)                                        | 🟢  |     |     |
| 6.3.3.13  | Ensure file deletion events by users are collected (Automated)                                  | 🟢  |     |     |
| 6.3.3.14  | Ensure events that modify the system's Mandatory Access Controls are collected (Automated)      | 🟢  |     |     |
| 6.3.3.15  | Ensure successful and unsuccessful attempts to use the chcon command are recorded (Automated)   | 🟢  |     |     |
| 6.3.3.16  | Ensure successful and unsuccessful attempts to use the setfacl command are recorded (Automated) | 🟢  |     |     |
| 6.3.3.17  | Ensure successful and unsuccessful attempts to use the chacl command are recorded (Automated)   | 🟢  |     |     |
| 6.3.3.18  | Ensure successful and unsuccessful attempts to use the usermod command are recorded (Automated) | 🟢  |     |     |
| 6.3.3.19  | Ensure kernel module loading unloading and modification is collected (Automated)                | 🟢  |     |     |
| 6.3.3.20  | Ensure the audit configuration is immutable (Automated)                                         | 🟢  |     |     |
| 6.3.3.21  | Ensure the running and on disk configuration is the same (Manual)                               | 🟢  |     |     |
| 6.3.4     | **Configure auditd File Access**                                                                | 🟢  |     |     |
| 6.3.4.1   | Ensure audit log files mode is configured (Automated)                                           | 🟢  |     |     |
| 6.3.4.2   | Ensure audit log files owner is configured (Automated)                                          | 🟢  |     |     |
| 6.3.4.3   | Ensure audit log files group owner is configured (Automated)                                    | 🟢  |     |     |
| 6.3.4.4   | Ensure the audit log file directory mode is configured (Automated)                              | 🟢  |     |     |
| 6.3.4.5   | Ensure audit configuration files mode is configured (Automated)                                 | 🟢  |     |     |
| 6.3.4.6   | Ensure audit configuration files owner is configured (Automated)                                | 🟢  |     |     |
| 6.3.4.7   | Ensure audit configuration files group owner is configured (Automated)                          | 🟢  |     |     |
| 6.3.4.8   | Ensure audit tools mode is configured (Automated)                                               | 🟢  |     |     |
| 6.3.4.9   | Ensure audit tools owner is configured (Automated)                                              | 🟢  |     |     |
| 6.3.4.10  | Ensure audit tools group owner is configured (Automated)                                        | 🟢  |     |     |
| 7         | **System Maintenance**                                                                          |     | 🟡  |     |
| 7.1       | **System File Permissions**                                                                     |     | 🟡  |     |
| 7.1.1     | Ensure permissions on /etc/passwd are configured (Automated)                                    | 🟢  |     |     |
| 7.1.2     | Ensure permissions on /etc/passwd- are configured (Automated)                                   | 🟢  |     |     |
| 7.1.3     | Ensure permissions on /etc/group are configured (Automated)                                     | 🟢  |     |     |
| 7.1.4     | Ensure permissions on /etc/group- are configured (Automated)                                    | 🟢  |     |     |
| 7.1.5     | Ensure permissions on /etc/shadow are configured (Automated)                                    | 🟢  |     |     |
| 7.1.6     | Ensure permissions on /etc/shadow- are configured (Automated)                                   | 🟢  |     |     |
| 7.1.7     | Ensure permissions on /etc/gshadow are configured (Automated)                                   | 🟢  |     |     |
| 7.1.8     | Ensure permissions on /etc/gshadow- are configured (Automated)                                  | 🟢  |     |     |
| 7.1.9     | Ensure permissions on /etc/shells are configured (Automated)                                    | 🟢  |     |     |
| 7.1.10    | Ensure permissions on /etc/security/opasswd are configured (Automated)                          | 🟢  |     |     |
| 7.1.11    | Ensure world writable files and directories are secured (Automated)                             | 🟢  |     |     |
| 7.1.12    | Ensure no files or directories without an owner and a group exist (Automated)                   |     | 🟡  |     |
| 7.1.13    | Ensure SUID and SGID files are reviewed (Manual)                                                |     | 🟡  |     |
| 7.2       | **Local User and Group Settings**                                                               |     | 🟡  |     |
| 7.2.1     | Ensure accounts in /etc/passwd use shadowed passwords (Automated)                               | 🟢  |     |     |
| 7.2.2     | Ensure /etc/shadow password fields are not empty (Automated)                                    | 🟢  |     |     |
| 7.2.3     | Ensure all groups in /etc/passwd exist in /etc/group (Automated)                                |     | 🟡  |     |
| 7.2.4     | Ensure shadow group is empty (Automated)                                                        | 🟢  |     |     |
| 7.2.5     | Ensure no duplicate UIDs exist (Automated)                                                      |     | 🟡  |     |
| 7.2.6     | Ensure no duplicate GIDs exist (Automated)                                                      |     | 🟡  |     |
| 7.2.7     | Ensure no duplicate user names exist (Automated)                                                |     | 🟡  |     |
| 7.2.8     | Ensure no duplicate group names exist (Automated)                                               |     | 🟡  |     |
| 7.2.9     | Ensure local interactive user home directories are configured (Automated)                       | 🟢  |     |     |
| 7.2.10    | Ensure local interactive user dot files access is configured (Automated)                        | 🟢  |     |     |

## License

MIT

---

## Resources

- <https://downloads.cisecurity.org/#/>
- <https://github.com/florianutz/ubuntu2004_cis>
- <https://github.com/MVladislav/ansible-cis-ubuntu-2404>
