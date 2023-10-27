# CIS - Ubuntu 22.04

---

[![Ansible Lint](https://github.com/MVladislav/ansible-cis-ubuntu-2204/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/MVladislav/ansible-cis-ubuntu-2204/actions/workflows/ansible-lint.yml)
[![Ansible Molecule Test](https://github.com/MVladislav/ansible-cis-ubuntu-2204/actions/workflows/ci.yml/badge.svg)](https://github.com/MVladislav/ansible-cis-ubuntu-2204/actions/workflows/ci.yml)

- [CIS - Ubuntu 22.04](#cis---ubuntu-2204)
  - [TODO](#todo)
  - [Requirements](#requirements)
  - [Role Variables](#role-variables)
    - [run only setup per section](#run-only-setup-per-section)
    - [variables not included in CIS](#variables-not-included-in-cis)
    - [variables which are recommended by CIS, but disable in this role](#variables-which-are-recommended-by-cis-but-disable-in-this-role)
    - [variable special usable between server and client](#variable-special-usable-between-server-and-client)
    - [variables to check and set for own purpose](#variables-to-check-and-set-for-own-purpose)
    - [variable rules implemented, but only print information for manual check](#variable-rules-implemented-but-only-print-information-for-manual-check)
  - [Dependencies](#dependencies)
  - [Example Playbook](#example-playbook)
  - [Definitions](#definitions)
    - [Profile](#profile)
  - [CIS - List of Recommendations](#cis---list-of-recommendations)
  - [License](#license)
  - [Resources](#resources)

---

Configure Ubuntu 22.04 to be CIS compliant.

Tested with:

- Ubuntu 22.04
- Ubuntu 23.04

This role **will make changes to the system** that could break things. \
This is not an auditing tool but rather a remediation tool to be used after an audit has been conducted.

This role was **developed against a clean install** of the Operating System. \
If you are **implementing to an existing system** please **review** this role for any **site specific changes** that are needed.

Based on **[CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0](https://downloads.cisecurity.org/#/)**.

## TODO

- improve grub changes
  - make changes for lvm or zfs
  - create checker and add for if grub exists with lines like, because we only check for replace in section
    - `GRUB_CMDLINE_LINUX`
  - make a copy from template if grub not exists
    - <https://askubuntu.com/questions/406229/there-was-no-etc-default-grub-file-so-how-come-my-system-was-able-to-boot>
- improve auditd for 32 or 64 system check to add rules
- check ufw sysctl usage
- improve cis_ubuntu2204_set_journal_upload
- improve with some variables for section5
- extend cis_ubuntu2204_rule_5_3_4
  - to also check in subfiles under '/etc/sudoers.d/'
- rules under '5.4', should be more tested
  - example for 'cis_ubuntu2204_rule_5_4_2' which fail to use password after performed
  - seams error found, but need tests, CIS pdf define success=1 but default value in ubuntu is success=2

## Requirements

You should **carefully read** through the tasks
to **make sure these changes will not break your systems**
before running this playbook.

To start working in this Role you just need to **install** **Python** and **Ansible**:

```sh
$sudo apt install python3 python3-pip sshpass
# if python >= 3.11 used add also '--break-system-packages'
$python3 -m pip install ansible ansible-lint yamllint
```

For run **tests** with **molecule**, you need also to **install**:

```sh
# if python >= 3.11 used add also '--break-system-packages'
$python3 -m pip install molecule molecule-plugins[docker]
```

## Role Variables

### run only setup per section

> _default all section are active and will performed_

```yaml
cis_ubuntu2204_section1: true
cis_ubuntu2204_section2: true
cis_ubuntu2204_section3: true
cis_ubuntu2204_section4: true
cis_ubuntu2204_section5: true
cis_ubuntu2204_section6: true
```

### variables not included in CIS

```yaml
# additional configs for ssh which not defined to set by CIS
cis_ubuntu2204_rule_5_2_23: true
```

### variables which are recommended by CIS, but disable in this role

> _change 'false' below to 'true', to be CIS recommended if needed_

```yaml
# Ensure bootloader password is set
cis_ubuntu2204_rule_1_4_1: false
cis_ubuntu2204_set_boot_pass: false

# Ensure authentication required for single user mode
cis_ubuntu2204_rule_1_4_3: false

# Ensure all AppArmor Profiles are in enforce or complain mode
# NOTE: will perform Profiles as complain mode
cis_ubuntu2204_rule_1_6_1_3: false
# Ensure all AppArmor Profiles are enforcing
# NOTE: will perform Profiles as enforcing mode
cis_ubuntu2204_rule_1_6_1_4: false

# cis define to deny all outgoing traffic and whitelist all needed
# default here is changed to allow all outgoing traffic,
# if you need to be cis conform, set to 'deny'
cis_ubuntu2204_firewall_ufw_outgoing_policy: allow # deny | allow

# active journal upload to remote log collection
# do not forget set related variables 'cis_ubuntu2204_set_journal_upload_*'
cis_ubuntu2204_set_journal_upload: false

# Ensure lockout for failed password attempts is configured
cis_ubuntu2204_rule_5_4_2: false
```

### variable special usable between server and client

> _check services which will removed or disabled,
> which maybe needed, for example especial for client usage_

```yaml
# will purge gdm/gui, if needed set to 'true'
# if 'true', recommended configs will perform in rules 1.8.2 - 1.8.10
cis_ubuntu2204_allow_gdm_gui: false

# will disable auto mount, if needed set to 'true'
cis_ubuntu2204_allow_autofs: false

# will disable USB storage, if needed set to 'false'
cis_ubuntu2204_rule_1_1_10: true

# will install and config AIDE, if not needed set to 'false'
cis_ubuntu2204_install_aide: true
cis_ubuntu2204_config_aide: true

# will purge printer service, if need set to 'true'
cis_ubuntu2204_allow_cups: false

# will disable ipv6 complete, if needed set to 'true'
cis_ubuntu2204_required_ipv6: false
```

### variables to check and set for own purpose

```yaml
# AIDE cron settings
cis_ubuntu2204_aide_cron:
  cron_user: root
  cron_file: aide
  aide_job: "/usr/bin/aide.wrapper --config /etc/aide/aide.conf --check"
  aide_minute: 0
  aide_hour: 5
  aide_day: "*"
  aide_month: "*"
  aide_weekday: "*"

# choose time synchronization
cis_ubuntu2204_time_synchronization_service: chrony # chrony | systemd-timesyncd | ntp
cis_ubuntu2204_time_synchronization_ntp_server: time.cloudflare.com
cis_ubuntu2204_time_synchronization_ntp_fallback_server: ntp.ubuntu.com

# choose firewall
cis_ubuntu2204_firewall: ufw # ufw | nftables | iptables

# put 'null' or list of users
# cron allow users
cis_ubuntu2204_cron_allow_users:
  - root
# at allow users
cis_ubuntu2204_at_allow_users:
  - root

# allows/denies for users/groups (4 possible variables can be used/activated)
# put 'null' or list of users (comma separated user list)
# default set to add ssh as group to allow use ssh (do not forget add group to user)
#cis_ubuntu2204_ssh_allow_users: root,user
cis_ubuntu2204_ssh_allow_groups: ssh
#cis_ubuntu2204_ssh_deny_users: root,user
#cis_ubuntu2204_ssh_deny_groups: root,group

# pw quality policies
cis_ubuntu2204_pwquality:
  - key: "minlen"
    value: "14"
  - key: "dcredit"
    value: "-1"
  - key: "ucredit"
    value: "-1"
  - key: "ocredit"
    value: "-1"
  - key: "lcredit"
    value: "-1"

# NOTE: check the two success values, in CIS-pdf they are defined with '1'
#       but on ubuntu-23.04 it is set per default as '2'
cis_ubuntu2204_remember_reuse: 5
cis_ubuntu2204_encrypt_method: yescrypt # yescrypt | sha512
cis_ubuntu2204_common_auth_success: 2
cis_ubuntu2204_common_password_success: 2
```

### variable rules implemented, but only print information for manual check

```yaml
# SECTION2 | 2.4 | Ensure rsync service is either not installed or masked
cis_ubuntu2204_rule_2_4: true

# SECTION6 | 6.1.10 | Ensure no unowned files or directories exist
cis_ubuntu2204_rule_6_1_10: true
# SECTION6 | 6.1.11 | Ensure no ungrouped files or directories exist
cis_ubuntu2204_rule_6_1_11: true
# SECTION6 | 6.1.12 | Audit SUID executables
cis_ubuntu2204_rule_6_1_12: true
# SECTION6 | 6.1.13 | Audit SGID executables
cis_ubuntu2204_rule_6_1_13: true
# SECTION6 | 6.2.3 | Ensure all groups in /etc/passwd exist in /etc/group
cis_ubuntu2204_rule_6_2_3: true
# SECTION6 | 6.2.5 | Ensure no duplicate UIDs exist
cis_ubuntu2204_rule_6_2_5: true
# SECTION6 | 6.2.6 | Ensure no duplicate GIDs exist
cis_ubuntu2204_rule_6_2_6: true
# SECTION6 | 6.2.7 | Ensure no duplicate user names exist
cis_ubuntu2204_rule_6_2_7: true
# SECTION6 | 6.2.8 | Ensure no duplicate group names exist
cis_ubuntu2204_rule_6_2_8: true
# SECTION6 | 6.2.9 | Ensure root PATH Integrity
cis_ubuntu2204_rule_6_2_9: true
# SECTION6 | 6.2.10 | Ensure root is the only UID 0 account
cis_ubuntu2204_rule_6_2_10: true
```

## Dependencies

Developed and testes with Ansible 2.14.4

## Example Playbook

example usage you can find also [here](https://github.com/MVladislav/ansible-env-setup).

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
      # -------------------------
      cis_ubuntu2204_rule_1_4_1: false # bootloader password
      cis_ubuntu2204_set_boot_pass: false # bootloader password
      cis_ubuntu2204_rule_1_4_3: false # authentication required for single user mode
      # -------------------------
      cis_ubuntu2204_rule_5_4_2: false # lockout for failed password attempts # NOTE: will fail to use password
      # -------------------------
      cis_ubuntu2204_rule_1_6_1_3: false # AppArmor complain mode
      cis_ubuntu2204_rule_1_6_1_4: false # AppArmor enforce mode
      # -------------------------
      cis_ubuntu2204_allow_gdm_gui: true
      cis_ubuntu2204_allow_autofs: true
      cis_ubuntu2204_rule_1_1_10: false # Disable USB Storage
      cis_ubuntu2204_time_synchronization_service: chrony # chrony | systemd-timesyncd | ntp
      cis_ubuntu2204_time_synchronization_ntp_server: '{{ ansible_host_default_ntp | default("time.cloudflare.com")}}'
      cis_ubuntu2204_time_synchronization_ntp_fallback_server: ntp.ubuntu.com
      cis_ubuntu2204_allow_cups: true
      # -------------------------
      cis_ubuntu2204_install_aide: "{{ cis_setup_aide | default(false) | bool }}"
      cis_ubuntu2204_config_aide: "{{ cis_setup_aide | default(false) | bool }}"
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
      cis_ubuntu2204_required_ipv6: "{{ cis_ipv6_required | default(false) | bool }}"
      cis_ubuntu2204_firewall: ufw
      cis_ubuntu2204_firewall_ufw_outgoing_policy: allow
      # -------------------------
      cis_ubuntu2204_ssh_allow_groups: null
      cis_ubuntu2204_cron_allow_users:
        - root
      cis_ubuntu2204_at_allow_users:
        - root
      cis_ubuntu2204_pwquality:
        - key: "minlen"
          value: "8"
        - key: "dcredit"
          value: "-1"
        - key: "ucredit"
          value: "-1"
        - key: "ocredit"
          value: "-1"
        - key: "lcredit"
          value: "-1"
      # -------------------------
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

| #         | CIS Benchmark Recommendation Set                                                                | Yes | Y/N | No  |
| :-------- | :---------------------------------------------------------------------------------------------- | :-: | :-: | :-: |
| 1         | **Initial Setup**                                                                               |     |  x  |     |
| 1.1       | **Filesystem Configuration**                                                                    |     |  x  |     |
| 1.1.1     | **Disable unused filesystems**                                                                  |  x  |     |     |
| 1.1.1.1   | Ensure mounting of cramfs filesystems is disabled (Automated)                                   |  x  |     |     |
| 1.1.1.2   | Ensure mounting of squashfs filesystems is disabled (Automated)                                 |  x  |     |     |
| 1.1.1.3   | Ensure mounting of udf filesystems is disabled (Automated)                                      |  x  |     |     |
| 1.1.2     | **Configure /tmp**                                                                              |  x  |     |     |
| 1.1.2.1   | Ensure /tmp is a separate partition (Automated)                                                 |  x  |     |     |
| 1.1.2.2   | Ensure nodev option set on /tmp partition (Automated)                                           |  x  |     |     |
| 1.1.2.3   | Ensure noexec option set on /tmp partition (Automated)                                          |  x  |     |     |
| 1.1.2.4   | Ensure nosuid option set on /tmp partition (Automated)                                          |  x  |     |     |
| 1.1.3     | **Configure /var**                                                                              |     |     |  x  |
| 1.1.3.1   | Ensure separate partition exists for /var (Automated)                                           |     |     |  x  |
| 1.1.3.2   | Ensure nodev option set on /var partition (Automated)                                           |     |     |  x  |
| 1.1.3.3   | Ensure nosuid option set on /var partition (Automated)                                          |     |     |  x  |
| 1.1.4     | **Configure /var/tmp**                                                                          |     |     |  x  |
| 1.1.4.1   | Ensure separate partition exists for /var/tmp (Automated)                                       |     |     |  x  |
| 1.1.4.2   | Ensure noexec option set on /var/tmp partition (Automated)                                      |     |     |  x  |
| 1.1.4.3   | Ensure nosuid option set on /var/tmp partition (Automated)                                      |     |     |  x  |
| 1.1.4.4   | Ensure nodev option set on /var/tmp partition (Automated)                                       |     |     |  x  |
| 1.1.5     | **Configure /var/log**                                                                          |     |     |  x  |
| 1.1.5.1   | Ensure separate partition exists for /var/log (Automated)                                       |     |     |  x  |
| 1.1.5.2   | Ensure nodev option set on /var/log partition (Automated)                                       |     |     |  x  |
| 1.1.5.3   | Ensure noexec option set on /var/log partition (Automated)                                      |     |     |  x  |
| 1.1.5.4   | Ensure nosuid option set on /var/log partition (Automated)                                      |     |     |  x  |
| 1.1.6     | **Configure /var/log/audit**                                                                    |     |     |  x  |
| 1.1.6.1   | Ensure separate partition exists for /var/log/audit (Automated)                                 |     |     |  x  |
| 1.1.6.2   | Ensure noexec option set on /var/log/audit partition (Automated)                                |     |     |  x  |
| 1.1.6.3   | Ensure nodev option set on /var/log/audit partition (Automated)                                 |     |     |  x  |
| 1.1.6.4   | Ensure nosuid option set on /var/log/audit partition (Automated)                                |     |     |  x  |
| 1.1.7     | **Configure /home**                                                                             |     |     |  x  |
| 1.1.7.1   | Ensure separate partition exists for /home (Automated)                                          |     |     |  x  |
| 1.1.7.2   | Ensure nodev option set on /home partition (Automated)                                          |     |     |  x  |
| 1.1.7.3   | Ensure nosuid option set on /home partition (Automated)                                         |     |     |  x  |
| 1.1.8     | **Configure /dev/shm**                                                                          |  x  |     |     |
| 1.1.8.1   | Ensure nodev option set on /dev/shm partition (Automated)                                       |  x  |     |     |
| 1.1.8.2   | Ensure noexec option set on /dev/shm partition (Automated)                                      |  x  |     |     |
| 1.1.8.3   | Ensure nosuid option set on /dev/shm partition (Automated)                                      |  x  |     |     |
| 1.1.9     | Disable Automounting (Automated)                                                                |  x  |     |     |
| 1.1.10    | Disable USB Storage (Automated)                                                                 |  x  |     |     |
| 1.2       | **Configure Software Updates**                                                                  |     |     |  x  |
| 1.2.1     | Ensure package manager repositories are configured (Manual)                                     |     |     |  x  |
| 1.2.2     | Ensure GPG keys are configured (Manual)                                                         |     |     |  x  |
| 1.3       | **Filesystem Integrity Checking**                                                               |  x  |     |     |
| 1.3.1     | Ensure AIDE is installed (Automated)                                                            |  x  |     |     |
| 1.3.2     | Ensure filesystem integrity is regularly checked (Automated)                                    |  x  |     |     |
| 1.4       | **Secure Boot Settings**                                                                        |  x  |     |     |
| 1.4.1     | Ensure bootloader password is set (Automated)                                                   |  x  |     |     |
| 1.4.2     | Ensure permissions on bootloader config are configured (Automated)                              |  x  |     |     |
| 1.4.3     | Ensure authentication required for single user mode (Automated)                                 |  x  |     |     |
| 1.5       | **Additional Process Hardening**                                                                |  x  |     |     |
| 1.5.1     | Ensure address space layout randomization (ASLR) is enabled (Automated)                         |  x  |     |     |
| 1.5.2     | Ensure prelink is not installed (Automated)                                                     |  x  |     |     |
| 1.5.3     | Ensure Automatic Error Reporting is not enabled (Automated)                                     |  x  |     |     |
| 1.5.4     | Ensure core dumps are restricted (Automated)                                                    |  x  |     |     |
| 1.6       | **Mandatory Access Control**                                                                    |  x  |     |     |
| 1.6.1     | **Configure AppArmor**                                                                          |  x  |     |     |
| 1.6.1.1   | Ensure AppArmor is installed (Automated)                                                        |  x  |     |     |
| 1.6.1.2   | Ensure AppArmor is enabled in the bootloader configuration (Automated)                          |  x  |     |     |
| 1.6.1.3   | Ensure all AppArmor Profiles are in enforce or complain mode (Automated)                        |  x  |     |     |
| 1.6.1.4   | Ensure all AppArmor Profiles are enforcing (Automated)                                          |  x  |     |     |
| 1.7       | **Command Line Warning Banners**                                                                |  x  |     |     |
| 1.7.1     | Ensure message of the day is configured properly (Automated)                                    |  x  |     |     |
| 1.7.2     | Ensure local login warning banner is configured properly (Automated)                            |  x  |     |     |
| 1.7.3     | Ensure remote login warning banner is configured properly (Automated)                           |  x  |     |     |
| 1.7.4     | Ensure permissions on /etc/motd are configured (Automated)                                      |  x  |     |     |
| 1.7.5     | Ensure permissions on /etc/issue are configured (Automated)                                     |  x  |     |     |
| 1.7.6     | Ensure permissions on /etc/issue.net are configured (Automated)                                 |  x  |     |     |
| 1.8       | **GNOME Display Manager**                                                                       |  x  |     |     |
| 1.8.1     | Ensure GNOME Display Manager is removed (Automated)                                             |  x  |     |     |
| 1.8.2     | Ensure GDM login banner is configured (Automated)                                               |  x  |     |     |
| 1.8.3     | Ensure GDM disable-user-list option is enabled (Automated)                                      |  x  |     |     |
| 1.8.4     | Ensure GDM screen locks when the user is idle (Automated)                                       |  x  |     |     |
| 1.8.5     | Ensure GDM screen locks cannot be overridden (Automated)                                        |  x  |     |     |
| 1.8.6     | Ensure GDM automatic mounting of removable media is disabled (Automated)                        |  x  |     |     |
| 1.8.7     | Ensure GDM disabling automatic mounting of removable media is not overridden (Automated)        |  x  |     |     |
| 1.8.8     | Ensure GDM autorun-never is enabled (Automated)                                                 |  x  |     |     |
| 1.8.9     | Ensure GDM autorun-never is not overridden (Automated)                                          |  x  |     |     |
| 1.8.10    | Ensure XDCMP is not enabled (Automated)                                                         |  x  |     |     |
| 1.9       | Ensure updates, patches, and additional security software are installed (Manual)                |  x  |     |     |
| 2         | **Services**                                                                                    |  x  |     |     |
| 2.1       | **Configure Time Synchronization**                                                              |  x  |     |     |
| 2.1.1     | **Ensure time synchronization is in use**                                                       |  x  |     |     |
| 2.1.1.1   | Ensure a single time synchronization daemon is in use (Automated)                               |  x  |     |     |
| 2.1.2     | **Configure chrony**                                                                            |  x  |     |     |
| 2.1.2.1   | Ensure chrony is configured with authorized timeserver (Manual)                                 |  x  |     |     |
| 2.1.2.2   | Ensure chrony is running as user \_chrony (Automated)                                           |  x  |     |     |
| 2.1.2.3   | Ensure chrony is enabled and running (Automated)                                                |  x  |     |     |
| 2.1.3     | **Configure systemd-timesyncd**                                                                 |  x  |     |     |
| 2.1.3.1   | Ensure systemd-timesyncd configured with authorized timeserver (Manual)                         |  x  |     |     |
| 2.1.3.2   | Ensure systemd-timesyncd is enabled and running (Automated)                                     |  x  |     |     |
| 2.1.4     | **Configure ntp**                                                                               |  x  |     |     |
| 2.1.4.1   | Ensure ntp access control is configured (Automated)                                             |  x  |     |     |
| 2.1.4.2   | Ensure ntp is configured with authorized timeserver (Manual)                                    |  x  |     |     |
| 2.1.4.3   | Ensure ntp is running as user ntp (Automated)                                                   |  x  |     |     |
| 2.1.4.4   | Ensure ntp is enabled and running (Automated)                                                   |  x  |     |     |
| 2.2       | **Special Purpose Services**                                                                    |  x  |     |     |
| 2.2.1     | Ensure X Window System is not installed (Automated)                                             |  x  |     |     |
| 2.2.2     | Ensure Avahi Server is not installed (Automated)                                                |  x  |     |     |
| 2.2.3     | Ensure CUPS is not installed (Automated)                                                        |  x  |     |     |
| 2.2.4     | Ensure DHCP Server is not installed (Automated)                                                 |  x  |     |     |
| 2.2.5     | Ensure LDAP server is not installed (Automated)                                                 |  x  |     |     |
| 2.2.6     | Ensure NFS is not installed (Automated)                                                         |  x  |     |     |
| 2.2.7     | Ensure DNS Server is not installed (Automated)                                                  |  x  |     |     |
| 2.2.8     | Ensure FTP Server is not installed (Automated)                                                  |  x  |     |     |
| 2.2.9     | Ensure HTTP server is not installed (Automated)                                                 |  x  |     |     |
| 2.2.10    | Ensure IMAP and POP3 server are not installed (Automated)                                       |  x  |     |     |
| 2.2.11    | Ensure Samba is not installed (Automated)                                                       |  x  |     |     |
| 2.2.12    | Ensure HTTP Proxy Server is not installed (Automated)                                           |  x  |     |     |
| 2.2.13    | Ensure SNMP Server is not installed (Automated)                                                 |  x  |     |     |
| 2.2.14    | Ensure NIS Server is not installed (Automated)                                                  |  x  |     |     |
| 2.2.15    | Ensure mail transfer agent is configured for local-only mode (Automated)                        |  x  |     |     |
| 2.2.16    | Ensure rsync service is either not installed or masked (Automated)                              |  x  |     |     |
| 2.3       | **Service Clients**                                                                             |  x  |     |     |
| 2.3.1     | Ensure NIS Client is not installed (Automated)                                                  |  x  |     |     |
| 2.3.2     | Ensure rsh client is not installed (Automated)                                                  |  x  |     |     |
| 2.3.3     | Ensure talk client is not installed (Automated)                                                 |  x  |     |     |
| 2.3.4     | Ensure telnet client is not installed (Automated)                                               |  x  |     |     |
| 2.3.5     | Ensure LDAP client is not installed (Automated)                                                 |  x  |     |     |
| 2.3.6     | Ensure RPC is not installed (Automated)                                                         |  x  |     |     |
| 2.4       | Ensure nonessential services are removed or masked (Manual)                                     |  x  |     |     |
| 3         | **Network Configuration**                                                                       |     |  x  |     |
| 3.1       | **Disable unused network protocols and devices**                                                |     |  x  |     |
| 3.1.1     | Ensure system is checked to determine if IPv6 is enabled (Manual)                               |  x  |     |     |
| 3.1.2     | Ensure wireless interfaces are disabled (Automated)                                             |     |     |  x  |
| 3.2       | **Network Parameters (Host Only)**                                                              |  x  |     |     |
| 3.2.1     | Ensure packet redirect sending is disabled (Automated)                                          |  x  |     |     |
| 3.2.2     | Ensure IP forwarding is disabled (Automated)                                                    |  x  |     |     |
| 3.3       | **Network Parameters (Host and Router)**                                                        |  x  |     |     |
| 3.3.1     | Ensure source routed packets are not accepted (Automated)                                       |  x  |     |     |
| 3.3.2     | Ensure ICMP redirects are not accepted (Automated)                                              |  x  |     |     |
| 3.3.3     | Ensure secure ICMP redirects are not accepted (Automated)                                       |  x  |     |     |
| 3.3.4     | Ensure suspicious packets are logged (Automated)                                                |  x  |     |     |
| 3.3.5     | Ensure broadcast ICMP requests are ignored (Automated)                                          |  x  |     |     |
| 3.3.6     | Ensure bogus ICMP responses are ignored (Automated)                                             |  x  |     |     |
| 3.3.7     | Ensure Reverse Path Filtering is enabled (Automated)                                            |  x  |     |     |
| 3.3.8     | Ensure TCP SYN Cookies is enabled (Automated)                                                   |  x  |     |     |
| 3.3.9     | Ensure IPv6 router advertisements are not accepted (Automated)                                  |  x  |     |     |
| 3.4       | **Uncommon Network Protocols**                                                                  |  x  |     |     |
| 3.4.1     | Ensure DCCP is disabled (Automated)                                                             |  x  |     |     |
| 3.4.2     | Ensure SCTP is disabled (Automated)                                                             |  x  |     |     |
| 3.4.3     | Ensure RDS is disabled (Automated)                                                              |  x  |     |     |
| 3.4.4     | Ensure TIPC is disabled (Automated)                                                             |  x  |     |     |
| 3.5       | **Firewall Configuration**                                                                      |     |  x  |     |
| 3.5.1     | **Configure UncomplicatedFirewall**                                                             |     |  x  |     |
| 3.5.1.1   | Ensure ufw is installed (Automated)                                                             |  x  |     |     |
| 3.5.1.2   | Ensure iptables-persistent is not installed with ufw (Automated)                                |  x  |     |     |
| 3.5.1.3   | Ensure ufw service is enabled (Automated)                                                       |  x  |     |     |
| 3.5.1.4   | Ensure ufw loopback traffic is configured (Automated)                                           |  x  |     |     |
| 3.5.1.5   | Ensure ufw outbound connections are configured (Manual)                                         |  x  |     |     |
| 3.5.1.6   | Ensure ufw firewall rules exist for all open ports (Automated)                                  |     |     |  x  |
| 3.5.1.7   | Ensure ufw default deny firewall policy (Automated)                                             |  x  |     |     |
| 3.5.2     | **Configure nftables**                                                                          |  x  |     |     |
| 3.5.2.1   | Ensure nftables is installed (Automated)                                                        |  x  |     |     |
| 3.5.2.2   | Ensure ufw is uninstalled or disabled with nftables (Automated)                                 |  x  |     |     |
| 3.5.2.3   | Ensure iptables are flushed with nftables (Manual)                                              |  x  |     |     |
| 3.5.2.4   | Ensure a nftables table exists (Automated)                                                      |  x  |     |     |
| 3.5.2.5   | Ensure nftables base chains exist (Automated)                                                   |  x  |     |     |
| 3.5.2.6   | Ensure nftables loopback traffic is configured (Automated)                                      |  x  |     |     |
| 3.5.2.7   | Ensure nftables outbound and established connections are configured (Manual)                    |  x  |     |     |
| 3.5.2.8   | Ensure nftables default deny firewall policy (Automated)                                        |  x  |     |     |
| 3.5.2.9   | Ensure nftables service is enabled (Automated)                                                  |  x  |     |     |
| 3.5.2.10  | Ensure nftables rules are permanent (Automated)                                                 |  x  |     |     |
| 3.5.3     | **Configure iptables**                                                                          |  x  |     |     |
| 3.5.3.1   | **Configure iptables software**                                                                 |  x  |     |     |
| 3.5.3.1.1 | Ensure iptables packages are installed (Automated)                                              |  x  |     |     |
| 3.5.3.1.2 | Ensure nftables is not installed with iptables (Automated)                                      |  x  |     |     |
| 3.5.3.1.3 | Ensure ufw is uninstalled or disabled with iptables (Automated)                                 |  x  |     |     |
| 3.5.3.2   | **Configure IPv4 iptables**                                                                     |  x  |     |     |
| 3.5.3.2.1 | Ensure iptables default deny firewall policy (Automated)                                        |  x  |     |     |
| 3.5.3.2.2 | Ensure iptables loopback traffic is configured (Automated)                                      |  x  |     |     |
| 3.5.3.2.3 | Ensure iptables outbound and established connections are configured (Manual)                    |  x  |     |     |
| 3.5.3.2.4 | Ensure iptables firewall rules exist for all open ports (Automated)                             |  x  |     |     |
| 3.5.3.3   | **Configure IPv6 ip6tables**                                                                    |  x  |     |     |
| 3.5.3.3.1 | Ensure ip6tables default deny firewall policy (Automated)                                       |  x  |     |     |
| 3.5.3.3.2 | Ensure ip6tables loopback traffic is configured (Automated)                                     |  x  |     |     |
| 3.5.3.3.3 | Ensure ip6tables outbound and established connections are configured (Manual)                   |  x  |     |     |
| 3.5.3.3.4 | Ensure ip6tables firewall rules exist for all open ports (Automated)                            |  x  |     |     |
| 4         | **Logging and Auditing**                                                                        |     |  x  |     |
| 4.1       | **Configure System Accounting (auditd)**                                                        |     |  x  |     |
| 4.1.1     | **Ensure auditing is enabled**                                                                  |  x  |     |     |
| 4.1.1.1   | Ensure auditd is installed (Automated)                                                          |  x  |     |     |
| 4.1.1.2   | Ensure auditd service is enabled and active (Automated)                                         |  x  |     |     |
| 4.1.1.3   | Ensure auditing for processes that start prior to auditd is enabled (Automated)                 |  x  |     |     |
| 4.1.1.4   | Ensure audit_backlog_limit is sufficient (Automated)                                            |  x  |     |     |
| 4.1.2     | **Configure Data Retention**                                                                    |  x  |     |     |
| 4.1.2.1   | Ensure audit log storage size is configured (Automated)                                         |  x  |     |     |
| 4.1.2.2   | Ensure audit logs are not automatically deleted (Automated)                                     |  x  |     |     |
| 4.1.2.3   | Ensure system is disabled when audit logs are full (Automated)                                  |  x  |     |     |
| 4.1.3     | **Configure auditd rules**                                                                      |     |  x  |     |
| 4.1.3.1   | Ensure changes to system administration scope (sudoers) is collected (Automated)                |  x  |     |     |
| 4.1.3.2   | Ensure actions as another user are always logged (Automated)                                    |  x  |     |     |
| 4.1.3.3   | Ensure events that modify the sudo log file are collected (Automated)                           |  x  |     |     |
| 4.1.3.4   | Ensure events that modify date and time information are collected (Automated)                   |  x  |     |     |
| 4.1.3.5   | Ensure events that modify the system's network environment are collected (Automated)            |  x  |     |     |
| 4.1.3.6   | Ensure use of privileged commands are collected (Automated)                                     |     |  x  |     |
| 4.1.3.7   | Ensure unsuccessful file access attempts are collected (Automated)                              |  x  |     |     |
| 4.1.3.8   | Ensure events that modify user/group information are collected (Automated)                      |  x  |     |     |
| 4.1.3.9   | Ensure discretionary access control permission modification events are collected (Automated)    |  x  |     |     |
| 4.1.3.10  | Ensure successful file system mounts are collected (Automated)                                  |  x  |     |     |
| 4.1.3.11  | Ensure session initiation information is collected (Automated)                                  |  x  |     |     |
| 4.1.3.12  | Ensure login and logout events are collected (Automated)                                        |  x  |     |     |
| 4.1.3.13  | Ensure file deletion events by users are collected (Automated)                                  |  x  |     |     |
| 4.1.3.14  | Ensure events that modify the system's Mandatory Access Controls are collected (Automated)      |  x  |     |     |
| 4.1.3.15  | Ensure successful and unsuccessful attempts to use the chcon command are recorded (Automated)   |  x  |     |     |
| 4.1.3.16  | Ensure successful and unsuccessful attempts to use the setfacl command are recorded (Automated) |  x  |     |     |
| 4.1.3.17  | Ensure successful and unsuccessful attempts to use the chacl command are recorded (Automated)   |  x  |     |     |
| 4.1.3.18  | Ensure successful and unsuccessful attempts to use the usermod command are recorded (Automated) |  x  |     |     |
| 4.1.3.19  | Ensure kernel module loading unloading and modification is collected (Automated)                |  x  |     |     |
| 4.1.3.20  | Ensure the audit configuration is immutable (Automated)                                         |  x  |     |     |
| 4.1.3.21  | Ensure the running and on disk configuration is the same (Manual)                               |     |     |  x  |
| 4.1.4     | **Configure auditd file access**                                                                |     |  x  |     |
| 4.1.4.1   | Ensure audit log files are mode 0640 or less permissive (Automated)                             |     |  x  |     |
| 4.1.4.2   | Ensure only authorized users own audit log files (Automated)                                    |     |  x  |     |
| 4.1.4.3   | Ensure only authorized groups are assigned ownership of audit log files (Automated)             |     |  x  |     |
| 4.1.4.4   | Ensure the audit log directory is 0750 or more restrictive (Automated)                          |  x  |     |     |
| 4.1.4.5   | Ensure audit configuration files are 640 or more restrictive (Automated)                        |  x  |     |     |
| 4.1.4.6   | Ensure audit configuration files are owned by root (Automated)                                  |  x  |     |     |
| 4.1.4.7   | Ensure audit configuration files belong to group root (Automated)                               |  x  |     |     |
| 4.1.4.8   | Ensure audit tools are 755 or more restrictive (Automated)                                      |  x  |     |     |
| 4.1.4.9   | Ensure audit tools are owned by root (Automated)                                                |  x  |     |     |
| 4.1.4.10  | Ensure audit tools belong to group root (Automated)                                             |  x  |     |     |
| 4.1.4.11  | Ensure cryptographic mechanisms are used to protect the integrity of audit tools (Automated)    |  x  |     |     |
| 4.2       | **Configure Logging**                                                                           |     |  x  |     |
| 4.2.1     | **Configure journald**                                                                          |     |  x  |     |
| 4.2.1.1   | **Ensure journald is configured to send logs to a remote log host**                             |     |  x  |     |
| 4.2.1.1.1 | Ensure systemd-journal-remote is installed (Automated)                                          |     |  x  |     |
| 4.2.1.1.2 | Ensure systemd-journal-remote is configured (Manual)                                            |     |  x  |     |
| 4.2.1.1.3 | Ensure systemd-journal-remote is enabled (Manual)                                               |  x  |     |     |
| 4.2.1.1.4 | Ensure journald is not configured to receive logs from a remote client (Automated)              |  x  |     |     |
| 4.2.1.2   | Ensure journald service is enabled (Automated)                                                  |     |     |  x  |
| 4.2.1.3   | Ensure journald is configured to compress large log files (Automated)                           |  x  |     |     |
| 4.2.1.4   | Ensure journald is configured to write logfiles to persistent disk (Automated)                  |  x  |     |     |
| 4.2.1.5   | Ensure journald is not configured to send logs to rsyslog (Manual)                              |  x  |     |     |
| 4.2.1.6   | Ensure journald log rotation is configured per site policy (Manual)                             |     |     |  x  |
| 4.2.1.7   | Ensure journald default file permissions configured (Manual)                                    |     |     |  x  |
| 4.2.2     | **Configure rsyslog**                                                                           |     |  x  |     |
| 4.2.2.1   | Ensure rsyslog is installed (Automated)                                                         |  x  |     |     |
| 4.2.2.2   | Ensure rsyslog service is enabled (Automated)                                                   |  x  |     |     |
| 4.2.2.3   | Ensure journald is configured to send logs to rsyslog (Manual)                                  |  x  |     |     |
| 4.2.2.4   | Ensure rsyslog default file permissions are configured (Automated)                              |  x  |     |     |
| 4.2.2.5   | Ensure logging is configured (Manual)                                                           |     |     |  x  |
| 4.2.2.6   | Ensure rsyslog is configured to send logs to a remote log host (Manual)                         |     |     |  x  |
| 4.2.2.7   | Ensure rsyslog is not configured to receive logs from a remote client (Automated)               |  x  |     |     |
| 4.2.3     | Ensure all logfiles have appropriate permissions and ownership (Automated)                      |     |     |  x  |
| 5         | **Access, Authentication and Authorization**                                                    |     |     |     |
| 5.1       | **Configure time-based job schedulers**                                                         |  x  |     |     |
| 5.1.1     | Ensure cron daemon is enabled and running (Automated)                                           |  x  |     |     |
| 5.1.2     | Ensure permissions on /etc/crontab are configured (Automated)                                   |  x  |     |     |
| 5.1.3     | Ensure permissions on /etc/cron.hourly are configured (Automated)                               |  x  |     |     |
| 5.1.4     | Ensure permissions on /etc/cron.daily are configured (Automated)                                |  x  |     |     |
| 5.1.5     | Ensure permissions on /etc/cron.weekly are configured (Automated)                               |  x  |     |     |
| 5.1.6     | Ensure permissions on /etc/cron.monthly are configured (Automated)                              |  x  |     |     |
| 5.1.7     | Ensure permissions on /etc/cron.d are configured (Automated)                                    |  x  |     |     |
| 5.1.8     | Ensure cron is restricted to authorized users (Automated)                                       |  x  |     |     |
| 5.1.9     | Ensure at is restricted to authorized users (Automated)                                         |  x  |     |     |
| 5.2       | **Configure SSH Server**                                                                        |  x  |     |     |
| 5.2.1     | Ensure permissions on /etc/ssh/sshd_config are configured (Automated)                           |  x  |     |     |
| 5.2.2     | Ensure permissions on SSH private host key files are configured (Automated)                     |  x  |     |     |
| 5.2.3     | Ensure permissions on SSH public host key files are configured (Automated)                      |  x  |     |     |
| 5.2.4     | Ensure SSH access is limited (Automated)                                                        |  x  |     |     |
| 5.2.5     | Ensure SSH LogLevel is appropriate (Automated)                                                  |  x  |     |     |
| 5.2.6     | Ensure SSH PAM is enabled (Automated)                                                           |  x  |     |     |
| 5.2.7     | Ensure SSH root login is disabled (Automated)                                                   |  x  |     |     |
| 5.2.8     | Ensure SSH HostbasedAuthentication is disabled (Automated)                                      |  x  |     |     |
| 5.2.9     | Ensure SSH PermitEmptyPasswords is disabled (Automated)                                         |  x  |     |     |
| 5.2.10    | Ensure SSH PermitUserEnvironment is disabled (Automated)                                        |  x  |     |     |
| 5.2.11    | Ensure SSH IgnoreRhosts is enabled (Automated)                                                  |  x  |     |     |
| 5.2.12    | Ensure SSH X11 forwarding is disabled (Automated)                                               |  x  |     |     |
| 5.2.13    | Ensure only strong Ciphers are used (Automated)                                                 |  x  |     |     |
| 5.2.14    | Ensure only strong MAC algorithms are used (Automated)                                          |  x  |     |     |
| 5.2.15    | Ensure only strong Key Exchange algorithms are used (Automated)                                 |  x  |     |     |
| 5.2.16    | Ensure SSH AllowTcpForwarding is disabled (Automated)                                           |  x  |     |     |
| 5.2.17    | Ensure SSH warning banner is configured (Automated)                                             |  x  |     |     |
| 5.2.18    | Ensure SSH MaxAuthTries is set to 4 or less (Automated)                                         |  x  |     |     |
| 5.2.19    | Ensure SSH MaxStartups is configured (Automated)                                                |  x  |     |     |
| 5.2.20    | Ensure SSH MaxSessions is set to 10 or less (Automated)                                         |  x  |     |     |
| 5.2.21    | Ensure SSH LoginGraceTime is set to one minute or less (Automated)                              |  x  |     |     |
| 5.2.22    | Ensure SSH Idle Timeout Interval is configured (Automated)                                      |  x  |     |     |
| 5.3       | **Configure privilege escalation**                                                              |  x  |     |     |
| 5.3.1     | Ensure sudo is installed (Automated)                                                            |  x  |     |     |
| 5.3.2     | Ensure sudo commands use pty (Automated)                                                        |  x  |     |     |
| 5.3.3     | Ensure sudo log file exists (Automated)                                                         |  x  |     |     |
| 5.3.4     | Ensure users must provide password for privilege escalation (Automated)                         |  x  |     |     |
| 5.3.5     | Ensure re-authentication for privilege escalation is not disabled globally (Automated)          |  x  |     |     |
| 5.3.6     | Ensure sudo authentication timeout is configured correctly (Automated)                          |  x  |     |     |
| 5.3.7     | Ensure access to the su command is restricted (Automated)                                       |  x  |     |     |
| 5.4       | **Configure PAM**                                                                               |     |  x  |     |
| 5.4.1     | Ensure password creation requirements are configured (Automated)                                |  x  |     |     |
| 5.4.2     | Ensure lockout for failed password attempts is configured (Automated)                           |  x  |     |     |
| 5.4.3     | Ensure password reuse is limited (Automated)                                                    |  x  |     |     |
| 5.4.4     | Ensure password hashing algorithm is up to date with the latest standards (Automated)           |  x  |     |     |
| 5.4.5     | Ensure all current passwords uses the configured hashing algorithm (Manual)                     |     |     |  x  |
| 5.5       | **User Accounts and Environment**                                                               |     |  x  |     |
| 5.5.1     | **Set Shadow Password Suite Parameters**                                                        |     |  x  |     |
| 5.5.1.1   | Ensure minimum days between password changes is configured (Automated)                          |  x  |     |     |
| 5.5.1.2   | Ensure password expiration is 365 days or less (Automated)                                      |  x  |     |     |
| 5.5.1.3   | Ensure password expiration warning days is 7 or more (Automated)                                |  x  |     |     |
| 5.5.1.4   | Ensure inactive password lock is 30 days or less (Automated)                                    |  x  |     |     |
| 5.5.1.5   | Ensure all users last password change date is in the past (Automated)                           |     |     |  x  |
| 5.5.2     | Ensure system accounts are secured (Automated)                                                  |  x  |     |     |
| 5.5.3     | Ensure default group for the root account is GID 0 (Automated)                                  |  x  |     |     |
| 5.5.4     | Ensure default user umask is 027 or more restrictive (Automated)                                |  x  |     |     |
| 5.5.5     | Ensure default user shell timeout is 900 seconds or less (Automated)                            |  x  |     |     |
| 6         | **System Maintenance**                                                                          |     |  x  |     |
| 6.1       | **System File Permissions**                                                                     |     |  x  |     |
| 6.1.1     | Ensure permissions on /etc/passwd are configured (Automated)                                    |  x  |     |     |
| 6.1.2     | Ensure permissions on /etc/passwd- are configured (Automated)                                   |  x  |     |     |
| 6.1.3     | Ensure permissions on /etc/group are configured (Automated)                                     |  x  |     |     |
| 6.1.4     | Ensure permissions on /etc/group- are configured (Automated)                                    |  x  |     |     |
| 6.1.5     | Ensure permissions on /etc/shadow are configured (Automated)                                    |  x  |     |     |
| 6.1.6     | Ensure permissions on /etc/shadow- are configured (Automated)                                   |  x  |     |     |
| 6.1.7     | Ensure permissions on /etc/gshadow are configured (Automated)                                   |  x  |     |     |
| 6.1.8     | Ensure permissions on /etc/gshadow- are configured (Automated)                                  |  x  |     |     |
| 6.1.9     | Ensure no world writable files exist (Automated)                                                |  x  |     |     |
| 6.1.10    | Ensure no unowned files or directories exist (Automated)                                        |     |  x  |     |
| 6.1.11    | Ensure no ungrouped files or directories exist (Automated)                                      |     |  x  |     |
| 6.1.12    | Audit SUID executables (Manual)                                                                 |     |  x  |     |
| 6.1.13    | Audit SGID executables (Manual)                                                                 |     |  x  |     |
| 6.2       | **Local User and Group Settings**                                                               |     |  x  |     |
| 6.2.1     | Ensure accounts in /etc/passwd use shadowed passwords (Automated)                               |  x  |     |     |
| 6.2.2     | Ensure /etc/shadow password fields are not empty (Automated)                                    |  x  |     |     |
| 6.2.3     | Ensure all groups in /etc/passwd exist in /etc/group (Automated)                                |     |  x  |     |
| 6.2.4     | Ensure shadow group is empty (Automated)                                                        |  x  |     |     |
| 6.2.5     | Ensure no duplicate UIDs exist (Automated)                                                      |     |  x  |     |
| 6.2.6     | Ensure no duplicate GIDs exist (Automated)                                                      |     |  x  |     |
| 6.2.7     | Ensure no duplicate user names exist (Automated)                                                |     |  x  |     |
| 6.2.8     | Ensure no duplicate group names exist (Automated)                                               |     |  x  |     |
| 6.2.9     | Ensure root PATH Integrity (Automated)                                                          |     |  x  |     |
| 6.2.10    | Ensure root is the only UID 0 account (Automated)                                               |     |  x  |     |
| 6.2.11    | Ensure local interactive user home directories exist (Automated)                                |  x  |     |     |
| 6.2.12    | Ensure local interactive users own their home directories (Automated)                           |  x  |     |     |
| 6.2.13    | Ensure local interactive user home directories are mode 750 or more restrictive (Automated)     |  x  |     |     |
| 6.2.14    | Ensure no local interactive user has .netrc files (Automated)                                   |  x  |     |     |
| 6.2.15    | Ensure no local interactive user has .forward files (Automated)                                 |  x  |     |     |
| 6.2.16    | Ensure no local interactive user has .rhosts files (Automated)                                  |  x  |     |     |
| 6.2.17    | Ensure local interactive user dot files are not group or world writable (Automated)             |  x  |     |     |

## License

MIT

---

## Resources

- <https://downloads.cisecurity.org/#/>
- <https://github.com/florianutz/ubuntu2004_cis>
