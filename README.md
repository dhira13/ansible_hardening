# Hardening - the Ansible role

An [Ansible](https://www.ansible.com/) role to make a AlmaLinux, Debian, or
Ubuntu server a bit more secure.
[systemd edition](https://freedesktop.org/wiki/Software/systemd/).

Requires Ansible >= 2.12.

Available on
[Ansible Galaxy](https://galaxy.ansible.com/dhira13/ansible_hardening).

[AlmaLinux 8](https://almalinux.org/),
[Debian 11](https://www.debian.org/),
Ubuntu [20.04 LTS (Focal Fossa)](https://releases.ubuntu.com/focal/) and
[22.04 LTS (Jammy Jellyfish)](https://releases.ubuntu.com/jammy/) are supported.

> **Note**
>
> Do not use this role without first testing in a non-operational environment.

> **Note**
>
> There is a [SLSA](https://slsa.dev/) artifact present under the
> [slsa action workflow](https://github.com/dhira13/ansible_hardening/actions/workflows/slsa.yml)
> for verification.

## Dependencies

None.

## Examples

### Playbook

```yaml
---
- hosts: localhost
  any_errors_fatal: true
  tasks:
    - name: Include the hardening role
      ansible.builtin.include_role:
        name: dhira13.ansible_hardening
      vars:
        block_blacklisted: true
        sshd_admin_net:
          - 10.0.2.0/24
          - 192.168.0.0/24
          - 192.168.1.0/24
        suid_sgid_permissions: false
...
```

### ansible-pull with git checkout

```yaml
---
- hosts: localhost
  any_errors_fatal: true
  tasks:
    - name: Install git
      become: true
      ansible.builtin.package:
        name: git
        state: present

    - name: Checkout dhira13.ansible_hardening
      become: true
      ansible.builtin.git:
        repo: 'https://github.com/dhira13/ansible_hardening'
        dest: /etc/ansible/roles/dhira13.ansible_hardening
        version: master

    - name: Include the hardening role
      ansible.builtin.include_role:
        name: dhira13.ansible_hardening
      vars:
        block_blacklisted: true
        sshd_admin_net:
          - 10.0.2.0/24
          - 192.168.0.0/24
          - 192.168.1.0/24
        suid_sgid_permissions: false
...
```

## Note regarding UFW firewall rules

Instead of resetting `ufw` every run and by doing so causing network traffic
disruption, the role deletes every `ufw` rule without
`comment: ansible managed` task parameter and value.

The role also sets default deny policies, which means that firewall rules
needs to be created for any additional ports except those specified in
the `sshd_port` and `ufw_outgoing_traffic` variables.

## Task Execution and Structure

See [STRUCTURE.md](STRUCTURE.md) for tree of the role structure.

## Role testing

See [TESTING.md](TESTING.md).

## Role Variables with defaults

### ./defaults/main/auditd.yml

```yaml
auditd_apply_audit_rules: true
auditd_action_mail_acct: root
auditd_admin_space_left_action: suspend
auditd_disk_error_action: suspend
auditd_disk_full_action: suspend
auditd_max_log_file: 8
auditd_max_log_file_action: keep_logs
auditd_mode: 1
auditd_num_logs: 5
auditd_space_left: 75
auditd_space_left_action: email
grub_audit_backlog_cmdline: audit_backlog_limit=8192
grub_audit_cmdline: audit=1
```

### ./defaults/main/compilers.yml

```yaml
compilers:
  - as
  - cargo
  - cc
  - cc-[0-9]*
  - clang-[0-9]*
  - go
  - make
  - rustc
```

### ./defaults/main/disablewireless.yml

```yaml
disable_wireless: false
```

### ./defaults/main/dns.yml

```yaml
dns: 127.0.0.1 1.1.1.1
fallback_dns: 9.9.9.9 1.0.0.1
dnssec: allow-downgrade
dns_over_tls: opportunistic
```

### ./defaults/main/ipv6.yml

```yaml
disable_ipv6: false
ipv6_disable_sysctl_settings:
  net.ipv6.conf.all.disable_ipv6: 1
  net.ipv6.conf.default.disable_ipv6: 1
```

### ./defaults/main/limits.yml

```yaml
limit_nofile_hard: 10240
limit_nofile_soft: 5120
limit_nproc_hard: 10240
limit_nproc_soft: 5120
```

### ./defaults/main/misc.yml

```yaml
install_aide: true
reboot_ubuntu: false
redhat_signing_keys:
  - 567E347AD0044ADE55BA8A5F199E2F91FD431D51
  - 47DB287789B21722B6D95DDE5326810137017186
epel7_signing_keys:
  - 91E97D7C4A5E96F17F3E888F6A2FAEA2352C64E5
epel8_signing_keys:
  - 94E279EB8D8F25B21810ADF121EA45AB2F86D6A1
epel9_signing_keys:
  - FF8AD1344597106ECE813B918A3872BF3228467C
```

### ./defaults/main/module_blocklists.yml

```yaml
block_blacklisted: false
fs_modules_blocklist:
  - cramfs
  - freevxfs
  - hfs
  - hfsplus
  - jffs2
  - squashfs
  - udf
misc_modules_blocklist:
  - bluetooth
  - bnep
  - btusb
  - can
  - cpia2
  - firewire-core
  - floppy
  - ksmbd
  - n_hdlc
  - net-pf-31
  - pcspkr
  - soundcore
  - thunderbolt
  - usb-midi
  - usb-storage
  - uvcvideo
  - v4l2_common
net_modules_blocklist:
  - atm
  - dccp
  - sctp
  - rds
  - tipc
```

### ./defaults/main/mount.yml

```yaml
hide_pid: 2
process_group: root
```

### ./defaults/main/ntp.yml

```yaml
fallback_ntp: 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org
ntp: 0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org
```

### ./defaults/main/packages.yml

```yaml
system_upgrade: true
packages_blocklist:
  - apport*
  - autofs
  - avahi*
  - avahi-*
  - beep
  - pastebinit
  - popularity-contest
  - prelink
  - rpcbind
  - rsh*
  - rsync
  - talk*
  - telnet*
  - tftp*
  - whoopsie
  - xinetd
  - yp-tools
  - ypbind
packages_debian:
  - acct
  - apparmor-profiles
  - apparmor-utils
  - apt-show-versions
  - audispd-plugins
  - auditd
  - cracklib-runtime
  - debsums
  - gnupg2
  - haveged
  - libpam-apparmor
  - libpam-cap
  - libpam-modules
  - libpam-pwquality
  - libpam-tmpdir
  - lsb-release
  - needrestart
  - openssh-server
  - postfix
  - rkhunter
  - rsyslog
  - sysstat
  - tcpd
  - vlock
  - wamerican
  - zsh
  - tree
  - vifm
  - pgcli
  - postgresql
  - libpam-google-authenticator
packages_redhat:
  - audispd-plugins
  - audit
  - cracklib
  - gnupg2
  - haveged
  - libpwquality
  - openssh-server
  - needrestart
  - postfix
  - psacct
  - rkhunter
  - rsyslog
  - rsyslog-gnutls
  - vlock
  - words
packages_ubuntu:
  - fwupd
  - secureboot-db
```

### ./defaults/main/password.yml

```yaml
crypto_policy: "DEFAULT:NO-SHA1"
pwquality_config:
  dcredit: -1
  dictcheck: 1
  difok: 8
  enforcing: 1
  lcredit: -1
  maxclassrepeat: 4
  maxrepeat: 3
  minclass: 4
  minlen: 15
  ocredit: -1
  ucredit: -1
```

### ./defaults/main/sshd.yml

```yaml
sshd_accept_env: LANG LC_*
sshd_admin_net:
  - 10.20.0.0/16
sshd_allow_agent_forwarding: 'yes'
sshd_allow_groups: sudo
sshd_allow_tcp_forwarding: 'yes'
sshd_authentication_methods: publickey
sshd_banner: /etc/issue.net
sshd_challenge_response_authentication: 'yes'
sshd_ciphers: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
sshd_client_alive_count_max: 1
sshd_client_alive_interval: 200
sshd_compression: 'no'
sshd_gssapi_authentication: 'no'
sshd_hostbased_authentication: 'no'
sshd_host_key_algorithms: ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ssh-rsa,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256
sshd_ignore_user_known_hosts: 'yes'
sshd_kerberos_authentication: 'no'
sshd_kex_algorithms: curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
sshd_login_grace_time: 120
sshd_log_level: VERBOSE
sshd_macs: hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
sshd_max_auth_tries: 3
sshd_max_sessions: 3
sshd_max_startups: 10:30:60
sshd_password_authentication: 'no'
sshd_permit_empty_passwords: 'no'
sshd_permit_root_login: 'no'
sshd_permit_user_environment: 'no'
sshd_port: 22
sshd_print_last_log: 'yes'
sshd_print_motd: 'no'
sshd_rekey_limit: 512M 1h
sshd_required_rsa_size: 2048
sshd_strict_modes: 'yes'
sshd_subsystem: sftp internal-sftp
sshd_tcp_keep_alive: 'no'
sshd_use_dns: 'no'
sshd_use_pam: 'yes'
sshd_x11_forwarding: 'no'
```

### ./defaults/main/suid_sgid_blocklist.yml

```yaml
suid_sgid_permissions: true
suid_sgid_blocklist:
  - 7z
  - ab
  - agetty
  - alpine
  - ansible-playbook
  - aoss
  - apt
  - apt-get
  - ar
  - aria2c
  - arj
  - arp
  - as
  - ascii-xfr
  - ascii85
  - ash
  - aspell
  - at
  - atobm
  - awk
  - aws
  - base32
  - base58
  - base64
  - basenc
  - basez
  - bash
  - batcat
  - bc
  - bconsole
  - bpftrace
  - bridge
  - bsd-write
  - bundle
  - bundler
  - busctl
  - busybox
  - byebug
  - bzip2
  - c89
  - c99
  - cabal
  - cancel
  - capsh
  - cat
  - cdist
  - certbot
  - chage
  - check_by_ssh
  - check_cups
  - check_log
  - check_memory
  - check_raid
  - check_ssl_cert
  - check_statusfile
  - chfn
  - chmod
  - choom
  - chown
  - chroot
  - chsh
  - cmp
  - cobc
  - column
  - comm
  - composer
  - cowsay
  - cowthink
  - cp
  - cpan
  - cpio
  - cpulimit
  - crash
  - crontab
  - csh
  - csplit
  - csvtool
  - cupsfilter
  - curl
  - cut
  - dash
  - date
  - dd
  - debugfs
  - dialog
  - diff
  - dig
  - dmesg
  - dmidecode
  - dmsetup
  - dnf
  - docker
  - dosbox
  - dpkg
  - dvips
  - easy_install
  - eb
  - ed
  - efax
  - emacs
  - env
  - eqn
  - espeak
  - ex
  - exiftool
  - expand
  - expect
  - facter
  - file
  - find
  - finger
  - fish
  - flock
  - fmt
  - fold
  - fping
  - ftp
  - fusermount
  - gawk
  - gcc
  - gcloud
  - gcore
  - gdb
  - gem
  - genie
  - genisoimage
  - ghc
  - ghci
  - gimp
  - ginsh
  - git
  - grc
  - grep
  - gtester
  - gzip
  - hd
  - head
  - hexdump
  - highlight
  - hping3
  - iconv
  - iftop
  - install
  - ionice
  - ip
  - irb
  - ispell
  - jjs
  - join
  - journalctl
  - jq
  - jrunscript
  - jtag
  - knife
  - ksh
  - ksshell
  - ksu
  - kubectl
  - latex
  - latexmk
  - ld.so
  - ldconfig
  - less
  - lftp
  - ln
  - loginctl
  - logsave
  - look
  - lp
  - ltrace
  - lua
  - lualatex
  - luatex
  - lwp-download
  - lwp-request
  - mail
  - make
  - man
  - mawk
  - mksh
  - mksh-static
  - mlocate
  - more
  - mosquitto
  - mount
  - mount.nfs
  - msfconsole
  - msgattrib
  - msgcat
  - msgconv
  - msgfilter
  - msgmerge
  - msguniq
  - mtr
  - multitime
  - mv
  - mysql
  - nano
  - nasm
  - nawk
  - nc
  - neofetch
  - netfilter-persistent
  - newgrp
  - nft
  - nice
  - nl
  - nm
  - nmap
  - node
  - nohup
  - npm
  - nroff
  - nsenter
  - ntfs-3g
  - octave
  - od
  - openssl
  - openvpn
  - openvt
  - opkg
  - pandoc
  - paste
  - pax
  - pdb
  - pdflatex
  - pdftex
  - perf
  - perl
  - perlbug
  - pg
  - php
  - pic
  - pico
  - pidstat
  - ping
  - ping6
  - pip
  - pkexec
  - pkg
  - posh
  - pppd
  - pr
  - pry
  - psad
  - psftp
  - psql
  - ptx
  - puppet
  - python
  - rake
  - rbash
  - readelf
  - red
  - redcarpet
  - restic
  - rev
  - rlogin
  - rlwrap
  - rpm
  - rpmdb
  - rpmquery
  - rpmverify
  - rsync
  - rtorrent
  - ruby
  - run-mailcap
  - run-parts
  - rview
  - rvim
  - sash
  - scanmem
  - scp
  - screen
  - script
  - scrot
  - sed
  - service
  - setarch
  - setfacl
  - setlock
  - sftp
  - sg
  - sh
  - shuf
  - slsh
  - smbclient
  - snap
  - socat
  - socket
  - soelim
  - softlimit
  - sort
  - split
  - sqlite3
  - ss
  - ssh
  - ssh-keygen
  - ssh-keyscan
  - sshpass
  - start-stop-daemon
  - stdbuf
  - strace
  - strings
  - su
  - sysctl
  - systemctl
  - systemd-resolve
  - tac
  - tail
  - tar
  - task
  - taskset
  - tasksh
  - tbl
  - tclsh
  - tcpdump
  - tcsh
  - tee
  - telnet
  - tex
  - tftp
  - tic
  - time
  - timedatectl
  - timeout
  - tmate
  - top
  - torify
  - torsocks
  - traceroute6.iputils
  - troff
  - tshark
  - ul
  - umount
  - unexpand
  - uniq
  - unshare
  - unzip
  - update-alternatives
  - uudecode
  - uuencode
  - valgrind
  - vi
  - view
  - vigr
  - vim
  - vimdiff
  - vipw
  - virsh
  - volatility
  - w3m
  - wall
  - watch
  - wc
  - wget
  - whiptail
  - whois
  - wireshark
  - wish
  - write
  - xargs
  - xdotool
  - xelatex
  - xetex
  - xmodmap
  - xmore
  - xpad
  - xxd
  - xz
  - yarn
  - yash
  - yelp
  - yum
  - zathura
  - zip
  - zsoelim
  - zypper
```

### ./defaults/main/sysctl.yml

```yaml
sysctl_dev_tty_ldisc_autoload: 0
sysctl_net_ipv6_conf_accept_ra_rtr_pref: 0

ipv4_sysctl_settings:
  net.ipv4.conf.all.accept_redirects: 0
  net.ipv4.conf.all.accept_source_route: 0
  net.ipv4.conf.all.log_martians: 1
  net.ipv4.conf.all.rp_filter: 1
  net.ipv4.conf.all.secure_redirects: 0
  net.ipv4.conf.all.send_redirects: 0
  net.ipv4.conf.all.shared_media: 0
  net.ipv4.conf.default.accept_redirects: 0
  net.ipv4.conf.default.accept_source_route: 0
  net.ipv4.conf.default.log_martians: 1
  net.ipv4.conf.default.rp_filter: 1
  net.ipv4.conf.default.secure_redirects: 0
  net.ipv4.conf.default.send_redirects: 0
  net.ipv4.conf.default.shared_media: 0
  net.ipv4.icmp_echo_ignore_broadcasts: 1
  net.ipv4.icmp_ignore_bogus_error_responses: 1
  net.ipv4.ip_forward: 0
  net.ipv4.tcp_challenge_ack_limit: 2147483647
  net.ipv4.tcp_invalid_ratelimit: 500
  net.ipv4.tcp_max_syn_backlog: 20480
  net.ipv4.tcp_rfc1337: 1
  net.ipv4.tcp_syn_retries: 5
  net.ipv4.tcp_synack_retries: 2
  net.ipv4.tcp_syncookies: 1

ipv6_sysctl_settings:
  net.ipv6.conf.all.accept_ra: 0
  net.ipv6.conf.all.accept_redirects: 0
  net.ipv6.conf.all.accept_source_route: 0
  net.ipv6.conf.all.forwarding: 0
  net.ipv6.conf.all.use_tempaddr: 2
  net.ipv6.conf.default.accept_ra: 0
  net.ipv6.conf.default.accept_ra_defrtr: 0
  net.ipv6.conf.default.accept_ra_pinfo: 0
  net.ipv6.conf.default.accept_ra_rtr_pref: 0
  net.ipv6.conf.default.accept_redirects: 0
  net.ipv6.conf.default.accept_source_route: 0
  net.ipv6.conf.default.autoconf: 0
  net.ipv6.conf.default.dad_transmits: 0
  net.ipv6.conf.default.max_addresses: 1
  net.ipv6.conf.default.router_solicitations: 0
  net.ipv6.conf.default.use_tempaddr: 2

generic_sysctl_settings:
  fs.protected_fifos: 2
  fs.protected_hardlinks: 1
  fs.protected_symlinks: 1
  fs.suid_dumpable: 0
  kernel.core_uses_pid: 1
  kernel.dmesg_restrict: 1
  kernel.kptr_restrict: 2
  kernel.panic: 60
  kernel.panic_on_oops: 60
  kernel.perf_event_paranoid: 3
  kernel.randomize_va_space: 2
  kernel.sysrq: 0
  kernel.unprivileged_bpf_disabled: 1
  kernel.yama.ptrace_scope: 2
  net.core.bpf_jit_harden: 2
  vm.max_map_count: 262144

conntrack_sysctl_settings:
  net.netfilter.nf_conntrack_max: 2000000
  net.netfilter.nf_conntrack_tcp_loose: 0
```

### ./defaults/main/ufw.yml

```yaml
ufw_enable: true
ufw_outgoing_traffic:
  - 22
  - 53
  - 80
  - 123
  - 443
  - 853
  - 5432
```

### ./defaults/main/users.yml

```yaml
delete_users:
  - games
  - gnats
  - irc
  - list
  - news
  - sync
  - uucp
```

## Recommended Reading

[Comparing the DISA STIG and CIS Benchmark values](https://github.com/dhira13/publications/blob/master/ubuntu_comparing_guides_benchmarks.md)

[Center for Internet Security Linux Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

[Common Configuration Enumeration](https://nvd.nist.gov/cce/index.cfm)

[DISA Security Technical Implementation Guides](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)

[SCAP Security Guides](https://static.open-scap.org/)

[Security focused systemd configuration](https://github.com/dhira13/ansible_hardening/blob/master/systemd.adoc)

## Contributing

Do you want to contribute? Great! Contributions are always welcome,
no matter how large or small. If you found something odd, feel free to submit a
issue, improve the code by creating a pull request, or by
[sponsoring this project](https://github.com/sponsors/dhira13).

## License

Apache License Version 2.0

## Author Information

[https://github.com/dhira13](https://github.com/dhira13 "github.com/dhira13")
