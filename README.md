# Kaosagnt's Ansible Everyday Utils #

This project contains many of the Ansible playbooks that I use daily
as a Systems Administrator in the pursuit of easy server task automation.

## Installation ##

You will need to setup and install Ansible like you normally would before
using what is presented here. Hint: it uses ansible. https://www.ansible.com

Optional:
Create an ansible-everyday/bin/ansible_config file with the following content:

    # Config file. Point to where your ansible config and host files are located.
    ANSIBLE_CONF_PATH=
    ANSIBLE_HOSTS_PATH=

If you don't create the ansible_config file then the default
ansible-everyday/conf directory will be used. Make sure to copy your ansible
config and host files into that directory.

Requires the following Python modules to be installed locally on the machine
you use:

    python3-netaddr

If you see the error

	localhost failed | msg: You need to install "jmespath" prior to running json_query filter

on Centos 8/9 Stream (Presumably RHEL 8/9 as well) you will need to install

	python3-jmespath

Ansible >= 2.2 contains the stdout_callback plugin(s) option if you want
human readability.

    ansible.cfg
    stdout_callback = <module_name>

skippy, debug, minimal, yaml, unixy and many more.
See: https://docs.ansible.com/ansible/2.5/plugins/callback.html

Modern Ansible seems to be split into pieces. Ansible Core no longer contains the
callbacks. You may nee to run the following to install them.

	ansible-galaxy collection install community.general
	ansible-galaxy collection list
	
ansible_decode-facts is a perl script that requires the following Perl
modules to be installed on your local ansible machine:

    File::Basename;
    File::Slurp;
    JSON::XS;

Where you have place the ansible/bin/ directory add it to your path. Therefore,
if you use a shell with name completion, it will make life easier for you.

## Available Commands / Playbooks ##

Contained in the ansible-everyday/bin/ directory are shell scripts that invoke
ansible-playbook and corresponding Playbook files in the
ansbile-everyday/playbook/ directory.

A lot of these Ansible Playbooks ARE interactive as they are used by myself
almost on a daily basis. Therefore you will have to fill out some information
rather than to continually rewrite playbooks for very common tasks. These
playbooks are not a substitute for writing Ansbile Playbooks in the traditional
sense using roles and the like. You will still need to write those if you are
deploying 100 new servers. These scripts/playbooks allow you to get those
everyday administration tasks completed.

A lot of the playbooks are designed for RHEL (or it's derivatives eg Centos/Fedora)
and Debian / Ubuntu derived systems but many are not and will work on
other Operating Systems.

    ansible_acl-get - retrive the ACL of a file / directory
    ansible_acl-remove - remove an ACL on a file / directory 
    ansible_acl-set - set an ACL on a file / directory
    ansible_acl-stat-file - get the information of a file / directory specified using stat
    ansible_acl-xattr-get - get the Extended Attributes of a file / directory
    
    ansible_boot-rhel-recreate-rescue-boot-image - recreate with rescue boot image for RHEL >=7 and Fedora Systems
    
    ansible_deb-apt-file-search - find which Deb package provides a file
    ansible_deb-apt-setup-shells - install a shell Deb package eg tcsh and profile files
    ansible_deb-apt-update - check for Deb package updates
    ansible_deb-apt-upgrade-deb - update / install Deb packages
    ansible_deb-info - obtain information about a particular Deb package
    ansible_deb-is-deb-installed - find out if a Deb package is installed on a remote host
    
    ansible_decode-facts - produce some human readable facts from the Ansible json fact files
    
    ansible_editors-setup-nano - set up the nano editor and config file
    
    ansible_find-etc-opt-rmpnew-files - find leftover rpmnew / rpmsave files in the /etc and /opt directories
    ansible_find-files - find files or directories. If the list of files are large then the list of files are uploaded instead of being displayed
    
    ansible_gather-facts - gather facts about remote hosts and save to the facts/ directory
    
    ansible_net-close-network-port-firewalld - close network port(s) on remote hosts. Firewalld
    ansible_net-open-network-port-firewalld - open network port(s) remote hosts. Firewalld
    ansible_net-list-all-zones-firewalld - list firewalld zone information
    ansible_net-close-network-port-iptables - close network port(s) on remote hosts. IPTables
    ansible_net-open-network-port-iptables - open network port(s) remote hosts. IPTables
	
	ansible_openbsd-pkg-add-update-package - add or update packages on an OpenBSD system
	ansible_openbsd-pkg-info-list-files - list the files of an installed OpenBSD package
	ansible_openbsd-pkg-info-list-installed-packages - obtain a list of packages installed on an OpenBSD system
    
    ansible_ping-hosts - use ansible to ping remote hosts. This is not a traditional ping command
    
    ansible_rpm-info - obtain information about a particular RPM package
    ansible_rpm-install-repo - install a 3rd party RPM repository
    ansible_rpm-is-rpm-installed - find out if an RPM is installed on a remote host
    ansible_rpm-list-files - list the files of an RPM package
    ansible_rpm-setup-shells - install a shell RPM eg tcsh and profile files.
    ansible_rpm-whatprovides - find which RPM package provides a file
    
    ansible_rpm-yum-dnf-check-update - check for RPM package updates
    ansible_rpm-yum-dnf-repolist - execute repolist all on RHEL hosts to show yum / dnf repository information.
    ansible_rpm-yum-dnf-update-rpm - update / install RPM packages
    
    ansible_scl-info - List any installed RHEL Software Collections using scl -l. Lists all collections or query by name
    
    ansible_security-check-ssl-tls-certificate-expired - Checks SSL / TLS security certificate files to see whether they have expired or will expire
     	within the next 2 weeks
	ansible_security-check-remote-ssl-tls-certificate-expired-https - Checks remotely via HTTPS request SSL / TLS security certificates to see whether
		they have expired or will expire within the next 2 weeks
	ansible_security-cve-2021-42574-42694-find_unicode_control2 - check for RHSB-2021-007 Trojan source attacks (CVE-2021-42574,CVE-2021-42694)
		https://access.redhat.com/security/vulnerabilities/RHSB-2021-007
	ansible_security-linux-bsd-github-speed47-spectre-meltdown-checker - more generic check for Kernel Side-Channel Attacks - CVE-2017-5754
		CVE-2017-5753 CVE-2017-5715
		https://github.com/speed47/spectre-meltdown-checker - also works on some BSD operating systems
    
	ansible_security-rhel-cve-2017-6074 - check for use-after-free in the IPv6 implementation of the DCCP protocol in the Linux kernel - CVE-2017-607
		https://access.redhat.com/security/vulnerabilities/2934281
	ansible_security-rhel-cve-2017-14491- check for dnsmasq: Multiple Critical and Important vulnerabilities - CVE-2017-14491
		https://access.redhat.com/security/vulnerabilities/3199382
	ansible_security-rhel-cve-2017-1000251 - check for Blueborne - Linux Kernel Remote Denial of Service in Bluetooth subsystem - CVE-2017-1000251
		https://access.redhat.com/security/vulnerabilities/CVE-2017-1000251
	ansible_security-rhel-cve-2017-1000251 - check for Linux Kernel load_elf_binary does not allocate sufficient space - CVE-2017-1000253
		https://access.redhat.com/security/vulnerabilities/CVE-2017-1000253
	ansible_security-rhel-cve-2017-1000366 - check for Stack Guard Page Circumvention Affecting Multiple Packages CVE-2017-1000366
		https://access.redhat.com/security/vulnerabilities/stackguard
	ansible_security-rhel-cve-2018-3620-3645 - check for L1TF - L1 Terminal Fault Attack - CVE-2018-3620 / CVE-2018-3645
		https://access.redhat.com/security/vulnerabilities/L1TF
	ansible_security-rhel-cve-2018-3639 - check for Kernel Side-Channel Attack using Speculative Store Bypass - CVE-2018-3639
		https://access.redhat.com/security/vulnerabilities/ssbd
	ansible_security-rhel-cve-2018-12130 - check for MDS - Microarchitectural Store Buffer Data - CVE-2018-12130, CVE-2018-12126, CVE-2018-12127,
		CVE-2019-11091 https://access.redhat.com/security/vulnerabilities/mds
	ansible_security-rhel-cve-2018-12207 - check for Machine Check Error on Page Size Change - CVE-2018-12207
		https://access.redhat.com/security/vulnerabilities/ifu-page-mce 
	ansible_security-rhel-cve-2019-5736 - check for runc - Malicious container escape - CVE-2019-5736
		https://access.redhat.com/security/vulnerabilities/runcescape
	ansible_security-rhel-tcp-sack-panic-cve-2019-11477-8-9 - check for TCP SACK PANIC - Kernel vulnerabilities - CVE-2019-11477,
		CVE-2019-11478 & CVE-2019-11479 https://access.redhat.com/security/vulnerabilities/tcpsack
	ansible_security-rhel-cve-2019-14835 - check for VHOST-NET guest to host escape - Kernel vulnerability CVE-2019-14835
		https://access.redhat.com/security/vulnerabilities/kernel-vhost
	ansible_security-rhel-cve-2020-10713 - Boot Hole Vulnerability - GRUB 2 boot loader
		https://access.redhat.com/security/vulnerabilities/grub2bootloader
	ansible_secuitry-rhel-DNSpooq - Multiple vulnerabilities within dnsmasq CVE-2020-25681, CVE-2020-25682, CVE-2020-25683, CVE-2020-25684,
		CVE-2020-25685, CVE-2020-25686, CVE-2020-25687
		https://access.redhat.com/security/vulnerabilities/RHSB-2021-001
	ansible_security-rhel-cve-2021-3156 - Privilege escalation via command line argument parsing - sudo
		https://access.redhat.com/security/vulnerabilities/RHSB-2021-002
	ansible_security-rhel-cve-2020-14372 - ACPI Secure Boot vulnerability - GRUB 2 CVE-2020-14372
		https://access.redhat.com/security/vulnerabilities/RHSB-2021-003
	ansible_security-rhel-cve-2021-30465 - RHSB-2021-004 Symlink-Exchange attack - runc - CVE-2021-30465
		https://access.redhat.com/security/vulnerabilities/RHSB-2021-004
	ansible_security-rhel-cve-2021-33909 - RHSB-2021-006 Long path name in mountpoint flaws in the kernel and systemd
		https://access.redhat.com/security/vulnerabilities/RHSB-2021-006
	ansible_security-rhel-cve-2021-43527 - RHSB-2021-008 NSS Memory corruption when decoding DSA signatures
		https://access.redhat.com/security/vulnerabilities/RHSB-2021-008
	ansible_security-rhel-cve-2021-4034 - RHSB-2022-001 Polkit Privilege Escalation - (CVE-2021-4034)
		https://access.redhat.com/security/vulnerabilities/RHSB-2022-001
	ansible_security-rhel-cve-2022-0847 - RHSB-2022-002 Dirty Pipe - kernel arbitrary file manipulation - (CVE-2022-0847)
		https://access.redhat.com/security/vulnerabilities/RHSB-2022-002
	ansible_security-rhel-drown-test - check the OpenSSL RPM package version for the DROWN vunerability
	ansible_security-spectre-meltdown - check for Kernel Side-Channel Attacks - CVE-2017-5754 CVE-2017-5753 CVE-2017-5715
		https://access.redhat.com/security/vulnerabilities/speculativeexecution
    
    ansible_service-enable-disable-at-boot - enable / disable services to start up at boot time
    ansible_service-rhel-check-status - check the status of a service eg stopped / running
    ansible_service-start-stop-restart - start / stop / restart a service
    
    ansible_ubuntu-security-status - Execute ubuntu-security-status / ubuntu-support-status on Ubuntu hosts
    
    ansible_user-create-new-user - create a new user. no default password.
    ansible_user-disable-user-login - disable a user login
    ansible_user-htpasswd-add-user - create / add a new user to an Apache htpasswd file
    ansible_user-htpasswd-remove-user - remove a user from an Apache htpasswd file
    ansible_user-remove-existing-user - delete a user account
    ansible_user-remove-ssh-public-key - remove a ssh public key from a user account
    ansible_user-renable-user-login - renable a disabled user account
    ansible_user-setup-ssh-public-key - add a ssh public key to a user account

All command line arguments are pass through to the ansible-playbook command. eg

    ansible_rpm-yum-dnf-check-update -e hosts=webservers,ted.sample.com

All of the bin/ansible_* scripts by default act on localhost. This is so one
can screw up your local machine BEFORE destroying a remote host. To make the
playbook act on remote hosts, use the
    -e hosts=
command line argument to list hosts or groups of hosts as defined within your
ansible hosts file. You can use a comma seperated list.

TODO: Finish this documentation...... 
