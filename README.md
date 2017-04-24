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

    python-netaddr

Install the callback plugin(s) if you want human readability:

    https://gist.github.com/cliffano/9868180
    plugins/callback/human_log_1.py

    https://gist.github.com/dmsimard/cd706de198c85a8255f6
    plugins/callback/human_log_2.py

    Version 1 + 2 compatible
    https://github.com/n0ts/ansible-human_log
    plugins/callback/human_log_1_2.py

to the appropriate location for the version of ansible in use. eg. Centos 6

    ansible 1 : callback_plugins = /usr/share/ansible_plugins/callback_plugins
    ansible 2 : callback_plugins = /usr/share/ansible/plugins/callback

ansible_decode-facts is a perl script that requires the following Perl
modules to be installed on your local ansible machine:

    File::Basename;
    File::Slurp;
    JSON::XS;

Where you have place the ansible/bin/ directory add it to your path. Therefore
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
but many are not and will work on other Operating Systems.

    ansible_acl-get - retrive the ACL of a file / directory
    ansible_acl-remove - remove an ACL on a file / directory 
    ansible_acl-set - set an ACL on a file / directory
    ansible_acl-xattr-get - get the Extended Attributes of a file / directory

    ansible_boot-rhel-recreate-rescue-boot-image - recreate with rescue boot image for RHEL >=7 and Fedora Systems.

    ansible_decode-facts - produce some human readable facts from the Ansible json fact files.

    ansible_find-etc-opt-rmpnew-files - find leftover rpmnew / rpmsave files in the /etc and /opt directories
    ansible_find-files - find files or directories. If the list of files are large then the list of files are uploaded instead of being displayed.

    ansible_gather-facts - gather facts about remote hosts and save to the facts/ directory

    ansible_net-close-network-port - close network port(s) on remote hosts IPTables / Firewalld
    ansible_net-open-network-port - open network port(s) remote hosts. IPTables / Firewalld

    ansible_ping-hosts - use ansible to ping remote hosts. This is not a traditional ping command.

    ansible_rpm-info - obtain information about a particular RPM package
    ansible_rpm-install-repo - install a 3rd party RPM repository
    ansible_rpm-is-rpm-installed - find out if an RPM is installed on a remote host
    ansible_rpm-list-files - list the files of an RPM package
    ansible_rpm-setup-nano - set up the nano editor and config file
    ansible_rpm-setup-shells - install a shell RPM eg tcsh and profile files.

    ansible_rpm-yum-dnf-check-update - check for RPM package updates
    ansible_rpm-yum-dnf-repolist - execute repolist all on RHEL hosts to show yum / dnf repository information.
    ansible_rpm-yum-dnf-update-rpm - update / install RPM packages

	ansible_scl-info - List any installed RHEL Software Collections using scl -l. Lists all collections or query by name.

	ansible_security-rhel-cve-2017-6074 - check for use-after-free in the IPv6 implementation of the DCCP protocol in the Linux kernel - CVE-2017-607
		Based upon CVE-2017-6074-1.sh from RedHat.
		https://access.redhat.com/security/vulnerabilities/2934281
    ansible_security-rhel-drown-test - check the OpenSSL RPM package version for the DROWN vunerability

    ansible_service-enable-disable-at-boot - enable / disable services to start up at boot time
    ansible_service-rhel-check-status - check the status of a service eg stopped / running
    ansible_service-start-stop-restart - start / stop / restart a service

    ansible_user-create-new-user - create a new user. no default password.
    ansible_user-disable-user-login - disable a user login
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
