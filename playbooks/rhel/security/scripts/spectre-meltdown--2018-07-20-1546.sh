#!/bin/bash

# Copyright (C) 2018  Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

VERSION="2.8"

# Warning! Be sure to download the latest version of this script from its primary source:
# https://access.redhat.com/security/vulnerabilities/speculativeexecution
# DO NOT blindly trust any internet sources and NEVER do `curl something | bash`!

# This script is meant for simple detection of the vulnerability. Feel free to modify it for your
# environment or needs. For more advanced detection, consider Red Hat Insights:
# https://access.redhat.com/products/red-hat-insights#getstarted

# Checking against the list of vulnerable packages is necessary because of the way how features
# are back-ported to older versions of packages in various channels.

# With version 2.4 of this script, checks for "vulnerabilities" files in
# /sys/devices/system/cpu/vulnerabilities/ were added. These files are available in newer kernels,
# and state explicitly the system's vulnerability/mitigation state for Meltdown, Spectre V1, and
# Spectre V2. If present (all_vuln_files=1), those files will take precedence.
# Otherwise (all_vuln_files=0), as would be the case in some older pre-retpoline but post-
# Spectre/Meltdown kernels, the script will rely on its older detection mechanisms.

basic_args() {
    # Parses basic commandline arguments and sets basic environment.
    #
    # Args:
    #     parameters - an array of commandline arguments
    #
    # Side effects:
    #     Exits if --help parameters is used
    #     Sets COLOR constants and debug variable

    local parameters=( "$@" )

    RED="\\033[1;31m"
    YELLOW="\\033[1;33m"
    GREEN="\\033[1;32m"
    BOLD="\\033[1m"
    RESET="\\033[0m"
    for parameter in "${parameters[@]}"; do
        if [[ "$parameter" == "-h" || "$parameter" == "--help" ]]; then
            echo "Usage: $( basename "$0" ) [-n | --no-colors] [-d | --debug]"
            exit 1
        elif [[ "$parameter" == "-n" || "$parameter" == "--no-colors" ]]; then
            RED=""
            YELLOW=""
            GREEN=""
            BOLD=""
            RESET=""
        elif [[ "$parameter" == "-d" || "$parameter" == "--debug" ]]; then
            debug=true
        fi
    done
}


basic_reqs() {
    # Prints common disclaimer and checks basic requirements.
    #
    # Args:
    #     CVE - string printed in the disclaimer
    #
    # Side effects:
    #     Exits when 'rpm' command is not available

    local CVE="$1"

    # Disclaimer
    echo
    echo -e "Spectre/Meltdown Detection Script Ver. $VERSION"
    echo -e "${BOLD}This script is primarily designed to detect $CVE on supported"
    echo -e "Red Hat Enterprise Linux systems and kernel packages."
    echo -e "Result may be inaccurate for other RPM based systems.${RESET}"
    echo

    # RPM is required
    if ! command -v rpm &> /dev/null; then
        echo "'rpm' command is required, but not installed. Exiting."
        exit 1
    fi
}


check_supported_kernel() {
    # Checks if running kernel is supported.
    #
    # Args:
    #     running_kernel - kernel string as returned by 'uname -r'
    #
    # Side effects:
    #     Exits when running kernel is obviously not supported

    local running_kernel="$1"

    # Check supported platform
    if [[ "$running_kernel" != *".el"[5-7]* ]]; then
        echo "This script is meant to be used only on Red Hat Enterprise Linux 5, 6 and 7."
        exit 1
    fi
}


get_rhel() {
    # Gets RHEL number.
    #
    # Args:
    #     running_kernel - kernel string as returned by 'uname -r'
    #
    # Prints:
    #     RHEL number, e.g. '5', '6', or '7'

    local running_kernel="$1"

    local rhel
    rhel=$( sed -r -n 's/^.*el([[:digit:]]).*$/\1/p' <<< "$running_kernel" )
    echo "$rhel"
}


check_cpu_vendor() {
    # Checks for supported CPU vendor/model/architecture.
    #
    # Prints:
    #     'Intel', 'AMD', 'POWER'
    #
    # Returns:
    #     0 if supported CPU vendor found, otherwise 1
    #
    # Notes:
    #     MOCK_CPU_INFO_PATH can be used to mock /proc/cpuinfo file

    local cpuinfo=${MOCK_CPU_INFO_PATH:-/proc/cpuinfo}

    if grep --quiet "GenuineIntel" "$cpuinfo"; then
        echo "Intel"
        return 0
    fi
    if grep --quiet "AuthenticAMD" "$cpuinfo"; then
        echo "AMD"
        return 0
    fi
    if grep --quiet "POWER" "$cpuinfo"; then
        echo "POWER"
        return 0
    fi

    return 1
}


gather_info() {
    # Gathers all available information and stores it in global variables.
    #
    # Side effects:
    #     Sets many global boolean flags
    #
    # Notes:
    #     MOCK_DEBUG_X86_PATH can be used to mock /sys/kernel/debug/x86 directory
    #     MOCK_VULNS_PATH can be used to mock /sys/devices/system/cpu/vulnerabilities directory
    #     MOCK_CMDLINE_PATH can be used to mock /proc/cmdline file
    #     MOCK_LOG_DMESG_PATH can be used to mock /var/log/dmesg

    local debug_x86=${MOCK_DEBUG_X86_PATH:-/sys/kernel/debug/x86}
    local vulns=${MOCK_VULNS_PATH:-/sys/devices/system/cpu/vulnerabilities}
    local cmdline_path=${MOCK_CMDLINE_PATH:-/proc/cmdline}
    local dmesg_log_path=${MOCK_LOG_DMESG_PATH:-/var/log/dmesg}

    # Are cpu/vulnerabilities files present?
    if [[ -r "${vulns}/meltdown" && -r "${vulns}/spectre_v1" && -r "${vulns}/spectre_v2" ]]; then
        all_vuln_files=1
        retpo_kernel=1
    fi

    # Read status from vulnerabilities files
    if (( all_vuln_files )); then
        if ! grep --quiet 'Vulnerable' "${vulns}/meltdown"; then
            vulns_md_mitigation=1
        fi
        if ! grep --quiet 'Vulnerable' "${vulns}/spectre_v1"; then
            vulns_sv1_mitigation=1
        fi
        if ! grep --quiet 'Vulnerable' "${vulns}/spectre_v2"; then
            vulns_sv2_mitigation=1
        fi
    fi

    # Read commandline
    if grep --quiet 'nopti' "$cmdline_path"; then
        nopti=1
    fi
    if grep --quiet 'noibrs' "$cmdline_path"; then
        noibrs=1
    fi
    if grep --quiet 'noibpb' "$cmdline_path"; then
        noibpb=1
    fi
    if grep --quiet 'no_rfi_flush' "$cmdline_path"; then
        norfi=1
    fi
    if grep --quiet 'nospectre_v2' "$cmdline_path"; then
        nospectre_v2=1
    fi
    if grep --quiet '[[:space:]]spectre_v2=' "$cmdline_path"; then
        spectre_v2=$( sed -r 's/.*[[:space:]]spectre_v2=([a-zA-Z]+).*/\1/' "$cmdline_path" )
    fi

    # Is debugfs mounted?
    if mount | grep --quiet debugfs; then
        mounted_debugfs=1
    fi

    # Will fallback detection be needed?
    if (( ! mounted_debugfs )); then
        fallback_needed=1
    fi

    # Are all debug files accessible?
    if (( rhel == 5 )); then
        if [[ -r "${debug_x86}/pti_enabled" ]]; then
            all_debug_files=1
        fi
    else
        if [[ -r "${debug_x86}/pti_enabled" && -r "${debug_x86}/ibpb_enabled" && -r "${debug_x86}/ibrs_enabled" ]]; then
            all_debug_files=1
        fi
    fi

    # Read features from debugfs
    if (( all_debug_files )); then
        new_kernel=1
        pti_debugfs=$( <"${debug_x86}/pti_enabled" )
        ibpb_debugfs=$( <"${debug_x86}/ibpb_enabled" )
        ibrs_debugfs=$( <"${debug_x86}/ibrs_enabled" )
        if (( retpo_kernel )); then
            if [[ -r "${debug_x86}/retp_enabled" ]]; then
                retp_debugfs=$( <"${debug_x86}/retp_enabled" )
            fi
        fi
    fi

    # Read features from dmesg, use log file first, fallback to circular buffer
    if [[ -r "$dmesg_log_path" ]]; then
        dmesg_data=$( <"$dmesg_log_path" )
        dmesg_log_used=1
    else
        dmesg_data=$( dmesg )
        dmesg_command_used=1
        if ! grep --quiet 'Linux.version' <<< "$dmesg_data"; then
            dmesg_wrapped=1
        fi
    fi

    # These will not appear if disabled from commandline
    if grep --quiet -e 'x86/pti: Unmapping kernel while in userspace' \
                    -e 'x86/pti: Kernel page table isolation enabled' \
                    -e 'x86/pti: Xen PV detected, disabling' \
                    -e 'x86/pti: Xen PV detected, disabling PTI protection' \
                    -e 'Kernel page table isolation enabled' <<< "$dmesg_data"; then
        new_kernel=1
        pti_dmesg=1
    fi

    # These will appear if disabled from commandline
    line=$( grep 'FEATURE SPEC_CTRL' <<< "$dmesg_data" | tail -n 1 )  # Check last
    if [[ "$line" ]]; then
        new_kernel=1
        if ! grep --quiet 'Not Present' <<< "$line"; then
            ibrs_dmesg=1
            hw_support=1
        else
            not_ibrs_dmesg=1
        fi
    fi

    line=$( grep 'FEATURE IBPB_SUPPORT' <<< "$dmesg_data" | tail -n 1 )   # Check last
    if [[ "$line" ]]; then
        new_kernel=1
        if ! grep --quiet 'Not Present' <<< "$line"; then
            ibpb_dmesg=1
            hw_support=1
        else
            not_ibpb_dmesg=1
        fi
    fi
}


check_variants() {
    # Checks which variants are mitigated based on many global boolean flags.
    #
    # Side effects:
    #     Sets global variable `result`, a bitmask of vulnerable variants

    # If vulnerabilities files are available, rely on them
    if (( all_vuln_files )); then
        if (( vulns_sv1_mitigation )); then
            (( result &= ~2 ))
        fi
        if (( vulns_sv2_mitigation )); then
            (( result &= ~4 ))
        fi
        if (( vulns_md_mitigation )); then
            (( result &= ~8 ))
        fi
        return
    fi

    if (( new_kernel )); then
        (( result &= ~2 ));
    fi

    if [[ "$vendor" == "Intel" ]]; then
        if (( ! fallback_needed )); then
            if (( pti_debugfs == 1 )); then
                (( result &= ~8 ))
            fi
            # The tests below check system defaults. It is possible that they will report
            # false positives in systems where SPEC_CTRL is unavailable, but SMT has been
            # disabled and ibpb_enabled is set to '2'.
            if (( ibrs_debugfs != 0 && ibpb_debugfs != 0 )); then
                (( result &= ~4 ))
            fi
        else
            if (( ibrs_dmesg && ibpb_dmesg && ! noibrs && ! noibpb && ! nospectre_v2 )); then
                (( result &= ~4 ))
            fi
            if (( pti_dmesg )); then
                (( result &= ~8 ))
            fi
        fi
    fi

    if [[ "$vendor" == "AMD" ]]; then
        (( result &= ~8 ))  # AMD isn't vulnerable to meltdown

        if (( ! fallback_needed )); then
            if (( pti_debugfs == 0 && ibrs_debugfs == 0 && ibpb_debugfs == 2 )); then
                (( result &= ~4 )) # Pre-retpoline kernels if updated microcode is applied
            fi
            if (( pti_debugfs == 0 && ibrs_debugfs == 2 && ibpb_debugfs == 1 )); then
                (( result &= ~4 )) # Pre-retpoline kernels on old CPUs which don't need microcode
            fi
        else
            if (( ibpb_dmesg && ! noibpb && ! noibrs && ! nospectre_v2 )); then
                (( result &= ~4 )) # Fallback detection -- assume kernel-set defaults based on dmesg
            fi
        fi
    fi
}


get_results() {
  # Set messages to display vulnerability/mitigation status
  # to the user.
  # Sets the following globals:
  # pti, ibrs, ibpb - Whether these features were disabled by the user
  # kernel_with_patches - Whether the kernel is spectre/meltdown aware
  # hw - Whether the hw/firmware supports mitigation features
  # result - The return code, a bitmask that represents vulnerable variants

    local vulns=${MOCK_VULNS_PATH:-/sys/devices/system/cpu/vulnerabilities}

    if (( new_kernel || retpo_kernel )); then
        kernel_with_patches="${GREEN}OK${RESET}"
        if (( hw_support )); then
            hw="${GREEN}YES${RESET}"
        else
            hw="${RED}NO${RESET}"
        fi
    else
        kernel_with_patches="${RED}Not installed${RESET}"
        hw="${YELLOW}Cannot detect without updated kernel${RESET}"
    fi

    if (( nopti )); then
        pti="${RED}Disabled on kernel commandline by 'nopti'${RESET}"
    else
        pti="Not disabled on kernel commandline"
    fi

    if (( noibrs )); then
        ibrs="${RED}Disabled on kernel commandline by 'noibrs'${RESET}"
    elif (( nospectre_v2 )); then
        ibrs="${RED}Disabled on kernel commandline by 'nospectre_v2'${RESET}"
    elif [[ ($spectre_v2 == "off") || ($spectre_v2 == "retpoline") ]]; then
        ibrs="${RED}Disabled on kernel commandline by 'spectre_v2=${spectre_v2}'${RESET}"
    else
        ibrs="Not disabled on kernel commandline"
    fi

    if (( noibpb )); then
        ibpb="${RED}Disabled on kernel commandline by 'noibpb'${RESET}"
    elif (( nospectre_v2 )); then
        ibpb="${RED}Disabled on kernel commandline by 'nospectre_v2'${RESET}"
    elif [[ ($spectre_v2 == "off") ]]; then
        ibpb="${RED}Disabled on kernel commandline by 'spectre_v2=${spectre_v2}'${RESET}"
    else
        ibpb="Not disabled on kernel commandline"
    fi

    if [[ ($spectre_v2 == "off") ||  ($spectre_v2 == "ibrs") || ($spectre_v2 == "ibrs_always") ]]; then
        retpolines="${RED}Disabled on kernel commandline by 'spectre_v2=${spectre_v2}'${RESET}"
    else
        retpolines="Not disabled on kernel commandline"
    fi

    if (( nopti || norfi )); then
        if (( ! norfi )); then
            rfiflush="${RED}Disabled on kernel commandline by 'nopti'${RESET}"
        elif (( ! nopti )); then
            rfiflush="${RED}Disabled on kernel commandline by 'no_rfi_flush'${RESET}"
        else
            rfiflush="${RED}Disabled on kernel commandline by 'nopti' and 'no_rfi_flush'${RESET}"
        fi
    else
        rfiflush="Not disabled on kernel commandline"
    fi

    if (( all_vuln_files )); then
        variant_1=$( <"${vulns}/spectre_v1" )
        variant_2=$( <"${vulns}/spectre_v2" )
        variant_3=$( <"${vulns}/meltdown" )
    else
        if (( ! (result & 2) )); then
            variant_1="Mitigated"
        fi
        if (( ! (result & 4) )); then
            variant_2="Mitigated"
        fi
        if (( ! (result & 8) )); then
            variant_3="Mitigated"
        elif [[ $vendor == "AMD" ]]; then
            variant_3="AMD is not vulnerable to this variant"
        fi
    fi

    if (( result & 2 )); then
        variant_1="${RED}$variant_1${RESET}"
    else
        variant_1="${GREEN}$variant_1${RESET}"
    fi
    if (( result & 4 )); then
        variant_2="${RED}$variant_2${RESET}"
    else
        variant_2="${GREEN}$variant_2${RESET}"
    fi
    if (( result & 8 )); then
        variant_3="${RED}$variant_3${RESET}"
    else
        variant_3="${GREEN}$variant_3${RESET}"
    fi
}


get_virtualization() {
    # Gets virtualization type.
    #
    # Prints:
    #     Virtualization type, "None", or "virt-what not available"

    local virt
    if command -v virt-what &> /dev/null; then
        virt=$( virt-what 2>&1 | tr '\n' ' ' )
        if [[ "$virt" ]]; then
            echo "$virt"
        else
            echo "None"
        fi
    else
        echo "virt-what not available"
    fi
}


require_root() {
    # Checks if user is root.
    #
    # Side effects:
    #     Exits when user is not root.
    #
    # Notes:
    #     MOCK_EUID can be used to mock EUID variable

    local euid=${MOCK_EUID:-$EUID}

    # Am I root?
    if (( euid != 0 )); then
        echo "This script must run with elevated privileges (e.g. as root)"
        exit 1
    fi
}


if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    require_root  # Needed for virt-what and reading debugfs
    basic_args "$@"
    basic_reqs "Spectre / Meltdown"
    running_kernel=$( uname -r )
    check_supported_kernel "$running_kernel"

    rhel=$( get_rhel "$running_kernel" )
    if (( rhel == 5 )); then
        export PATH='/sbin':$PATH
    fi

    vendor=$( check_cpu_vendor )
    if (( $? == 1 )); then
        # Archictectures other than x86_64, x86, POWER
        # are supported on a best-effort basis if vuln
        # files are present
        unspecified_arch=1
    else
        unspecified_arch=0
    fi

    mounted_debugfs=0
    all_debug_files=0
    fallback_needed=0
    pti_debugfs=0
    ibrs_debugfs=0
    ibpb_debugfs=0
    retp_debugfs=0
    dmesg_wrapped=0
    pti_dmesg=0
    ibrs_dmesg=0
    ibpb_dmesg=0
    not_ibrs_dmesg=0
    not_ibpb_dmesg=0
    new_kernel=0
    retpo_kernel=0
    nopti=0
    noibrs=0
    noibpb=0
    nospectre_v2=0
    spectre_v2="auto"
    hw_support=0
    dmesg_log_used=0
    dmesg_command_used=0
    virtualization=""

    # /sys/devices/system/cpu/vulnerabilities updates
    # See comments on line 23 above
    all_vuln_files=0
    vulns_md_mitigation=0
    vulns_sv1_mitigation=0
    vulns_sv2_mitigation=0

    # Assume all vulnerabilities present
    variant_1="Vulnerable"
    variant_2="Vulnerable"
    variant_3="Vulnerable"
    result=14

    # Tests
    gather_info
    check_variants
    get_results
    virtualization=$( get_virtualization )

    # Debug prints
    if [[ "$debug" ]]; then
        echo "running_kernel = *$running_kernel*"
        echo "rhel = *$rhel*"
        echo "vendor = *$vendor*"
        echo "mounted_debugfs = *$mounted_debugfs*"
        echo "all_debug_files = *$all_debug_files*"
        echo "fallback_needed = *$fallback_needed*"
        echo "pti_debugfs = *$pti_debugfs*"
        echo "ibrs_debugfs = *$ibrs_debugfs*"
        echo "ibpb_debugfs = *$ibpb_debugfs*"
        echo "retp_debugfs = *$retp_debugfs*"
        echo "dmesg_wrapped = *$dmesg_wrapped*"
        echo "pti_dmesg = *$pti_dmesg*"
        echo "ibrs_dmesg = *$ibrs_dmesg*"
        echo "ibpb_dmesg = *$ibpb_dmesg*"
        echo "not_ibrs_dmesg = *$not_ibrs_dmesg*"
        echo "not_ibpb_dmesg = *$not_ibpb_dmesg*"
        echo "new_kernel = *$new_kernel*"
        echo "retpo_kernel = *$retpo_kernel*"
        echo "nopti = *$nopti*"
        echo "noibrs = *$noibrs*"
        echo "noibpb = *$noibpb*"
        echo "norfi = *$norfi*"
        echo "hw_support = *$hw_support*"
        echo "variant_1 = *$variant_1*"
        echo "variant_2 = *$variant_2*"
        echo "variant_3 = *$variant_3*"
        echo "all_vuln_files = *$all_vuln_files*"
        echo "vulns_md_mitigation = *$vulns_md_mitigation*"
        echo "vulns_sv1_mitigation = *$vulns_sv1_mitigation*"
        echo "vulns_sv2_mitigation = *$vulns_sv2_mitigation*"
        echo "nospectre_v2 = *$nospectre_v2*"
        echo "spectre_v2 = *$spectre_v2*"
        echo "retpolines = *$retpolines*"
        echo "unspecified_arch = *$unspecified_arch*"
        echo "dmesg_log_used = *$dmesg_log_used*"
        echo "dmesg_command_used = *$dmesg_command_used*"
        echo "result = *$result*"
        echo "virtualization = *$virtualization*"
        echo
    fi

    # Output
    echo -e "Detected CPU vendor: ${BOLD}$vendor${RESET}"
    echo -e "Running kernel: ${BOLD}$running_kernel${RESET}"
    echo -e "Virtualization: ${BOLD}$virtualization${RESET}"
    echo

    if (( ! all_vuln_files )); then
        if [[ "$unspecified_arch" == 1 || "$vendor" == "POWER" ]]; then
            echo "This system's kernel does not provide detailed vulnerability information."
            echo "Fallback detection for this CPU vendor is not supported by the script at the moment."
            echo "Only Intel/AMD x86/x86_64 and IBM POWER (RHEL 7) are supported for now."
            exit 1
        else
            echo "Detailed information about this CPU architecture may not be available."
            echo "Presently, only Intel/AMD x86/x86_64 and IBM POWER are fully supported."
        fi
    fi

    # Warnings
    if [[ "$vendor" == "AMD" || "$vendor" == "Intel" ]]; then
        if (( dmesg_wrapped )); then
            echo -e "${YELLOW}It seems that dmesg circular buffer already wrapped,${RESET}"
            echo -e "${YELLOW}the results may be inaccurate.${RESET}"
            echo
        fi
    fi

    # Variants
    echo -e "Variant #1 (Spectre): $variant_1"
    echo -e "CVE-2017-5753 - speculative execution bounds-check bypass"
    if [[ ( "$vendor" == "AMD" ) || ( "$vendor" == "Intel" ) ]]; then
        echo -e "   - Kernel with mitigation patches: $kernel_with_patches"
    fi
    echo

    echo -e "Variant #2 (Spectre): $variant_2"
    echo -e "CVE-2017-5715 - speculative execution branch target injection"
    if [[ ( "$vendor" == "AMD" ) || ( "$vendor" == "Intel" ) ]]; then
        if (( rhel == 5 && ! retpo_kernel )); then
            echo -e "   - Kernel with mitigation patches: ${RED}NO${RESET}"
            echo -e "   - HW support / updated microcode: ${YELLOW}Cannot detect without updated kernel${RESET}"
        else
            echo -e "   - Kernel with mitigation patches: $kernel_with_patches"
            echo -e "   - HW support / updated microcode: $hw"
        fi
        echo -e "   - IBRS: $ibrs"
        echo -e "   - IBPB: $ibpb"
        echo -e "   - Retpolines: $retpolines"
    fi
    echo

    echo -e "Variant #3 (Meltdown): $variant_3"
    echo -e "CVE-2017-5754 - speculative execution permission faults handling"
    if [[ "$vendor" == "AMD" ]]; then
        echo -e "   - AMD CPU: ${GREEN}OK${RESET}"
    else
        echo -e "   - Kernel with mitigation patches: $kernel_with_patches"
        if [[ "$vendor" == "Intel" ]]; then
            echo -e "   - PTI: $pti"
        fi
        if [[ "$vendor" == "POWER" ]]; then
            echo -e "   - RFI Flush: $rfiflush"
        fi
    fi
    echo

    if (( result != 0 )); then
        if (( unspecified_arch )); then
            echo "Detailed remediation steps may not be available."
        fi
        echo "Red Hat recommends that you:"
        if (( ! retpo_kernel )); then
            echo -e "* Update your kernel and reboot the system."
        fi
        if [[ "$vendor" == "AMD" || "$vendor" == "Intel" ]]; then
            if (( ! hw_support )); then
                echo -e "* Ask your HW vendor for CPU microcode update."
            fi
        fi
        if (( noibrs || noibpb || nopti || norfi || nospectre_v2 )); then
            echo -e "* Remove kernel commandline options as noted above."
        fi
        if [[ $variant_2 == "${RED}Vulnerable: Retpoline with unsafe module(s)${RESET}" ]]; then
            echo -e "* See https://access.redhat.com/solutions/3399691 to determine which modules are vulnerable."
        fi
        echo
    fi

    if (( fallback_needed )); then
        echo -e "${YELLOW}Fallback non-runtime heuristics check is used (reading dmesg messages),"
        echo -e "because debugfs could not be read.${RESET}"
        echo
        echo "To improve mitigation detection:"
        if (( ! mounted_debugfs )); then
            echo "* Mount debugfs by following command:"
            if (( rhel == 5 || rhel == 6 )); then
                echo "    # mount -t debugfs nodev /sys/kernel/debug"
            fi
            if (( rhel == 7 )); then
                echo "    # systemctl restart sys-kernel-debug.mount"
            fi
        fi
        echo
    fi

    if [[ "$virtualization" != "None" ]]; then
        echo -e "${BOLD}Note about virtualization${RESET}"
        echo -e "In virtualized environment, there are more steps to mitigate the issue, including:"
        echo -e "* Host needs to have updated kernel and CPU microcode"
        echo -e "* Host needs to have updated virtualization software"
        echo -e "* Guest needs to have updated kernel"
        echo -e "* Hypervisor needs to propagate new CPU features correctly"
        echo -e "For more details about mitigations in virtualized environment see:"
        echo -e "https://access.redhat.com/articles/3331571"
        echo
    fi

    echo -e "For more information about the vulnerabilities see:"
    echo -e "https://access.redhat.com/security/vulnerabilities/speculativeexecution"
    exit "$result"
fi
