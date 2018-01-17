#!/bin/bash

# Copyright (C) 2018  Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Version: 2.0

# Warning! Be sure to download the latest version of this script from its primary source:
# https://access.redhat.com/security/vulnerabilities/speculativeexecution
# DO NOT blindly trust any internet sources and NEVER do `curl something | bash`!

# This script is meant for simple detection of the vulnerability. Feel free to modify it for your
# environment or needs. For more advanced detection, consider Red Hat Insights:
# https://access.redhat.com/products/red-hat-insights#getstarted

# Checking against the list of vulnerable packages is necessary because of the way how features
# are back-ported to older versions of packages in various channels.


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

    RED="\033[1;31m"
    YELLOW="\033[1;33m"
    GREEN="\033[1;32m"
    BOLD="\033[1m"
    RESET="\033[0m"
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
        echo -e "${RED}This script is meant to be used only on Red Hat Enterprise"
        echo -e "Linux 5, 6 and 7.${RESET}"
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

    local rhel=$( sed -r -n 's/^.*el([[:digit:]]).*$/\1/p' <<< "$running_kernel" )
    echo "$rhel"
}


check_cpu_vendor() {
    # Checks for supported CPU vendor.
    #
    # Prints:
    #     'Intel' or 'AMD'
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
    #     MOCK_CMDLINE_PATH can be used to mock /proc/cmdline file
    #     MOCK_EUID can be used to mock EUID variable

    local debug_x86=${MOCK_DEBUG_X86_PATH:-/sys/kernel/debug/x86}
    local cmdline_path=${MOCK_CMDLINE_PATH:-/proc/cmdline}
    local euid=${MOCK_EUID:-$EUID}

    # Am I root?
    if (( euid == 0 )); then
        root=1
    fi

    # Is debugfs mounted?
    if mount | grep --quiet debugfs; then
        mounted_debugfs=1
    fi

    # Will fallback detection be needed?
    if (( ! mounted_debugfs || ! root )); then
        fallback_needed=1
    fi

    # Are all debug files accessible?
    if [[ -r "${debug_x86}/pti_enabled" && -r "${debug_x86}/ibpb_enabled" && -r "${debug_x86}/ibrs_enabled" ]]; then
        all_debug_files=1
    fi

    # Read features from debugfs
    if (( all_debug_files )); then
        new_kernel=1
        pti_debugfs=$( <"${debug_x86}/pti_enabled" )
        ibpb_debugfs=$( <"${debug_x86}/ibpb_enabled" )
        ibrs_debugfs=$( <"${debug_x86}/ibrs_enabled" )
    fi

    # Read features from dmesg
    if ! dmesg | grep --quiet 'Linux.version'; then
        dmesg_wrapped=1
    fi

    # These two will not appear if disabled from commandline
    if dmesg | grep --quiet 'x86/pti: Unmapping kernel while in userspace'; then
        new_kernel=1
        pti_dmesg=1
    fi

    if dmesg | grep --quiet 'x86/pti: Xen PV detected, disabling'; then
        new_kernel=1
        pti_dmesg=1
    fi

    # These will appear if disabled from commandline
    line=$( dmesg | tac | grep --max-count 1 'FEATURE SPEC_CTRL' )  # Check last
    if [[ "$line" ]]; then
        new_kernel=1
        if ! grep --quiet 'Not Present' <<< "$line"; then
            ibrs_dmesg=1
            hw_support=1
        fi
    fi

    line=$( dmesg | tac | grep --max-count 1 'FEATURE IBPB_SUPPORT' )   # Check last
    if [[ "$line" ]]; then
        new_kernel=1
        if ! grep --quiet 'Not Present' <<< "$line"; then
            ibpb_dmesg=1
            hw_support=1
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
}


check_variants() {
    # Checks which variants are mitigated based on many global boolean flags.
    #
    # Side effects:
    #     Sets global variables variant_1, variant_2, variant_3.

    if (( new_kernel )); then
        variant_1="Mitigated"
    fi

    if [[ "$vendor" == "Intel" ]]; then
        if (( ! fallback_needed )); then
            if (( pti_debugfs == 1 && ibrs_debugfs == 1 && ibpb_debugfs == 1 )); then
                variant_2="Mitigated"
                variant_3="Mitigated"
            fi
            if (( pti_debugfs == 1 && ibrs_debugfs == 2 && ibpb_debugfs == 1 )); then
                variant_2="Mitigated"
                variant_3="Mitigated"
            fi
            if (( pti_debugfs == 1 && ibrs_debugfs == 0 && ibpb_debugfs == 0 )); then
                variant_3="Mitigated"
            fi
        else
            if (( ibrs_dmesg && ibpb_dmesg && ! noibrs && ! noibpb )); then
                variant_2="Mitigated"
            fi
            if (( pti_dmesg )); then
                variant_3="Mitigated"
            fi
        fi
    fi

    if [[ "$vendor" == "AMD" ]]; then
        variant_3="AMD is not vulnerable to this variant"

        if (( ! fallback_needed )); then
            if (( pti_debugfs == 0 && ibrs_debugfs == 0 && ibpb_debugfs == 2 )); then
                variant_2="Mitigated"
            fi
            if (( pti_debugfs == 0 && ibrs_debugfs == 2 && ibpb_debugfs == 1 )); then
                variant_2="Mitigated"
            fi
        else
            if (( ibpb_dmesg && ! noibpb )); then
                variant_2="Mitigated"
            fi
        fi
    fi
}


if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    basic_args "$@"
    basic_reqs "Spectre / Meltdown"
    running_kernel=$( uname -r )
    check_supported_kernel "$running_kernel"

    rhel=$( get_rhel "$running_kernel" )
    if [[ "$rhel" == "5" ]]; then
        export PATH='/sbin':$PATH
    fi

    vendor=$( check_cpu_vendor )
    if (( $? == 1 )); then
        echo -e "${RED}Your CPU vendor is not supported by the script at the moment.${RESET}"
        echo -e "Only Intel and AMD are supported for now."
        exit 1
    fi

    root=0
    mounted_debugfs=0
    all_debug_files=0
    fallback_needed=0
    pti_debugfs=0
    ibrs_debugfs=0
    ibpb_debugfs=0
    dmesg_wrapped=0
    pti_dmesg=0
    ibrs_dmesg=0
    ibpb_dmesg=0
    new_kernel=0
    nopti_cmd=0
    noibrs_cmd=0
    noibpb_cmd=0
    hw_support=0

    variant_1="Vulnerable"
    variant_2="Vulnerable"
    variant_3="Vulnerable"

    # Tests
    gather_info
    check_variants

    # Debug prints
    if [[ "$debug" ]]; then
        echo "running_kernel = *$running_kernel*"
        echo "rhel = *$rhel*"
        echo "vendor = *$vendor*"
        echo "root = *$root*"
        echo "mounted_debugfs = *$mounted_debugfs*"
        echo "all_debug_files = *$all_debug_files*"
        echo "fallback_needed = *$fallback_needed*"
        echo "pti_debugfs = *$pti_debugfs*"
        echo "ibrs_debugfs = *$ibrs_debugfs*"
        echo "ibpb_debugfs = *$ibpb_debugfs*"
        echo "dmesg_wrapped = *$dmesg_wrapped*"
        echo "pti_dmesg = *$pti_dmesg*"
        echo "ibrs_dmesg = *$ibrs_dmesg*"
        echo "ibpb_dmesg = *$ibpb_dmesg*"
        echo "new_kernel = *$new_kernel*"
        echo "nopti_cmd = *$nopti_cmd*"
        echo "noibrs_cmd = *$noibrs_cmd*"
        echo "noibpb_cmd = *$noibpb_cmd*"
        echo "hw_support = *$hw_support*"
        echo "variant_1 = *$variant_1*"
        echo "variant_2 = *$variant_2*"
        echo "variant_3 = *$variant_3*"
        echo
    fi

    # Results
    if (( new_kernel )); then
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
    else
        ibrs="Not disabled on kernel commandline"
    fi

    if (( noibpb )); then
        ibpb="${RED}Disabled on kernel commandline by 'noibpb'${RESET}"
    else
        ibpb="Not disabled on kernel commandline"
    fi

    (( result = 0 ))
    if [[ "$variant_1" == "Vulnerable" ]]; then
        (( result |= 2 ))
        variant_1="${RED}$variant_1${RESET}"
    else
        variant_1="${GREEN}$variant_1${RESET}"
    fi
    if [[ "$variant_2" == "Vulnerable" ]]; then
        (( result |= 4 ))
        variant_2="${RED}$variant_2${RESET}"
    else
        variant_2="${GREEN}$variant_2${RESET}"
    fi
    if [[ "$variant_3" == "Vulnerable" ]]; then
        (( result |= 8 ))
        variant_3="${RED}$variant_3${RESET}"
    else
        variant_3="${GREEN}$variant_3${RESET}"
    fi

    # Output
    echo -e "Detected CPU vendor: ${BOLD}$vendor${RESET}"
    echo -e "Running kernel: ${BOLD}$running_kernel${RESET}"
    echo

    # Warnings
    if (( fallback_needed )); then
        echo -e "${YELLOW}Fallback non-runtime heuristics check is used (reading dmesg messages)${RESET},"
        echo -e "because debugfs could not be read."
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
        if (( ! root )); then
            echo "* Run this script with elevated privileges (e.g. as root)"
        fi
        echo
    fi

    if (( dmesg_wrapped )); then
        echo -e "${YELLOW}It seems that dmesg circular buffer already wrapped,${RESET}"
        echo -e "${YELLOW}the results may be inaccurate.${RESET}"
        echo
    fi

    # Variants
    echo -e "Variant #1 (Spectre): $variant_1"
    echo -e "CVE-2017-5753 - speculative execution bounds-check bypass"
    echo -e "   - Kernel with mitigation patches: $kernel_with_patches"
    echo

    echo -e "Variant #2 (Spectre): $variant_2"
    echo -e "CVE-2017-5715 - speculative execution branch target injection"
    echo -e "   - Kernel with mitigation patches: $kernel_with_patches"
    echo -e "   - HW support / updated microcode: $hw"
    echo -e "   - IBRS: $ibrs"
    echo -e "   - IBPB: $ibpb"
    echo

    echo -e "Variant #3 (Meltdown): $variant_3"
    echo -e "CVE-2017-5754 - speculative execution permission faults handling"
    if [[ "$vendor" == "AMD" ]]; then
        echo -e "   - AMD CPU: ${GREEN}OK${RESET}"
    else
        echo -e "   - Kernel with mitigation patches: $kernel_with_patches"
        echo -e "   - PTI: $pti"
    fi
    echo

    if (( result != 0 )); then
        echo "Red Hat recommends that you:"
        if (( ! new_kernel )); then
            echo -e "* Update your kernel and reboot the system."
        fi
        if (( ! hw_support )); then
            echo -e "* Ask your HW vendor for CPU microcode update."
        fi
        if (( noibrs || noibpb || nopti_cmd )); then
            echo -e "* Remove kernel commandline options as noted above."
        fi
        echo
    fi

    echo -e "For more information see:"
    echo -e "https://access.redhat.com/security/vulnerabilities/speculativeexecution"
    exit "$result"
fi
