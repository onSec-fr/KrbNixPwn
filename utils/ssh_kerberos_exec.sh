#!/usr/bin/env bash
# Exec ssh commands on multiple hosts using Kerberos authentication
# Usage: ssh_kerberos_exec.sh -f <hostfile> -u <user@domain.com> -c <command>"

usage() {
    echo "Usage: $0 -f <hostfile> -u <user@domain.com> -c <command>"
    exit 1
}

if [[ $# -eq 0 ]]; then
    usage
fi

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -f|--file) hostfile="$2"; shift ;;
        -u|--user) user="$2"; shift ;;
        -c|--command) command="$2"; shift ;;
        *) echo "Unknown argument: $1"; usage ;;
    esac
    shift
done

if [[ -z "$hostfile" || -z "$user" || -z "$command" ]]; then
    usage
fi

if [[ ! -f "$hostfile" ]]; then
    echo -e "\e[31m[ERROR] Unable to find host file $hostfile \e[0m"
    exit 1
fi

while read -r host; do 
    echo -e "\e[34m===== Processing: $host =====\e[0m"
    ssh -o GSSAPIAuthentication=yes -o GSSAPIDelegateCredentials=yes \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        "$user@$host" "$command" \
    && echo -e "\e[32m[SUCCESS] $host\e[0m" \
    || echo -e "\e[31m[FAILED] $host\e[0m"
done < "$hostfile"
