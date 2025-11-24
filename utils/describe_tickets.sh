#!/usr/bin/env bash
# Describe Kerberos ccache files inside a directory
# Usage: describe_tickets.sh /path/to/dir

set -euo pipefail

DIR="${1:-}"
if [ -z "$DIR" ]; then
	echo "Usage: $0 /path/to/directory"
	exit 2
fi

if [ ! -d "$DIR" ]; then
	echo "Error: not a directory: $DIR" >&2
	exit 3
fi

# Separator for internal storage (unit separator unlikely to appear in fields)
sep=$'\x1F'
declare -a rows=()

# Iterate non-recursively over regular files in the directory
shopt -s nullglob
for f in "$DIR"/*; do
	[ -f "$f" ] || continue

	# Try to parse with klist; skip files that are not ccache
	kout=$(klist -c "FILE:$f" 2>/dev/null || true)
	if [ -z "$kout" ]; then
		# not a parsable ccache
		continue
	fi

	default_pr=$(printf "%s" "$kout" | awk -F': ' '/Default principal/ {print $2; exit}')

	# Extract ticket lines: everything after the 'Valid starting' header
	ticket_lines=$(printf "%s" "$kout" | awk '/^Valid starting/ {found=1; next} found {print}')

	if [ -z "$ticket_lines" ]; then
		# printf "%s\t%s\t%s\t%s\t%s\n" "$f" "${default_pr:-}" "-" "-" "-"
		continue
	fi

	# Split ticket_lines into an array of lines so we can peek the following line.
	IFS=$'\n' read -r -d '' -a tlines <<<"${ticket_lines}" || true
	for ((li=0; li<${#tlines[@]}; li++)); do
		line="${tlines[li]}"
		# skip empty lines
		[[ -z "${line// /}" ]] && continue

		# Split into fields
		read -ra parts <<<"$line"
		np=${#parts[@]}
		if [ "$np" -lt 5 ]; then
			# unexpected format, skip
			continue
		fi
		vs="${parts[0]} ${parts[1]}"
		ex="${parts[2]} ${parts[3]}"
		renew=""

		# Build service principal from the remaining parts on this line (from index 4)
		sp=""
		for ((i=4; i<np; i++)); do
			if [ -z "$sp" ]; then
				sp="${parts[i]}"
			else
				sp="$sp ${parts[i]}"
			fi
		done

		# Check the next line for a 'renew until' entry (common format: indented line starting with 'renew until')
		if (( li+1 < ${#tlines[@]} )); then
			next_line="${tlines[li+1]}"
			if [[ "$next_line" =~ [Rr]enew[[:space:]]+until[[:space:]]+(.+) ]]; then
				renew="${BASH_REMATCH[1]}"
				# skip the next line since we've consumed it
				li=$((li+1))
			fi
		fi

		# Skip rows that contain epoch placeholder dates (01/01/1970)
		if [[ "$vs" == *"01/01/1970"* || "$ex" == *"01/01/1970"* || "$renew" == *"01/01/1970"* ]]; then
			# ignore synthetic/empty tickets
			continue
		fi

		# Store row fields into rows array using internal separator
		if [ -z "$sp" ]; then sp="-"; fi
		if [ -z "$renew" ]; then renew="-"; fi
		rows+=("$f${sep}${default_pr:-}${sep}${vs}${sep}${ex}${sep}${sp}${sep}${renew}")
	done


done

# If no rows found, exit
if [ ${#rows[@]} -eq 0 ]; then
	echo "No valid ccache files found in $DIR"
	exit 0
fi

# Prepare pretty table: compute column widths
hdr=("FILE" "DEFAULT_PRINCIPAL" "VALID_STARTING" "EXPIRES" "SERVICE_PRINCIPAL" "RENEW_UNTIL")
cols=${#hdr[@]}
declare -a widths
for ((i=0;i<cols;i++)); do widths[i]=${#hdr[i]}; done

for r in "${rows[@]}"; do
	IFS="$sep" read -r -a flds <<<"$r"
	for ((i=0;i<cols;i++)); do
		l=${#flds[i]}
		if [ "$l" -gt "${widths[i]}" ]; then widths[i]="$l"; fi
	done
done

# Build printf format
fmt=""
for ((i=0;i<cols;i++)); do
	fmt+="%-${widths[i]}s  "
done
fmt+="\n"

# Colors
GREEN="\e[32m"
RESET="\e[0m"
BOLD="\e[1m"

# Print header
printf "$BOLD"
printf "$fmt" "${hdr[@]}"
printf "$RESET"

# Current epoch
now=$(date +%s)

# Print rows, color green when expires > now
for r in "${rows[@]}"; do
	IFS="$sep" read -r -a flds <<<"$r"
	expires_val="${flds[3]:-}"
	color_start=""
	color_end=""
	if [ "$expires_val" != "-" ]; then
		# try to parse expires date to epoch
		expires_epoch=$(date -d "$expires_val" +%s 2>/dev/null || true)
		if [ -n "$expires_epoch" ]; then
			if [ "$now" -lt "$expires_epoch" ]; then
				color_start="$GREEN"
				color_end="$RESET"
			fi
		fi
	fi
	# print row with optional color
	if [ -n "$color_start" ]; then
		printf "%b" "$color_start"
		printf "$fmt" "${flds[0]}" "${flds[1]}" "${flds[2]}" "${flds[3]}" "${flds[4]}" "${flds[5]}"
		printf "%b" "$color_end"
	else
		printf "$fmt" "${flds[0]}" "${flds[1]}" "${flds[2]}" "${flds[3]}" "${flds[4]}" "${flds[5]}"
	fi
done


exit 0

