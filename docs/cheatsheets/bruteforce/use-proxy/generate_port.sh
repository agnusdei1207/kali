#!/bin/bash
out=/tmp/ports_to_check.txt
arg="${1:-1000}"

if [[ "$arg" =~ ^[0-9]+$ ]]; then
    awk -F'\t' '$2 ~ /\/tcp$/ && $3 != "" {
        gsub(/\/tcp$/, "", $2)
        print $3, $2
    }' /usr/share/nmap/services | sort -rn | head -n "$arg" | awk '{print $2}' > "$out"
fi
