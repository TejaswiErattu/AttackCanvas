#!/usr/bin/env bash
# Run-to-run consistency of saved eval results. No model is called.
#
#   scripts/eval/consistency.sh eval/results/a.json eval/results/b.json [eval/results/c.json ...]
#
# A threat is identified the way the dashboard's "Since last run" identifies one: its
# normalised title, the names of the components it affects, and its OWASP categories. Only
# threats at 25% confidence or higher are counted, as the dashboard does. Prints, for every
# pair of results, how many threats they share and the Jaccard similarity
# (shared / in either), so 1.00 means the two runs agree on every threat. Two measures:
#   strict  title + components + OWASP. Model-written titles differ between runs, so this
#           is low even when two runs find the same problems.
#   coarse  components + OWASP only. Two threats on the same components in the same OWASP
#           category count as the same finding, so this is the fairer "same problems" measure
#           and is the number to report.
set -euo pipefail
[ "$#" -ge 2 ] || { echo "usage: $0 result.json result.json [...]" >&2; exit 2; }

keys() { # $1 = result file, $2 = strict | coarse
  jq -r --arg mode "$2" '.threatModel as $m
    | ($m.components | map({(.id): .name}) | add // {}) as $n
    | $m.threats[] | select(.confidence >= 0.25)
    | [ (if $mode == "strict" then (.title | ascii_downcase | gsub("[^a-z0-9]+"; " ") | sub("^ +"; "") | sub(" +$"; "")) else "" end),
        (.componentIds | map($n[.] // .) | map(ascii_downcase) | sort | join(",")),
        (.owasp | sort | join(",")) ]
    | join("|")' "$1" | sort -u
}
jaccard() { # $1 = mode, $2 = file a, $3 = file b
  local a b shared union
  a=$(mktemp); b=$(mktemp)
  keys "$2" "$1" > "$a"; keys "$3" "$1" > "$b"
  shared=$(comm -12 "$a" "$b" | wc -l | tr -d ' ')
  union=$(sort -u "$a" "$b" | wc -l | tr -d ' ')
  printf '  %-6s %s shared of %s, Jaccard %s\n' "$1" "$shared" "$union" \
    "$(awk -v s="$shared" -v u="$union" 'BEGIN { printf "%.2f", (u ? s / u : 1) }')"
  rm -f "$a" "$b"
}

files=("$@")
for f in "${files[@]}"; do
  printf '%s: %s threats at >=25%% confidence\n' "$f" "$(keys "$f" strict | wc -l | tr -d ' ')"
done
for ((i = 0; i < ${#files[@]}; i++)); do
  for ((j = i + 1; j < ${#files[@]}; j++)); do
    printf '%s vs %s\n' "${files[$i]##*/}" "${files[$j]##*/}"
    jaccard strict "${files[$i]}" "${files[$j]}"
    jaccard coarse "${files[$i]}" "${files[$j]}"
  done
done
