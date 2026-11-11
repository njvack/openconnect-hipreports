#!/bin/zsh -f
# Compare hipreport with hipreport.zsh on this Mac, element for element.
#
#   scripts/parity.sh [path/to/hipreport]
#
# Both get the same openconnect-style arguments. Differences that are
# expected are normalized first: generate-time, and Packet Filter's
# is-enabled, which hipreport.zsh reads with `sudo -n pfctl` and hipreport
# reports as n/a unless it runs as root. Exits non-zero on any other
# difference.
emulate -R zsh
setopt err_exit pipe_fail

here=${0:A:h}
go_bin=${1:-$here/../hipreport}
zsh_script=$here/../hipreport.zsh
work=$(mktemp -d)
trap 'rm -rf $work' EXIT

args=(--cookie "authcookie=x&portal=p&user=${USER}&domain=Parity+Test&computer=${HOST%%.*}"
      --client-ip 10.99.0.2 --md5 0123456789abcdef0123456789abcdef --client-os Mac)

normalize() {
  perl -0pe '
    s{<generate-time>[^<]*</generate-time>}{<generate-time/>}g;
    s{(name="Packet Filter"[^>]*/>\s*<is-enabled>)[^<]*(</is-enabled>)}{$1-$2}g;
  '
}

zsh -f $zsh_script $args 2>$work/zsh.err | normalize >$work/zsh.xml
$go_bin $args 2>$work/go.err | normalize >$work/go.xml

if diff -u $work/zsh.xml $work/go.xml; then
  print "parity: identical ($(grep -c '<Prod ' $work/go.xml) products)"
else
  print -u2 "parity: reports differ (zsh -, go +)"
  print -u2 "--- hipreport stderr"; cat $work/go.err >&2
  exit 1
fi
