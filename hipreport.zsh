#!/bin/zsh -f
#
# hipreport.zsh - an honest HIP report for OpenConnect's GlobalProtect mode.
#
#   openconnect --protocol=gp --os=mac-intel --csd-user="$USER" \
#               --csd-wrapper=/path/to/hipreport.zsh vpn.example.edu
#
# OpenConnect passes --cookie, --client-ip, --client-ipv6, --md5 and
# --client-os, and submits whatever this prints on stdout as the report.
# Pass --debug (or set HIPREPORT_DEBUG=1) to log raw tool output to stderr.
#
# Nothing here needs root. The one exception is Packet Filter status,
# which is reported as n/a when pfctl refuses us.

emulate -R zsh
setopt no_unset pipe_fail
zmodload zsh/datetime            # strftime, EPOCHSECONDS
zmodload -F zsh/stat b:zstat     # zstat, without shadowing stat(1)

export PATH=/usr/bin:/bin:/usr/sbin:/sbin

#--- Configuration ---------------------------------------------------------

# Interface whose hardware MAC GP reports as host-id.
HOST_ID_INTERFACE=en0

CLIENT_VERSION_DEFAULT=6.2.8-1045

# Third-party products, reported only if the app is installed.
# Fields: category|vendor|product|app path|process_1;process_2;process_n
# "process" entries can either be a path to a process, or an entry like:
# launchd:gui/<label> or launchd:system/<label>
# "gui" will be replaced by "gui/$UID"
# Enabled/real-time state is "is *every* process listed running / launchctl enabled"
# If no process entries are there, lists n/a
# `mdfind -name`, and find process paths with `ps -axww -o pid,user,comm | grep -i <name>`
THIRD_PARTY=(
  'anti-malware|Cisco Systems, Inc.|Cisco Secure Endpoint|/Applications/Cisco Secure Endpoint/Secure Endpoint Connector.app|/Applications/Cisco Secure Endpoint/Secure Endpoint Service.app/Contents/MacOS/ampdaemon;/Applications/Cisco Secure Endpoint/Secure Endpoint Service.app/Contents/MacOS/ampscansvc'
  'disk-backup|Google Inc.|Google Drive|/Applications/Google Drive.app|/Applications/Google Drive.app/Contents/PlugIns/DFSFileProviderExtension.appex/Contents/MacOS/DFSFileProviderExtension'
  'patch-management|VMware, Inc.|Workspace ONE Intelligent Hub|/Applications/Workspace ONE Intelligent Hub.app|/Applications/Workspace ONE Intelligent Hub.app/Contents/Resources/IntelligentHubAgent.app/Contents/MacOS/IntelligentHubAgent'
  'patch-management|Qualys, Inc.|Qualys Cloud Security Agent|/Applications/QualysCloudAgent.app|/Applications/QualysCloudAgent.app/Contents/MacOS/qualys-cloud-agent;/Applications/QualysCloudAgent.app/Contents/MacOS/qualys-cep'
  'patch-management|Microsoft Corporation|Microsoft AutoUpdate|/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app|launchd:gui/com.microsoft.update.agent'
)

# Custom plist checks configured on the gateway, as plist / key pairs.
CUSTOM_PLISTS=(
  /Applications/QualysCloudAgent.app/Contents/MacOS/com.qualys.cloud.agent-restart.plist  Label
)

#--- Plumbing --------------------------------------------------------------

DEBUG=${HIPREPORT_DEBUG:-0}

debug() {
  (( DEBUG )) && print -ru2 -- "hipreport: $*"
  return 0
}

# Run a command and print its stdout. stderr is dropped so it can never
# leak into the report; in debug mode the raw output is logged instead.
run() {
  local output rc
  output=$("$@" 2>/dev/null)
  rc=$?
  debug "\$ $* (exit $rc)"$'\n'"$output"
  print -r -- "$output"
  return $rc
}

#--- XML output ------------------------------------------------------------

# Escape text for XML content and attribute values. Every value that
# reaches the report goes through here.
xml_escape() {
  local s=$1
  s=${s//'&'/&amp;}     # must come first
  s=${s//'<'/&lt;}
  s=${s//'>'/&gt;}
  s=${s//'"'/&quot;}
  s=${s//\'/&apos;}
  print -rn -- "$s"
}

# <tag>value</tag>
el() { print -r -- "<$1>$(xml_escape "${2-}")</$1>" }

# <entry name="..."> and <entry name="..."/>
entry_open() { print -r -- "<entry name=\"$(xml_escape "$1")\">" }
entry_leaf() { print -r -- "<entry name=\"$(xml_escape "$1")\"/>" }

# <Prod key="value" .../> from key/value pairs.
# Always quote the values: zsh drops empty unquoted arguments, which
# would shift every pair after it.
prod() {
  local line='<Prod' key value
  for key value in "$@"; do
    line+=" $key=\"$(xml_escape "$value")\""
  done
  print -r -- "$line/>"
}

category_open()  { entry_open "$1"; print '<list>' }
category_close() { print '</list>'; print '</entry>' }

product_open()   { print '<entry>'; print '<ProductInfo>'; prod "$@" }
product_close()  { print '</ProductInfo>'; print '</entry>' }

# A product with one extra field. Args: vendor name version field value
simple_product() {
  product_open vendor "$1" name "$2" version "$3"
  el "$4" "$5"
  product_close
}

# An anti-malware product.
# Args: vendor name version defver updated-epoch real-time-protection
antimalware_product() {
  date_parts "$5"
  product_open vendor "$1" name "$2" version "$3" defver "$4" engver '' \
    datemon "${reply[1]}" dateday "${reply[2]}" dateyear "${reply[3]}" \
    prodType 3 osType 4
  el real-time-protection "$6"
  el last-full-scan-time n/a
  product_close
}

drive() { print '<entry>'; el drive-name "$1"; el enc-state "$2"; print '</entry>' }

#--- Checks: each prints a plain value --------------------------------------

# CFBundleShortVersionString of an .app or .bundle; nothing if absent.
bundle_version() {
  local plist="$1/Contents/Info.plist"
  [[ -r $plist ]] || return 0
  run plutil -extract CFBundleShortVersionString raw "$plist"
}

mtime() { zstat +mtime "$1" 2>/dev/null }

# Unpadded month, day and year of an epoch time, in $reply.
date_parts() {
  local m d y
  if [[ -z ${1-} ]]; then
    reply=( '' '' '' )
    return
  fi
  strftime -s m '%-m' "$1"
  strftime -s d '%-d' "$1"
  strftime -s y '%Y'  "$1"
  reply=( $m $d $y )
}

# Hardware MAC of an interface. This is the burned-in address, not the
# private per-network Wi-Fi address, which is what GP reports too.
hardware_mac() {
  local mac
  mac=$(run networksetup -getmacaddress "$1" | awk '{ print $3 }')
  if [[ $mac != *:*:* ]]; then   # e.g. bridge0; fall back to ifconfig
    mac=$(run ifconfig "$1" | awk '$1 == "ether" { print $2; exit }')
  fi
  print -r -- "$mac"
}

# Addresses of one family (inet or inet6), with any %scope suffix removed.
if_addrs() {
  run ifconfig "$1" | awk -v fam="$2" '$1 == fam { sub(/%.*/, "", $2); print $2 }'
}

gatekeeper_state() {
  case $(run spctl --status) in
    *'assessments enabled'*)  print yes ;;
    *'assessments disabled'*) print no ;;
    *)                        print n/a ;;
  esac
}

app_firewall_state() {
  case $(run /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate) in
    *disabled*)           print no ;;
    *enabled*|*blocking*) print yes ;;
    *)                    print n/a ;;
  esac
}

# pfctl needs root, so as a normal user this is n/a.
packet_filter_state() {
  case $(run sudo -n pfctl -s info) in
    *'Status: Enabled'*)  print yes ;;
    *'Status: Disabled'*) print no ;;
    *)                    print n/a ;;
  esac
}

auto_update_state() {
  case $(run softwareupdate --schedule) in
    *' off'*) print no ;;
    *' on'*)  print yes ;;
    *)        print n/a ;;
  esac
}

# The name of a volume
volume_name() {
  run diskutil info -plist "$1" | plutil -extract VolumeName raw - 2>/dev/null
}

# true if the volume at $1 is on an internal device
is_internal() {
  [[ $(run diskutil info -plist "$1" | plutil -extract Internal raw - 2>/dev/null) == true ]]
}

# Volumes to report, one "label<TAB>mount point" per line: the boot volume,
# its Data half, and browsable local disks under /Volumes.
encryption_volumes() {
  local line mp flags
  run mount | while read -r line; do
    [[ $line =~ ' on (.+) \(([^)]*)\)$' ]] || continue
    mp=${match[1]} flags=${match[2]}
    [[ $flags == *local* ]] || continue
    case $mp in
      /)                    print -r -- "$(volume_name /)"$'\t'"$mp" ;;
      /System/Volumes/Data) print -r -- "Data"$'\t'"$mp" ;;
      /Volumes/*)           [[ $flags != *nobrowse* ]] && is_internal "$mp" && print -r -- "${mp:t}"$'\t'"$mp" ;;
    esac
  done
}

# FileVault state of the volume mounted at $1. "encrypted" is what GP
# sent; "unencrypted" and "unknown" are my guesses at its other values.
volume_encryption() {
  case $(run diskutil info -plist "$1" | plutil -extract FileVault raw - 2>/dev/null) in
    true)  print encrypted ;;
    false) print unencrypted ;;
    *)     print unknown ;;
  esac
}

# yes if every item in the ;-separated list is running (executable path) or
# loaded (launchd:<label>, in the user's GUI session); n/a if none given.
process_state() {
  local item running
  [[ -n ${1-} ]] || { print n/a; return }
  running=$(ps -axo comm=)
  for item in "${(@s:;:)1}"; do
    if [[ $item == launchd:* ]]; then
      local target=${item#launchd:}
      [[ $target == gui/* ]] && target="gui/$UID/${target#gui/}"
      launchctl print "$target" >/dev/null 2>&1 || { print no; return }
    else
      grep -Fxq -- "$item" <<< "$running" || { print no; return }
    fi
  done
  print yes
}

# Installed third-party products in a category, one per line:
# vendor|product|version|state
installed_products() {
  local line category vendor product app process
  for line in $THIRD_PARTY; do
    IFS='|' read -r category vendor product app process <<< "$line"
    [[ $category == "$1" && -d $app ]] || continue
    print -r -- "$vendor|$product|$(bundle_version "$app")|$(process_state "$process")"
  done
}

#--- Report sections ---------------------------------------------------------

# <ip-address> or <ipv6-address> list for an interface; omitted if empty.
address_list() {
  local tag=$1 addr
  local -a addrs=( ${(f)"$(if_addrs "$2" "$3")"} )
  (( $#addrs )) || return 0
  print "<$tag>"
  for addr in $addrs; do entry_leaf "$addr"; done
  print "</$tag>"
}

# Hardware ports only: GP skips lo0, utun*, awdl0 and similar.
network_interfaces() {
  local dev
  print '<network-interface>'
  run networksetup -listallhardwareports | awk '/^Device:/ { print $2 }' |
    while read -r dev; do
      entry_open "$dev"
      el description "$dev"
      el mac-address "$(hardware_mac "$dev")"
      address_list ip-address   "$dev" inet
      address_list ipv6-address "$dev" inet6
      print '</entry>'
    done
  print '</network-interface>'
}

host_info() {
  entry_open host-info
  el client-version "$CLIENT_VERSION"
  el os "Apple Mac OS X $OS_VERSION"
  el os-vendor Apple
  el domain "$DOMAIN"
  el host-name "${HOST%%.*}"
  el host-id "$HOST_ID"
  network_interfaces
  print '</entry>'
}

anti_malware() {
  local vendor product version state
  local xprotect=/Library/Apple/System/Library/CoreServices/XProtect.bundle
  local remediator=/Library/Apple/System/Library/CoreServices/XProtect.app

  category_open anti-malware

  # XProtect has no off switch short of disabling SIP, so installed means
  # running. GP reports XProtect Remediator's version as defver.
  if [[ -d $xprotect ]]; then
    antimalware_product 'Apple Inc.' Xprotect \
      "$(bundle_version $xprotect)" "$(bundle_version $remediator)" \
      "$(mtime $xprotect/Contents/Info.plist)" yes
  fi

  antimalware_product 'Apple Inc.' Gatekeeper "$OS_VERSION" '' '' "$(gatekeeper_state)"

  installed_products anti-malware |
    while IFS='|' read -r vendor product version state; do
      antimalware_product "$vendor" "$product" "$version" '' '' "$state"
    done

  category_close
}

disk_backup() {
  local vendor product version state
  category_open disk-backup
  simple_product 'Apple Inc.' 'Time Machine' \
    "$(bundle_version '/System/Applications/Time Machine.app')" last-backup-time n/a
  installed_products disk-backup |
    while IFS='|' read -r vendor product version state; do
      simple_product "$vendor" "$product" "$version" last-backup-time n/a
    done
  category_close
}

disk_encryption() {
  local label mount state all=encrypted
  category_open disk-encryption
  product_open vendor 'Apple Inc.' name FileVault version "$OS_VERSION"
  print '<drives>'
  # zsh runs the last stage of a pipeline in the current shell, so $all
  # survives the loop (it wouldn't in bash).
  encryption_volumes | while IFS=$'\t' read -r label mount; do
    state=$(volume_encryption "$mount")
    drive "$label" "$state"
    case $state in
      unencrypted) all=unencrypted ;;
      unknown)     [[ $all == unencrypted ]] || all=unknown ;;
    esac
  done
  drive All "$all"
  print '</drives>'
  product_close
  category_close
}

firewall() {
  category_open firewall
  simple_product 'Apple Inc.' 'Mac OS X Builtin Firewall' "$OS_VERSION" \
    is-enabled "$(app_firewall_state)"
  simple_product OpenBSD 'Packet Filter' "$OS_VERSION" \
    is-enabled "$(packet_filter_state)"
  category_close
}

patch_management() {
  local vendor product version state
  category_open patch-management
  simple_product 'Apple Inc.' 'Software Update' \
    "$(bundle_version '/System/Library/CoreServices/Software Update.app')" \
    is-enabled "$(auto_update_state)"
  installed_products patch-management |
    while IFS='|' read -r vendor product version state; do
      simple_product "$vendor" "$product" "$version" is-enabled "$state"
    done
  print '</list>'
  # TODO: pending updates aren't checked, so this always claims none.
  print '<missing-patches/>'
  print '</entry>'
}

data_loss_prevention() {
  category_open data-loss-prevention
  category_close
}

custom_checks() {
  local plist key file_exists key_exists value
  print '<custom-checks>'
  print '<plist>'
  for plist key in $CUSTOM_PLISTS; do
    file_exists=no key_exists=no value=''
    if [[ -f $plist ]]; then
      file_exists=yes
      value=$(run plutil -extract "$key" raw "$plist") && key_exists=yes
    fi
    entry_open "$plist"
    el exist "$file_exists"
    el value ''
    print '<preference-value>'
    entry_open "$key"
    el exist "$key_exists"
    el value "$value"
    print '</entry>'
    print '</preference-value>'
    print '</entry>'
  done
  print '</plist>'
  print '</custom-checks>'
}

hip_report() {
  print '<?xml version="1.0" encoding="UTF-8"?>'
  print '<hip-report>'
  el md5-sum "$MD5"
  el user-name "$USER_NAME"
  el domain "$DOMAIN"
  el host-name "$COMPUTER"
  el host-id "$HOST_ID"
  el ip-address "${opt[--client-ip]-}"
  el ipv6-address "${opt[--client-ipv6]-}"
  el generate-time "$(strftime '%m/%d/%Y %H:%M:%S' $EPOCHSECONDS)"
  el hip-report-version 4
  print '<categories>'
  host_info
  anti_malware
  disk_backup
  disk_encryption
  firewall
  patch_management
  data_loss_prevention
  print '</categories>'
  custom_checks
  print '</hip-report>'
}

#--- Arguments ---------------------------------------------------------------

typeset -A opt
zparseopts -D -E -A opt - -cookie: -client-ip: -client-ipv6: -md5: -client-os: -client-version: -debug
(( ${+opt[--debug]} )) && DEBUG=1

# Decode one field of the URL-encoded login cookie (user=...&domain=...).
url_decode() {
  local s=${1//+/ }
  print -r -- "${(g::)${s//\%/\\x}}"
}

cookie_field() {
  local pair
  for pair in "${(@s:&:)${opt[--cookie]-}}"; do
    if [[ $pair == "$1="* ]]; then
      url_decode "${pair#*=}"
      return
    fi
  done
}

#--- Main --------------------------------------------------------------------

MD5=${opt[--md5]-}
[[ -n $MD5 ]] ||
  print -ru2 -- 'hipreport: warning: no --md5 given; the gateway will reject this'


# The GlobalProtect version we claim to be. Keep in step with openconnect's
# --version-string if you set one.
CLIENT_VERSION=${opt[--client-version]-$CLIENT_VERSION_DEFAULT}

# These must match what the client sent at login, so the cookie wins.
USER_NAME=$(cookie_field user)
DOMAIN=$(cookie_field domain)
COMPUTER=$(cookie_field computer)
[[ -n $USER_NAME ]] || USER_NAME=${USER:-$(id -un)}
[[ -n $COMPUTER ]]  || COMPUTER=${HOST%%.*}

OS_VERSION=$(run sw_vers -productVersion)
HOST_ID=$(hardware_mac "$HOST_ID_INTERFACE")

report=$(hip_report)

# Pretty-print, which also checks the XML is well-formed. If xmllint
# objects, send the raw report anyway and say so on stderr.
if ! xmllint --format - <<< "$report"; then
  print -ru2 -- 'hipreport: warning: report is not well-formed XML'
  print -r -- "$report"
fi