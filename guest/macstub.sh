#!/bin/bash
# Stand-in for macOS tools in the run-darwin phase (copied by dynamic.sh to their Mac paths: /usr/bin/security,
# /usr/bin/osascript, /bin/launchctl, ...). Records argv and stdin in an append-only log, then answers like a Mac
# would, with decoy values (every secret contains AUDITDECOY). strace records every call independently of this log.
name=${0##*/}
LOG=/var/log/audit/macstub.log
in=
[ -t 0 ] || in=$(timeout 2 head -c 4096 2>/dev/null | tr '\n' ' ')
printf '%s uid=%s %s %s | stdin: %s\n' "$(date +%s)" "$(id -u)" "$name" "$*" "${in:0:600}" >> "$LOG" 2>/dev/null
all="$* $in"
case "$name" in
  security)
    case "$1" in
      find-generic-password|find-internet-password)
        case " $* " in *" -w "*|*" -g "*) echo "AUDITDECOY-keychain-secret" ;; *) echo 'keychain: "/Users/sandbox/Library/Keychains/login.keychain-db"' ;; esac ;;
      dump-keychain) echo 'keychain: "/Users/sandbox/Library/Keychains/login.keychain-db"'; echo '    "acct"<blob>="AUDITDECOY"' ;;
      list-keychains|default-keychain|login-keychain) echo '    "/Users/sandbox/Library/Keychains/login.keychain-db"' ;;
    esac ;;
  osascript)
    case "$all" in
      *"display dialog"*|*"hidden answer"*) echo "button returned:OK, text returned:AUDITDECOY-password" ;;
      *"system attribute"*|*"short user name"*) echo "sandbox" ;;
    esac ;;
  sw_vers)
    case "$1" in
      -productName) echo macOS ;; -productVersion) echo 15.5 ;; -buildVersion) echo 24F74 ;;
      *) printf 'ProductName:\t\tmacOS\nProductVersion:\t\t15.5\nBuildVersion:\t\t24F74\n' ;;
    esac ;;
  system_profiler)
    printf 'Hardware:\n\n    Hardware Overview:\n\n      Model Name: MacBook Pro\n      Model Identifier: Mac16,8\n      Chip: Apple M4 Pro\n      Memory: 48 GB\n      Serial Number (system): C02AUDITDECOY\n      Hardware UUID: 6B29FC40-CA47-1067-B31D-00DD010662DA\n' ;;
  ioreg) echo '    |   "IOPlatformSerialNumber" = "C02AUDITDECOY"'; echo '    |   "IOPlatformUUID" = "6B29FC40-CA47-1067-B31D-00DD010662DA"' ;;
  dscl) case "$*" in *authonly*) ;; *) echo sandbox ;; esac ;;   # authonly: exit 0 = password accepted
  pbpaste) echo "AUDITDECOY clipboard text" ;;
  defaults) case "$1" in read) exit 1 ;; esac ;;
  screencapture) for a; do f=$a; done; [ -n "${f:-}" ] && [ "${f#-}" = "$f" ] && : > "$f" 2>/dev/null ;;
esac
exit 0
