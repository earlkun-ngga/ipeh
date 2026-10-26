#!/usr/bin/env bash
# Inspektorat PHP (IPEH) v1.2 - WHM + Linux PHP inventory and passive CVE triage - read-only
# CVE-2026-109618 / CVE-2026-109619, official cPanel advisory 2026-10-21
# Bash 4+; requires rpm, awk, grep, find, sort, coreutils
set -u
export LC_ALL=C

if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'
  CYAN=$'\033[1;36m'; BLUE=$'\033[1;34m'; BOLD=$'\033[1m'
  DIM=$'\033[2m'; RESET=$'\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BLUE=''; BOLD=''; DIM=''; RESET=''
fi
ROOT=/var/cpanel/userdata
ADVISORY='https://support.cpanel.net/hc/en-us/articles/44397389677335-Critical-PHP-Security-Release-CVE-2026-109618-and-CVE-2026-109619'
SEP='-------------------------------------------------------------------------------------------------------------'
HOST=$(hostname -f 2>/dev/null || hostname)

pause_screen() {
  [[ -t 0 ]] || return 0
  printf '\n%sTekan ENTER untuk kembali ke menu...%s' "$DIM" "$RESET"
  read -r _ || true
}
heading() {
  printf '\n%s%s%s\n' "$CYAN" "$SEP" "$RESET"
  printf '%s%s%s\n' "$BOLD" "$1" "$RESET"
  printf '%s%s%s\n' "$CYAN" "$SEP" "$RESET"
}
# Compare dotted version plus RPM release; sufficient for cPanel official patch floors.
version_ge() {
  local have=$1 minimum=$2 first
  [[ $have == "$minimum" ]] && return 0
  first=$(printf '%s\n%s\n' "$have" "$minimum" | sort -V | head -n 1)
  [[ $first == "$minimum" ]]
}
show_status() {
  local label=$1 detail=$2 state=$3 code=$4
  local colored
  case "$code" in
    ok) colored="${GREEN}✓ AMAN (PATCHED)${RESET}"; ((ok+=1));;
    bad) colored="${RED}✗ TIDAK AMAN${RESET}"; ((bad+=1));;
    *) colored="${YELLOW}! PERLU VERIFIKASI${RESET}"; ((unknown+=1));;
  esac
  printf '%-17s %-31s %b' "$label" "$detail" "$colored"
  [[ -z $state ]] || printf ' %s' "$state"
  printf '\n'
}
check_patch() {
  local cpver major patch minpatch pkg id installed baseline runtime
  local ok=0 bad=0 unknown=0
  heading 'MENU 1 | AUDIT PATCH PHP2SHELL (READ ONLY)'
  printf 'Server: %s | %s\n' "$HOST" "$(date '+%F %T %Z')"
  printf 'CVE-2026-109618 / CVE-2026-109619\n\n'
  printf '%-17s %-31s %s\n' 'KOMPONEN' 'VERSI / RPM RELEASE' 'STATUS'
  printf '%s\n' "$SEP"
  if [[ -r /usr/local/cpanel/version ]]; then
    cpver=$(tr -d '[:space:]' < /usr/local/cpanel/version)
    major=$(printf '%s' "$cpver" | cut -d. -f2)
    patch=$(printf '%s' "$cpver" | cut -d. -f4)
    minpatch=''
    case "$major" in
      110) minpatch=153;; 134) minpatch=66;; 136) minpatch=50;; 138) minpatch=18;;
    esac
    if [[ -n $minpatch && $patch =~ ^[0-9]+$ ]]; then
      if (( 10#$patch >= minpatch )); then
        show_status 'cPanel/WHM' "$cpver" '' ok
      else
        show_status 'cPanel/WHM' "$cpver" '' bad
      fi
    else
      show_status 'cPanel/WHM' "$cpver" '(branch belum dinilai)' unknown
    fi
  else
    show_status 'cPanel/WHM' 'TIDAK DITEMUKAN' '' unknown
  fi
  if ! command -v rpm >/dev/null 2>&1; then
    printf '%sERROR: rpm tidak tersedia.%s\n' "$RED" "$RESET"
    return 2
  fi
  local -a ids=()
  mapfile -t ids < <(rpm -qa --qf '%{NAME}\n' | grep -E '^ea-php[0-9]{2,3}-(php-common|php-cli)$' | sed -E 's/^ea-php([0-9]{2,3})-.*/\1/' | sort -Vu)
  if (( ${#ids[@]} == 0 )); then
    show_status 'EasyApache PHP' 'TIDAK DITEMUKAN' '' unknown
  fi
  for id in "${ids[@]}"; do
    pkg="ea-php${id}-php-common"
    rpm -q "$pkg" >/dev/null 2>&1 || pkg="ea-php${id}-php-cli"
    installed=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null || true)
    if [[ -z $installed ]]; then
      show_status "ea-php${id}" 'PAKET TIDAK TERBACA' '' unknown
      continue
    fi
    baseline=''
    case "$id" in
      74) baseline='7.4.33-19';; 80) baseline='8.0.30-12';;
      81) baseline='8.1.34-5';; 82) baseline='8.2.35';;
      83) baseline='8.3.36';; 84) baseline='8.4.27';;
      85) baseline='8.5.12';;
    esac
    if [[ -z $baseline ]]; then
      show_status "ea-php${id}" "$installed" '(cek ELS/vendor)' unknown
    elif version_ge "$installed" "$baseline"; then
      show_status "ea-php${id}" "$installed" '' ok
    else
      show_status "ea-php${id}" "$installed" "(minimum: $baseline)" bad
    fi
  done
  printf '%s\n' "$SEP"
  printf '%b%d patched%b | %b%d tidak aman%b | %b%d perlu verifikasi%b\n' "$GREEN" "$ok" "$RESET" "$RED" "$bad" "$RESET" "$YELLOW" "$unknown" "$RESET"
  printf '\n%sCATATAN:%s AMAN = memenuhi baseline kedua CVE saja, bukan jaminan keamanan keseluruhan.\n' "$BOLD" "$RESET"
  printf 'PHP <7.4 atau alt-php memerlukan verifikasi ELS/vendor secara terpisah.\n'
  printf 'Referensi resmi: %s\n' "$ADVISORY"
  printf 'Tidak ada update, instalasi, atau restart service.\n'
}
get_field() {
  local key=$1 file=$2
  awk -v k="$key" 'index($0,k ":")==1 {sub(/^[^:]*:[[:space:]]*/, ""); gsub(/^[\047\"]|[\047\"]$/, ""); print; exit}' "$file" 2>/dev/null
}
htaccess_php() {
  local dir=$1 home=$2 file found
  [[ -d $dir && -d $home ]] || return 0
  dir=$(cd "$dir" 2>/dev/null && pwd -P) || return 0
  home=$(cd "$home" 2>/dev/null && pwd -P) || return 0
  [[ $dir == "$home" || $dir == "$home"/* ]] || return 0
  while :; do
    file=$dir/.htaccess
    if [[ -r $file ]]; then
      found=$(grep -Ei '^[[:space:]]*(AddHandler|SetHandler)[[:space:]].*(ea-php[0-9]{2,3}|alt-php[0-9]{2,3})' "$file" 2>/dev/null | grep -Eo '(ea-php[0-9]{2,3}|alt-php[0-9]{2,3})' | tail -1 || true)
      if [[ -n $found ]]; then printf '%s' "$found"; return 0; fi
    fi
    [[ $dir == "$home" ]] && break
    dir=${dir%/*}; [[ -n $dir ]] || dir=/
  done
}
csv_escape() { local v=${1//\"/\"\"}; printf '"%s"' "$v"; }
write_csv() {
  local n=0 value
  for value in "$@"; do
    (( n == 0 )) || printf ','
    csv_escape "$value"
    n=$((n+1))
  done
  printf '\n'
}
handler_status() {
  local php=$1 web=$2
  if [[ $php == UNKNOWN || -z $php ]]; then echo UNKNOWN; return; fi
  if [[ $php == ea-php* ]]; then
    [[ -x /opt/cpanel/$php/root/usr/bin/php ]] || { echo NOT_INSTALLED; return; }
    if systemctl is-active --quiet "${php}-php-fpm.service" 2>/dev/null; then
      echo FPM_SERVICE_ACTIVE
    elif [[ $web == RUNNING ]]; then
      echo PHP_AVAILABLE
    else
      echo WEB_STOPPED
    fi
  elif [[ $php == alt-php* ]]; then
    echo ALT_PHP_CHECK
  else
    echo UNKNOWN
  fi
}
list_domains() {
  local outfile=${1:-} count=0 legacy=0 web=STOPPED default domain user docroot explicit php source status file base override home
  heading 'MENU 2 | DAFTAR DOMAIN DAN VERSI PHP (READ ONLY)'
  if [[ ! -d $ROOT ]]; then
    printf '%sERROR: %s tidak tersedia.%s\n' "$RED" "$ROOT" "$RESET"
    return 1
  fi
  default=$(/usr/local/cpanel/bin/rebuild_phpconf --current 2>/dev/null | awk '/^DEFAULT PHP:/ {print $3; exit}')
  [[ -n $default ]] || default=UNKNOWN
  if systemctl is-active --quiet httpd 2>/dev/null || pgrep -x httpd >/dev/null 2>&1; then web=RUNNING; fi
  printf 'Server: %s | Default PHP: %s | Apache: %s\n\n' "$HOST" "$default" "$web"
  if [[ -n $outfile ]]; then
    if ! (umask 077; : > "$outfile"); then
      printf 'ERROR: tidak bisa membuat CSV: %s\n' "$outfile" >&2
      return 1
    fi
    write_csv DOMAIN USER PHP SOURCE HANDLER_STATUS DOCUMENT_ROOT > "$outfile"
  fi
  printf '%-42s %-17s %-11s %-13s %-21s %s\n' 'DOMAIN' 'USER' 'PHP' 'SOURCE' 'HANDLER_STATUS' 'DOCUMENT_ROOT'
  printf '%s\n' "$SEP"
  while IFS= read -r -d '' file; do
    base=${file##*/}
    case "$base" in main|cache|userdata|*.cache|*.json|*_SSL|*.yaml) continue;; esac
    [[ $base == *.* ]] || continue
    domain=$(get_field servername "$file")
    [[ -n $domain ]] || continue
    user=$(get_field user "$file")
    [[ -n $user ]] || user=$(basename "$(dirname "$file")")
    docroot=$(get_field documentroot "$file")
    explicit=$(get_field phpversion "$file")
    if [[ $explicit == ea-php* || $explicit == alt-php* ]]; then
      php=$explicit; source=USERDATA
    else
      home="/home/$user"
      override=$(htaccess_php "$docroot" "$home")
      if [[ -n $override ]]; then php=$override; source=HTACCESS
      else php=$default; source=INHERIT_EST; fi
    fi
    status=$(handler_status "$php" "$web")
    if [[ $php == ea-php72 || $php == ea-php73 || $php == alt-php72 || $php == alt-php73 ]]; then
      printf '%b' "$YELLOW"
      legacy=$((legacy+1))
    else
      printf '%b' "$RESET"
    fi
    printf '%-42.42s %-17.17s %-11.11s %-13.13s %-21.21s %s%b\n' "$domain" "$user" "$php" "$source" "$status" "$docroot" "$RESET"
    if [[ -n $outfile ]]; then
      write_csv "$domain" "$user" "$php" "$source" "$status" "$docroot" >> "$outfile"
    fi
    count=$((count+1))
  done < <(find "$ROOT" -mindepth 2 -maxdepth 2 -type f -print0 2>/dev/null | sort -z)
  printf '%s\n' "$SEP"
  printf 'Total: %d domain | PHP 7.2/7.3: %b%d%b\n' "$count" "$YELLOW" "$legacy" "$RESET"
  [[ -z $outfile ]] || printf 'CSV: %s (permissions owner-only)\n' "$outfile"
  printf '%sCatatan:%s HANDLER_STATUS = indikasi layanan, BUKAN status website ONLINE.\n' "$DIM" "$RESET"
  printf 'INHERIT_EST adalah perkiraan; verifikasi PHP efektif di WHM MultiPHP Manager.\n'
}
# Menu 3: Cross-distribution PHP inventory. Report evidence, not guessed active vhost PHP.
get_os_info() {
  local name='' ver='' pretty=''
  if [[ -r /etc/os-release ]]; then
    # os-release is an OS-supplied shell assignment file.
    . /etc/os-release
    pretty=${PRETTY_NAME:-${NAME:-Unknown}}
  elif [[ -r /etc/redhat-release ]]; then
    pretty=$(head -n 1 /etc/redhat-release)
  else
    pretty=$(uname -s)
  fi
  printf '%s' "$pretty"
}
# Label source for binaries based on package type without changing anything.
php_binary_source() {
  local path=$1
  case "$path" in
    /opt/cpanel/ea-php*) printf 'EasyApache';;
    /opt/alt/php*) printf 'CloudLinux ALT';;
    /opt/remi/php*) printf 'Remi SCL';;
    /usr/local/php*) printf 'Custom';;
    *)
      if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -S "$path" 2>/dev/null | head -n 1 | cut -d: -f1
      elif command -v rpm >/dev/null 2>&1; then
        rpm -qf "$path" 2>/dev/null || true
      else
        printf 'system/custom'
      fi;;
  esac
}
linux_php_inventory() {
  local osinfo cli_path cli_ver path ver src service state line pid n=0 fpm_count=0
  local -a candidates=() fpm_services=()
  local -A seen=()
  heading 'MENU 3 | INSPEKSI PHP LINUX (READ ONLY)'
  osinfo=$(get_os_info)
  printf 'Hostname        : %s\n' "$HOST"
  printf 'OS              : %s\n' "$osinfo"
  printf 'Kernel          : %s\n' "$(uname -r)"
  printf 'Arsitektur      : %s\n' "$(uname -m)"
  printf 'Package manager : '
  if command -v dpkg-query >/dev/null 2>&1; then printf 'dpkg/apt\n'
  elif command -v rpm >/dev/null 2>&1; then printf 'rpm/dnf/yum\n'
  else printf 'unknown\n'; fi
  printf '\n%sA. PHP DEFAULT DI TERMINAL (CLI)%s\n' "$BOLD" "$RESET"
  if command -v php >/dev/null 2>&1; then
    cli_path=$(command -v php)
    cli_ver=$(php -r 'echo PHP_VERSION;' 2>/dev/null || true)
    [[ -n $cli_ver ]] || cli_ver=$(php -v 2>/dev/null | head -n 1)
    printf '  %b✓%b PHP CLI: %s | %s\n' "$GREEN" "$RESET" "$cli_ver" "$cli_path"
    if command -v readlink >/dev/null 2>&1; then
      printf '  Target     : %s\n' "$(readlink -f "$cli_path" 2>/dev/null || printf '%s' "$cli_path")"
    fi
  else
    printf '  %b!%b Perintah php tidak ada di PATH. Ini tidak berarti PHP web tidak terpasang.\n' "$YELLOW" "$RESET"
  fi
  printf '\n%sB. SEMUA BINARY PHP YANG DITEMUKAN%s\n' "$BOLD" "$RESET"
  printf '%-46s %-13s %s\n' 'LOKASI BINARY' 'VERSI' 'SUMBER'
  printf '%s\n' "$SEP"
  # Glob-only directory scan avoids crawling user websites or broad /usr trees.
  shopt -s nullglob
  candidates=(/usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php /usr/local/bin/php[0-9]*
              /opt/cpanel/ea-php*/root/usr/bin/php /opt/remi/php*/root/usr/bin/php
              /opt/alt/php*/usr/bin/php /usr/local/php*/bin/php)
  shopt -u nullglob
  for path in "${candidates[@]}"; do
    [[ -f $path && -x $path ]] || continue
    # Only deduplicate the literal path, so distinct aliases remain visible.
    [[ -z ${seen[$path]+set} ]] || continue
    seen[$path]=1
    ver=$("$path" -r 'echo PHP_VERSION;' 2>/dev/null || true)
    [[ $ver =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || ver='TIDAK TERBACA'
    src=$(php_binary_source "$path")
    printf '%-46.46s %-13s %s\n' "$path" "$ver" "${src:-unknown}"
    n=$((n+1))
  done
  (( n > 0 )) || printf 'Tidak ditemukan binary PHP di path umum.\n'
  printf '\n%sC. SERVICE PHP-FPM & PROSES WEB%s\n' "$BOLD" "$RESET"
  if command -v systemctl >/dev/null 2>&1; then
    # Show both active and stopped PHP-FPM units without assuming units are authoritative for vhosts.
    mapfile -t fpm_services < <(systemctl list-units --all --type=service --no-legend --plain 2>/dev/null | awk 'tolower($1) ~ /(php.*fpm|php-fpm)/ {print $1}' | sort -u)
    if (( ${#fpm_services[@]} > 0 )); then
      for service in "${fpm_services[@]}"; do
        state=$(systemctl is-active "$service" 2>/dev/null || true)
        if [[ $state == active ]]; then
          printf '  %b✓%b %-42s %s\n' "$GREEN" "$RESET" "$service" RUNNING
        else
          printf '  %b!%b %-42s %s\n' "$YELLOW" "$RESET" "$service" "${state:-UNKNOWN}"
        fi
      done
    else
      printf '  Tidak ada unit PHP-FPM terdeteksi via systemctl.\n'
    fi
  else
    printf '  systemctl tidak tersedia.\n'
  fi
  if command -v ps >/dev/null 2>&1; then
    printf '\n  Proses PHP-FPM terdeteksi (maks 20 baris):\n'
    ps -eo pid=,comm=,args= 2>/dev/null | awk 'tolower($0) ~ /php-fpm(: master process|: pool| -[fF]|$)/ && tolower($0) !~ /awk/ {print; n++; if(n>=20) exit}'
    printf '\n  Service web yang aktif (indikasi):\n'
    for service in httpd apache2 nginx lsws; do
      if { command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$service" 2>/dev/null; } || pgrep -x "$service" >/dev/null 2>&1; then
        printf '  %b✓%b %s aktif\n' "$GREEN" "$RESET" "$service"
      fi
    done
  fi
  printf '\n%sD. PHP YANG DIGUNAKAN WEBSITE (INDIKATOR)%s\n' "$BOLD" "$RESET"
  if [[ -x /usr/local/cpanel/bin/rebuild_phpconf ]]; then
    line=$(/usr/local/cpanel/bin/rebuild_phpconf --current 2>/dev/null | head -n 12)
    if [[ -n $line ]]; then
      printf '  cPanel EasyApache default/handler:\n%s\n' "$line"
      printf '  Versi per-domain dapat berbeda: lihat MENU 2.\n'
    fi
  fi
  if command -v apachectl >/dev/null 2>&1; then
    line=$(apachectl -M 2>/dev/null | grep -Ei 'php.*module|proxy_fcgi_module' | head -n 6 || true)
    [[ -z $line ]] || printf '  Apache modules:\n%s\n' "$line"
  elif command -v httpd >/dev/null 2>&1; then
    line=$(httpd -M 2>/dev/null | grep -Ei 'php.*module|proxy_fcgi_module' | head -n 6 || true)
    [[ -z $line ]] || printf '  Apache modules:\n%s\n' "$line"
  fi
  printf '\n%b! CATATAN:%b PHP CLI, PHP-FPM aktif, dan PHP aktual per website bisa berbeda.\n' "$YELLOW" "$RESET"
  printf '  Untuk membuktikan versi PHP suatu website, audit vhost/pool atau tes endpoint terproteksi.\n'
  printf '  Menu 3 hanya inventaris versi/runtime, bukan verifikasi patch CVE.\n'
  printf '  Read-only: tidak menginstal paket, mengubah konfigurasi, ataupun restart service.\n'
}
# Passive, read-only triage for PHP2Shell. Not an exploit probe or a proof of compromise.
compromise_scan() {
  local since=${1:-2026-10-17} days=0 scanned=0 found=0 warnings=0 unknown=0
  local file line matches count readable=0 accessn=0 errn=0 fhits=0 hits=0
  local -a access_logs=() error_logs=() scan_dirs=()
  heading 'MENU 4 | PHP2SHELL COMPROMISE TRIAGE (PASIF / READ ONLY)'
  printf 'CVE-2026-109618 / CVE-2026-109619 | Host: %s\n' "$HOST"
  printf 'Periode analisis file/log: sejak %s (berdasarkan mtime; isi log tidak difilter tanggal)\n' "$since"
  printf 'Tidak mengirim request eksploitasi, tidak membunuh proses, tidak memodifikasi file.\n'
  if [[ $EUID -ne 0 ]]; then printf '%b[!] Jalankan sebagai root untuk cakupan log yang lebih lengkap.%b\n' "$YELLOW" "$RESET"; ((unknown+=1)); fi
  if ! date -d "$since" +%s >/dev/null 2>&1; then printf 'ERROR: tanggal harus YYYY-MM-DD.\n' >&2; return 2; fi

  # Use access logs only where there is evidence in URL/headers; POST bodies are usually absent.
  printf '\n%b[A] HTTP ACCESS LOG - upload/session probes (maks 20 contoh)%b\n' "$BOLD" "$RESET"
  for file in /etc/apache2/logs/access_log /usr/local/apache/logs/access_log /var/log/httpd/access_log /var/log/apache2/access.log /var/log/nginx/access.log; do
    [[ -f $file && -r $file && $file -nt /dev/null ]] && access_logs+=("$file")
  done
  if [[ -d /etc/apache2/logs/domlogs ]]; then
    while IFS= read -r -d '' file; do access_logs+=("$file"); done < <(find /etc/apache2/logs/domlogs -maxdepth 1 -type f ! -name '*bytes_log*' -newermt "$since" -print0 2>/dev/null | head -z -n 100)
  fi
  # Bound work per log via tail; do not process all historical traffic.
  for file in "${access_logs[@]}"; do
    [[ -r $file ]] || continue
    ((accessn+=1))
    matches=$(tail -n 12000 "$file" 2>/dev/null | grep -Ei 'PHP_SESSION_UPLOAD_PROGRESS|session\.upload_progress|php2shell|(%5[fF]|_)SESSION_UPLOAD_PROGRESS' | head -n 3 || true)
    if [[ -n $matches ]]; then
      ((hits+=1)); printf '%b[!] %s: upload-progress / php2shell token di HTTP log%b\n' "$YELLOW" "$file" "$RESET"
      printf '%s\n' "$matches" | cut -c 1-260
    fi
  done
  if (( accessn == 0 )); then printf '[?] Tidak ada access log yang terbaca dalam lokasi umum.\n'; ((unknown+=1));
  elif (( hits == 0 )); then printf '%b[✓] Tidak ada token URL/header terkait pada %d access log yang diperiksa.%b\n' "$GREEN" "$accessn" "$RESET"; fi
  ((warnings+=hits))
  printf '    Catatan: body multipart biasanya tidak disimpan di access log; hasil negatif BUKAN bukti aman.\n'

  printf '\n%b[B] PHP / WEB ERRORS & CRASH (maks 15 contoh)%b\n' "$BOLD" "$RESET"
  for file in /etc/apache2/logs/error_log /usr/local/apache/logs/error_log /var/log/httpd/error_log /var/log/apache2/error.log /var/log/nginx/error.log /var/log/php-fpm/error.log /var/log/php*-fpm.log; do
    [[ -f $file && -r $file ]] && error_logs+=("$file")
  done
  hits=0
  for file in "${error_logs[@]}"; do
    ((errn+=1))
    matches=$(tail -n 15000 "$file" 2>/dev/null | grep -Ei 'Allowed memory size.*exhausted|Out of memory|segmentation fault|SIGSEGV|zend_mm_heap corrupted|double free|malloc.*corrupt|child.*exited on signal 11' | tail -n 3 || true)
    if [[ -n $matches ]]; then
      ((hits+=1)); printf '%b[!] %s: OOM/crash/memory error%b\n' "$YELLOW" "$file" "$RESET"
      printf '%s\n' "$matches" | cut -c 1-260
    fi
  done
  if (( errn == 0 )); then printf '[?] Error log umum tidak terbaca.\n'; ((unknown+=1));
  elif (( hits == 0 )); then printf '%b[✓] Tidak ada crash/OOM pada sampel %d error log.%b\n' "$GREEN" "$errn" "$RESET"; fi
  ((warnings+=hits))
  if command -v journalctl >/dev/null 2>&1; then
    matches=$(journalctl --since "$since" --no-pager -q -p warning..emerg 2>/dev/null | grep -Ei 'php|httpd|apache|nginx|lsphp' | grep -Ei 'oom|segfault|SIGSEGV|killed process|memory' | tail -n 5 || true)
    if [[ -n $matches ]]; then printf '%b[!] Journal: indikasi OOM/crash web/PHP%b\n%s\n' "$YELLOW" "$RESET" "$matches"; ((warnings+=1)); fi
  fi

  printf '\n%b[C] PROSES ANAK SHELL DARI WEB/PHP (snapshot)%b\n' "$BOLD" "$RESET"
  # Snapshot, not historical proof. Report only process tree edges that are suspicious.
  if command -v ps >/dev/null 2>&1; then
    matches=$(ps -eo pid=,ppid=,comm=,args= 2>/dev/null | awk '
      {pid=$1; ppid=$2; comm=$3; line=$0; c[pid]=comm; par[pid]=ppid; cmd[pid]=line}
      END {for (pid in c) {p=par[pid]; if (c[pid] ~ /^(sh|bash|dash|curl|wget|python[0-9.]*)$/ && c[p] ~ /^(php|php-fpm|php-cgi|lsphp|httpd|apache2)$/) print cmd[pid] " [parent=" c[p] "]" }}' | head -n 15)
    if [[ -n $matches ]]; then printf '%b[!] Anak shell/tools dari proses PHP/web:%b\n%s\n' "$YELLOW" "$RESET" "$matches"; ((warnings+=1));
    else printf '%b[✓] Snapshot proses tidak menemukan pola anak shell tersebut.%b\n' "$GREEN" "$RESET"; fi
  else printf '[?] ps tidak tersedia.\n'; ((unknown+=1)); fi

  printf '\n%b[D] PHP FILE BARU/BERUBAH (maks 30; bukan bukti webshell)%b\n' "$BOLD" "$RESET"
  if [[ -d /home ]]; then
    matches=$(find /home -type f \( -iname '*.php' -o -iname '*.phtml' \) -newermt "$since" -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' 2>/dev/null | head -n 30)
    if [[ -n $matches ]]; then printf '%b[!] File PHP berubah sejak tanggal awal:%b\n%s\n' "$YELLOW" "$RESET" "$matches"; ((warnings+=1));
    else printf '%b[✓] Tidak ada perubahan file PHP yang terlihat di /home.%b\n' "$GREEN" "$RESET"; fi
  else printf '[?] /home tidak ada; docroot mungkin berbeda.\n'; ((unknown+=1)); fi
  printf '    Bandingkan dengan deployment/update aplikasi resmi sebelum menetapkan insiden.\n'

  printf '\n%b[E] PHP WEB PROCESS RESTART / OOM SYSTEM%b\n' "$BOLD" "$RESET"
  if command -v journalctl >/dev/null 2>&1; then
    matches=$(journalctl -k --since "$since" --no-pager -q 2>/dev/null | grep -Ei 'out of memory|oom-killer|killed process|segfault' | tail -n 8 || true)
    if [[ -n $matches ]]; then printf '%b[!] Kernel OOM/segfault tercatat:%b\n%s\n' "$YELLOW" "$RESET" "$matches"; ((warnings+=1));
    else printf '%b[✓] Tidak ada OOM/segfault pada kernel journal yang tersedia.%b\n' "$GREEN" "$RESET"; fi
  else printf '[?] journalctl tidak tersedia.\n'; ((unknown+=1)); fi

  printf '\n%s\n' "$SEP"
  if (( warnings > 0 )); then
    printf '%b[!] %d KELOMPOK TEMUAN PERLU INVESTIGASI LANJUT%b\n' "$YELLOW" "$warnings" "$RESET"
  else
    printf '%b[✓] TIDAK ADA INDIKATOR DITEMUKAN pada cakupan dan sampel pemeriksaan.%b\n' "$GREEN" "$RESET"
  fi
  if (( unknown > 0 )); then printf '%b[?] %d area tidak terverifikasi.%b\n' "$YELLOW" "$unknown" "$RESET"; fi
  printf 'PENTING: Ini TRIAGE pasif, bukan deteksi definitif, tidak membuktikan host bersih atau CVE tidak exploitable.\n'
  printf 'Untuk forensik, simpan log asli dan lakukan investigasi IR bila ada indikasi.\n'
}

menu() {
  local choice csv
  if [[ ! -t 0 ]]; then
    printf 'Mode interaktif memerlukan terminal. Gunakan --patch, --domains [--csv FILE], atau --linux / --compromise.\n' >&2
    return 2
  fi
  while :; do
    if command -v clear >/dev/null 2>&1 && [[ -t 1 ]]; then clear; fi
    printf '%s' "$CYAN"
    printf '=============================================================\n'
    printf '          INSPEKTORAT PHP (IPEH)\n'
    printf '=============================================================%s\n' "$RESET"
    printf ' Server : %s\n' "$HOST"
    printf ' Mode   : %sREAD ONLY%s\n\n' "$GREEN" "$RESET"
    printf ' %s[1]%s Check php2shell Version & Patch Status\n' "$CYAN" "$RESET"
    printf ' %s[2]%s List Domain & PHP Version\n' "$CYAN" "$RESET"
    printf ' %s[3]%s Cek OS Linux dan PHP Terpasang/Terpakai\n' "$CYAN" "$RESET"
    printf ' %s[4]%s Scan Indikasi Kompromi PHP2Shell\n' "$CYAN" "$RESET"
    printf ' %s[5]%s Exit\n\n' "$CYAN" "$RESET"
    printf ' Pilih menu [1-5]: '
    read -r choice || return 0
    case "$choice" in
      1) check_patch; pause_screen;;
      2)
         printf ' Export CSV? [y/N]: '
         read -r csv || csv=n
         if [[ $csv == [yY] || $csv == [yY][eE][sS] ]]; then
           list_domains "/root/whm-domain-php-$(date +%Y%m%d-%H%M%S).csv"
         else
           list_domains
         fi
         pause_screen;;
      3) linux_php_inventory; pause_screen;;
      4) compromise_scan; pause_screen;;
      5) printf '\nSelesai. Tidak ada konfigurasi yang diubah.\n'; return 0;;
      *) printf '%sPilihan tidak valid.%s\n' "$RED" "$RESET"; pause_screen;;
    esac
  done
}
case ${1:-} in
  '') menu;;
  --patch) [[ $# -eq 1 ]] || { echo 'Usage: --patch' >&2; exit 2; }; check_patch;;
  --domains)
    if [[ $# -eq 1 ]]; then list_domains
    elif [[ $# -eq 3 && $2 == --csv && -n $3 ]]; then list_domains "$3"
    else echo 'Usage: --domains [--csv /path/report.csv]' >&2; exit 2; fi;;
  --linux) [[ $# -eq 1 ]] || { echo 'Usage: --linux' >&2; exit 2; }; linux_php_inventory;;
  --compromise)
    if [[ $# -eq 1 ]]; then compromise_scan
    elif [[ $# -eq 3 && $2 == --since ]]; then compromise_scan "$3"
    else echo 'Usage: --compromise [--since YYYY-MM-DD]' >&2; exit 2; fi;;
  --help|-h)
    printf 'Usage: %s [--patch | --domains [--csv FILE] | --linux | --compromise [--since YYYY-MM-DD] | --help]\n' "$0";;
  *) echo 'Unknown option; use --help' >&2; exit 2;;
esac
