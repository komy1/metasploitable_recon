#!/bin/bash

# Check if at least one argument is given
if [[ -z $1 ]]; then
  echo "Usage: $0 <target|ip|domain or -f filename>" 
  exit 1
fi

OUTPUT_DIR="output"
mkdir -p "$OUTPUT_DIR"

# Log messages with timestamp to general log
log_message() {
  timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  echo "[$timestamp] $1" | tee -a "$OUTPUT_DIR/logs.txt"
}

# Log vulnerabilities with timestamp
log_vuln() {
  timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  echo "[$timestamp] $1" | tee -a "$OUTPUT_DIR/vulnerabilities.txt"
}

# Check for outdated software versions from Nmap scan
check_outdate() {
  local nmap_file="$1"
  local target="$2"

  if grep -q "Apache/2\.0\.[0-9]" "$nmap_file" || grep -q "Apache/1\.[0-9]\." "$nmap_file"; then
    log_vuln "Outdated Apache version (under 2.0) detected on $target. Check $nmap_file"
  fi
  if grep -q "OpenSSH [1-6]\." "$nmap_file" || grep -q "OpenSSH 7\.[0-1]" "$nmap_file"; then
    log_vuln "Outdated OpenSSH version (under 7.2) detected on $target. Check $nmap_file"
  fi
  if grep -q "vsftpd 2\.3\." "$nmap_file"; then
    log_vuln "Outdated vsftpd version (2.3) detected on $target. Check $nmap_file"
  fi
  if grep -q "MySQL 5\.0\." "$nmap_file"; then
    log_vuln "Outdated MySQL version (5.0) detected on $target. Check $nmap_file"
  fi
}

# Check if any HTTP-related services are running on scanned ports
check_web_services() {
  local nmap_file="$1"

  if grep -Eq "80/tcp|443/tcp|8080/tcp|8443/tcp|8000/tcp|8081/tcp|8888/tcp|9000/tcp|3000/tcp" "$nmap_file" || \
     grep -qi "Service: http" "$nmap_file" || \
     grep -qi "Service: https" "$nmap_file" || \
     grep -qi "Service: http-alt" "$nmap_file" || \
     grep -qi "Service: ssl-http" "$nmap_file" || \
     grep -qi "Server: " "$nmap_file" || \
     grep -qi "Content-Type: text/html" "$nmap_file"; then
    return 0
  else
    return 1
  fi
}

# Check Nikto output for known issues
nikto_bugs() {
  local nikto_file="$1"
  local target="$2"

  if grep -qi "High" "$nikto_file"; then
    log_vuln "High severity vulnerabilities found on $target. See $nikto_file"
  fi
  if grep -qi "critical" "$nikto_file"; then
    log_vuln "Critical vulnerabilities found on $target. See $nikto_file"
  fi
  if grep -q "X-Content-Type-Options header is not set" "$nikto_file"; then
    log_vuln "Missing X-Content-Type header on $target. See $nikto_file"
  fi
  if grep -q "HTTP TRACE method enable is active" "$nikto_file"; then
    log_vuln "HTTP TRACE method enabled on $target. See $nikto_file"
  fi
  if grep -q "phpinfo.php" "$nikto_file"; then
    log_vuln "phpinfo.php is exposed on $target. See $nikto_file"
  fi
}

# Perform recon on a single target
perform_recon() {
  local TARGET="$1"
  local TARGET_OUTPUT_DIR="$OUTPUT_DIR/$TARGET"
  mkdir -p "$TARGET_OUTPUT_DIR"

  log_message "Starting recon on target: $TARGET"

  # Ping check
  if ! ping -c 3 "$TARGET" >> "$TARGET_OUTPUT_DIR/ping.txt" 2>&1; then
    log_message "Ping failed. Skipping further checks for $TARGET"
    echo "Ping failed on target '$TARGET'"
    return
  fi

  echo "-----------------------------------------------------"
  log_message "Performing nslookup on target: $TARGET"
  nslookup "$TARGET" 2>&1 | tee "$TARGET_OUTPUT_DIR/nslookup.txt"
  if [ ${PIPESTATUS[0]} -ne 0 ]; then
    log_message "nslookup failed for $TARGET"
  fi

  echo "-----------------------------------------------------"
  log_message "Performing whois on target: $TARGET"
  whois "$TARGET" 2>&1 | tee "$TARGET_OUTPUT_DIR/whois.txt"
  if [ ${PIPESTATUS[0]} -ne 0 ]; then
    log_message "whois failed for $TARGET"
  fi

  echo "-----------------------------------------------------"
  log_message "Running Nmap on $TARGET"
  nmap -sV -sC -O -T4 -p- "$TARGET" 2>&1 | tee "$TARGET_OUTPUT_DIR/nmap.txt"
  if [ ${PIPESTATUS[0]} -ne 0 ]; then
    log_message "Nmap scan failed for $TARGET"
  fi

  echo "-----------------------------------------------------"
  check_outdate "$TARGET_OUTPUT_DIR/nmap.txt" "$TARGET"

  echo "-----------------------------------------------------"
  if check_web_services "$TARGET_OUTPUT_DIR/nmap.txt"; then
    log_message "HTTP/HTTPS service detected. Running Nikto on $TARGET"
    nikto -h "$TARGET" 2>&1 | tee "$TARGET_OUTPUT_DIR/nikto.txt"
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
      log_message "Nikto scan failed for $TARGET"
    else
      nikto_bugs "$TARGET_OUTPUT_DIR/nikto.txt" "$TARGET"
    fi
  else
    log_message "No HTTP/HTTPS services detected on $TARGET"
  fi

  echo "-----------------------------------------------------"
  log_message "Recon done for $TARGET"
  echo -e "\nRecon done for $TARGET"
}

# === Main Control Flow ===

if [ "$1" == "-f" ]; then
  if [ ! -f "$2" ]; then
    echo "File not found: $2"
    exit 1
  fi

  while IFS= read -r TARGET; do
    perform_recon "$TARGET"
  done < "$2"

else
  # Loop over all provided targets
  for TARGET in "$@"; do
    perform_recon "$TARGET"
  done
fi
