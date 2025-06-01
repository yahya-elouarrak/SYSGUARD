#!/bin/bash
#Clean up
rm -r sysguard_reports

#Fonction pour afficher les infos du script

function display_banner() {
    echo -e "${GREEN}${BOLD}"
    echo "  ███████╗██╗   ██╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ "
    echo "  ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
    echo "  ███████╗ ╚████╔╝ ███████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
    echo "  ╚════██║  ╚██╔╝  ╚════██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
    echo "  ███████║   ██║   ███████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
    echo "  ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
    echo -e "-----------------------------------------------------------------"
    echo -e "${BOLD}${GREEN}SYSGUARD: Syslog & Suspicious Activity Analyzer"
    echo -e "${BOLD}${GREEN}Author: y4hya - wissal - youssef"
    echo -e "${BOLD}${GREEN}Version: 1.0"
    echo ""
}



#Fonction pour l'Installation automatique des packages necessaires

function install_packages() {
  echo -e "${BOLD}${GREEN}Starting installing required packages...${RESET}"

  # List of system packages to check and install
  system_packages=(python3 python3-pandas mutt)
  for pkg in "${system_packages[@]}"; do
    if dpkg -s "$pkg" &> /dev/null; then
      echo -e "${GREEN}Package $pkg is already installed. Skipping.${RESET}"
    else
      echo -e "${GREEN}Installing package $pkg...${RESET}"
      sudo apt-get install -y "$pkg"
    fi
    done

  echo -e "${BOLD}${GREEN}Finished installing required packages!${RESET}"
}


#Les couleurs de text, niveau de risque

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'



#Configuration 
#Si aucun fichier log n'est spécifié, le script vérifie par défaut /var/log/auth.log et /var/log/syslog.log
#si le path de sortie n'est pas spécifié, par défaut la sortie est stocké dans /sysguard_reports

FORK_MODE=false
THREAD_MODE=false
LOG_FILES=()
OUTPUT_DIR="$(pwd)/sysguard_reports"
TIMESTAMP=$(date +"%Y-%d-%m___%H-%M-%S")
SESSION_LOG="${OUTPUT_DIR}/sysguard-${TIMESTAMP}.log"
ALERTS_LOG="${OUTPUT_DIR}/alerts-${TIMESTAMP}.log"

EMAIL_MODE=false
EMAIL_RECIPIENT=""
EMAIL_SUBJECT="[SYSGUARD] Security Alert Report"
EMAIL_HIGH_ONLY=true  # Set to true to only send emails for HIGH severity alerts
EXCEL_MODE=false

REALTIME_MODE=false
REALTIME_INTERVAL=2



#Fonction pour afficher un tutorial du script

function display_help() {
    echo -e "${BOLD}${YELLOW}Usage:${NC} ./sysguard.sh [options] [log_file1] [log_file2] ..."
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  -h, --help            Display this help message"
    echo "  -f, --fork            Fork to analyze multiple files in parallel"
    echo "  -t, --thread          Spawn a thread per detection rule"
    echo "  -o, --output DIR      Specify output directory (default: current-directory/sysguard)"
    echo "  -e, --excel           Generate Excel report"
    echo "  -m, --email EMAIL     Send alert notifications to specified email"
    echo "  --realtime            Start real-time log monitoring"
    echo "  --realtime-interval N Set real-time check interval in seconds (default: 2)"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 /var/log/auth.log"
    echo "  $0 -f /var/log/auth.log /var/log/syslog"
    echo "  $0 -t -o /tmp/sysguard_output /var/log/auth.log"
    echo "  $0 -e -m admin@example.com /var/log/auth.log"
    echo "  $0 --realtime -m admin@example.com"
    echo ""
    echo -e "${BOLD}Default log files if none specified:${NC}"
    echo "  /var/log/auth.log  &  /var/log/syslog"
    echo ""
}



#Fonction pour Verifier que le script est executé en mode administrateur

function check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}${BOLD}Warning:${NC} Running without root privileges. Some log files may not be accessible."
        echo "Consider running with sudo for full functionality."
        echo ""
    fi
}



#Fonction pour Creer la structure du dossier de sortie

function init_output_dir() {
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        mkdir -p "$OUTPUT_DIR" || {
            echo -e "${RED}${BOLD}Error:${NC} Failed to create output directory $OUTPUT_DIR"
            exit 1
        }
        echo -e "${GREEN}Created output directory:${NC} $OUTPUT_DIR"
    fi
    
    # Initialize session log
    echo "=== SYSGUARD SESSION: $(date) ===" > "$SESSION_LOG"
    echo "=== SYSGUARD ALERTS: $(date) ===" > "$ALERTS_LOG"
}



#Fonction pour Ajouter le message log dans le log du session

function log_message() {
    local level="$1"
    local message="$2"
    local color=""
    
    case "$level" in
        "INFO") color="${GREEN}" ;;
        "WARNING") color="${YELLOW}" ;;
        "ERROR") color="${RED}" ;;
        *) color="${NC}" ;;
    esac
    
    echo -e "${color}[$level] $message${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$SESSION_LOG"

}



#fonction pour Ajouter l'alert log dans le log des alertes

function record_alert() {
    local severity="$1"
    local source="$2"
    local message="$3"
    local color=""
    
    case "$severity" in
        "LOW") color="${GREEN}" ;;
        "MEDIUM") color="${YELLOW}" ;;
        "HIGH") color="${RED}" ;;
        *) color="${NC}" ;;
    esac
    
    echo -e "${color}[ALERT:$severity] $message${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ALERT:$severity] [$source] $message" >> "$ALERTS_LOG"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ALERT:$severity] [$source] $message" >> "$SESSION_LOG"
    
    # Send email alert if enabled
    if [[ "$EMAIL_MODE" = true ]]; then
        send_email_alert "$severity" "$source" "$message"
    fi
}



#Fonction pour la Configuration des options (-h -t -f -o -m -e)

function parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                display_help
                exit 0
                ;;
            -f|--fork)
                FORK_MODE=true
                shift
                ;;
            -t|--thread)
                THREAD_MODE=true
                shift
                ;;
            -o|--output)
                if [[ -n "$2" && "$2" != -* ]]; then
                    OUTPUT_DIR="$2"
                    shift 2
                else
                    echo -e "${RED}${BOLD}Error:${NC} Output directory not specified."
                    exit 1
                fi
                ;;
            -e|--excel)
                EXCEL_MODE=true
                shift
                ;;
            -m|--email)
                EMAIL_MODE=true
                if [[ -n "$2" && "$2" != -* ]]; then
                    EMAIL_RECIPIENT="$2"
                    shift 2
                else
                    echo -e "${RED}${BOLD}Error:${NC} Email recipient not specified."
                    exit 1
                fi
                ;;
            --email-all)
                EMAIL_HIGH_ONLY=false
                shift
                ;;
            --realtime)
                REALTIME_MODE=true
                shift
                ;;
            --realtime-interval)
                if [[ -n "$2" && "$2" != -* ]]; then
                    REALTIME_INTERVAL="$2"
                    shift 2
                else
                    echo -e "${RED}${BOLD}Error:${NC} Realtime interval not specified."
                    exit 1
                fi
                ;;
            *)
                if [[ -f "$1" ]]; then
                    LOG_FILES+=("$1")
                else
                    echo -e "${RED}${BOLD}Error:${NC} File not found: $1"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # If no log files specified, use defaults
    if [[ ${#LOG_FILES[@]} -eq 0 ]]; then
        if [[ -f "/var/log/auth.log" ]]; then
            LOG_FILES+=("/var/log/auth.log")
        fi
        if [[ -f "/var/log/syslog" ]]; then
            LOG_FILES+=("/var/log/syslog")
        fi
        
        # If still no log files found
        if [[ ${#LOG_FILES[@]} -eq 0 ]]; then
            echo -e "${RED}${BOLD}Error:${NC} No log files found. Please specify log files."
            exit 1
        fi
        ###################################

    fi
}




############################## Real time function ###########################################



function start_realtime_watcher() {
    local watch_files=("${LOG_FILES[@]}")
    
    log_message "INFO" "Starting real-time watcher for files: ${watch_files[*]}"
    log_message "INFO" "Check interval: ${REALTIME_INTERVAL} seconds"
    
    # Create a temporary directory for tracking file positions
    local watch_dir="${OUTPUT_DIR}/realtime_watch"
    mkdir -p "$watch_dir"
    
    # Initialize position files for each log file
    local position_files=()
    for log_file in "${watch_files[@]}"; do
        local pos_file="${watch_dir}/$(basename "$log_file").pos"
        position_files+=("$pos_file")
        
        # Initialize position to end of file (only watch new entries)
        if [[ -f "$log_file" ]]; then
            wc -l < "$log_file" > "$pos_file"
        else
            echo "0" > "$pos_file"
        fi
    done
    
    log_message "INFO" "Real-time monitoring started. Press Ctrl+C to stop."
    echo -e "${GREEN}${BOLD}Real-time monitoring active...${NC}"
    echo -e "${YELLOW}Monitoring files: ${watch_files[*]}${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    echo ""
    
    # Main monitoring loop
    while true; do
        local i=0
        for log_file in "${watch_files[@]}"; do
            local pos_file="${position_files[$i]}"
            
            # Check if log file exists and is readable
            if [[ ! -f "$log_file" || ! -r "$log_file" ]]; then
                ((i++))
                continue
            fi
            
            # Get current line count and last processed position
            local current_lines=$(wc -l < "$log_file")
            local last_position=$(cat "$pos_file" 2>/dev/null || echo "0")
            
            # If there are new lines to process
            if [[ $current_lines -gt $last_position ]]; then
                local new_lines=$((current_lines - last_position))
                log_message "${RED}Detected Suspicious activity in $log_file${NC}"
                
                # Extract new lines and process them
                tail -n +$((last_position + 1)) "$log_file" | head -n "$new_lines" | while IFS= read -r line; do
                    process_realtime_line "$line" "$log_file"
                done
                
                # Update position file
                echo "$current_lines" > "$pos_file"
            fi
            
            ((i++))
        done
        
        # Sleep for specified interval
        sleep "$REALTIME_INTERVAL"
    done
}

function process_realtime_line() {
    local line="$1"
    local source_file="$2"
    
    # Check for SSH brute force patterns
    if echo "$line" | grep -qEi 'sshd.*Failed password|sshd.*Invalid user'; then
        local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
        if [[ -n "$ip" ]]; then
            check_ssh_brute_force "$ip" "$line" "$source_file"
        fi
    fi
    
    # Check for sudo abuse patterns
    if echo "$line" | grep -qEi 'sudo.*authentication failure|sudo.*user NOT in sudoers'; then
        local username=$(echo "$line" | grep -oE 'user=[^ ]+' | cut -d= -f2)
        if [[ -n "$username" ]]; then
            check_sudo_abuse "$username" "$line" "$source_file"
        fi
    fi
    muttconf
    # Check for root login attempts
    if echo "$line" | grep -qEi 'session opened.*for user root'; then
        send_email "SYSGUARD ALERT !" "HIGH SEVERITY ALERT | Direct root login detected: $source_file" "$EMAIL_RECIPIENT"
    fi
    
    # Check for unusual login hours (11PM - 5AM)
    if echo "$line" | grep -qE 'session opened' && echo "$line" | grep -qE '(2[3]|[0-4]):[0-9]{2}:[0-9]{2}'; then
        local username=$(echo "$line" | grep -oE 'for user [^ ]+' | awk '{print $3}')
        send_email "SYSGUARD ALERT !" "MEDIUM SEVERITY ALERT | UNUSUAL_HOURS | Login during unusual hours by user $username: $line" "$EMAIL_RECIPIENT"
    fi
}

function check_ssh_brute_force() {
    local ip="$1"
    local line="$2"
    local source_file="$3"
    
    local ssh_track_file="${OUTPUT_DIR}/realtime_watch/ssh_failures_${ip//\./_}.count"
    local current_count=0
    
    if [[ -f "$ssh_track_file" ]]; then
        current_count=$(cat "$ssh_track_file")
    fi
    ((current_count++))
    echo "$current_count" > "$ssh_track_file"
    muttconf
    if [[ $current_count -ge 5 ]]; then
        send_email "SYSGUARD ALERT !" "HIGH SEVERITY ALERT | SSH_BRUTE_FORCE | Brute force attack detected: $current_count failed SSH attempts from IP $ip" "$EMAIL_RECIPIENT"
        echo "0" > "$ssh_track_file"
    elif [[ $current_count -ge 3 ]]; then
        send_email "SYSGUARD ALERT !" "MEDIUM SEVERITY ALERT | SSH_SUSPICIOUS | Multiple SSH failures from IP $ip" "$EMAIL_RECIPIENT"
    fi
    
    find "${OUTPUT_DIR}/realtime_watch" -name "ssh_failures_*.count" -mmin +60 -delete 2>/dev/null
}

function check_sudo_abuse() {
    local username="$1"
    local line="$2"
    local source_file="$3"
    
    local sudo_track_file="${OUTPUT_DIR}/realtime_watch/sudo_failures_${username}.count"
    local current_count=0
    
    if [[ -f "$sudo_track_file" ]]; then
        current_count=$(cat "$sudo_track_file")
    fi
    
    ((current_count++))
    echo "$current_count" > "$sudo_track_file"
    muttconf
    if [[ $current_count -ge 3 ]]; then
        send_email "SYSGUARD ALERT !" "HIGH SEVERITY ALERT | SUDO_ABUSE | Potential sudo abuse: $current_count failed attempts by user $username" "$EMAIL_RECIPIENT"
        echo "0" > "$sudo_track_file"
    fi
    
    find "${OUTPUT_DIR}/realtime_watch" -name "sudo_failures_*.count" -mmin +60 -delete 2>/dev/null
}

#############################################################################################




#Fonction pour Analyser les authentification ssh échoués

function analyze_ssh_auth_failures() {
    local log_file="$1"
    local tmp_file="${OUTPUT_DIR}/ssh_failures_$(basename "$log_file").tmp"
    
    log_message "INFO" "Analyzing SSH authentication failures in $log_file"
    
    # Extract SSH authentication failures with IP and username
    grep -Ei 'sshd.*Failed password|sshd.*Invalid user' "$log_file" > "$tmp_file"
    
    if [[ -s "$tmp_file" ]]; then
        # Get unique IPs with failure counts
        local ip_counts=$(grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' "$tmp_file" | awk '{print $2}' | sort | uniq -c | sort -nr)
        
        while read -r count ip; do
            if [[ $count -gt 5 ]]; then
                local severity="HIGH"
                local message="Potential brute force attack: $count failed SSH authentication attempts from IP $ip"
                record_alert "$severity" "SSH" "$message"
                
                # Get usernames tried from this IP
                local usernames=$(grep "$ip" "$tmp_file" | grep -oE 'user [^ ]+' | sort | uniq | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
                record_alert "$severity" "SSH" "Usernames attempted from $ip: $usernames"
            elif [[ $count -gt 2 ]]; then
                local severity="MEDIUM"
                local message="Multiple failed SSH authentications: $count attempts from IP $ip"
                record_alert "$severity" "SSH" "$message"
            fi
        done <<< "$ip_counts"
    else
        log_message "INFO" "No SSH authentication failures found in $log_file"
    fi
    
    rm -f "$tmp_file"
}



#Fonction pour Analyser les tentatives sudo

function analyze_sudo_attempts() {
    local log_file="$1"
    local tmp_file="${OUTPUT_DIR}/sudo_failures_$(basename "$log_file").tmp"
    
    log_message "INFO" "Analyzing sudo usage and failures in $log_file"
    
    # Extract sudo authentication failures
    grep -Ei 'sudo.*authentication failure|sudo.*user NOT in sudoers' "$log_file" > "$tmp_file"
    
    if [[ -s "$tmp_file" ]]; then
        # Get users with sudo failure counts
        local user_counts=$(grep -oE 'user=[^ ]+' "$tmp_file" | sort | uniq -c | sort -nr)
        
        while read -r count user_entry; do
            local username=${user_entry#user=}
            
            if [[ $count -gt 3 ]]; then
                local severity="HIGH"
                local message="Potential sudo abuse: $count failed sudo attempts by user $username"
                record_alert "$severity" "SUDO" "$message"
                
                # Get commands attempted with sudo by this user
                local commands=$(grep "$username" "$tmp_file" | grep -oE 'COMMAND=[^ ]+' | sort | uniq | tr '\n' ',' | sed 's/,$//')
                if [[ -n "$commands" ]]; then
                    record_alert "$severity" "SUDO" "Commands attempted with sudo by $username: $commands"
                fi
            elif [[ $count -gt 1 ]]; then
                local severity="MEDIUM"
                local message="Multiple failed sudo attempts by user $username"
                record_alert "$severity" "SUDO" "$message"
            fi
        done <<< "$user_counts"
    else
        log_message "INFO" "No sudo failures found in $log_file"
    fi
    
    # Check for users not in sudoers
    local not_in_sudoers=$(grep 'sudo.*NOT in sudoers' "$log_file")
    if [[ -n "$not_in_sudoers" ]]; then
        local users=$(echo "$not_in_sudoers" | grep -oE 'user=[^ ]+' | sort | uniq | awk -F= '{print $2}' | tr '\n' ',' | sed 's/,$//')
        local severity="MEDIUM"
        local message="Users attempting sudo without permission: $users"
        record_alert "$severity" "SUDO" "$message"
    fi
    
    rm -f "$tmp_file"
}



#Fonction pour analyser les tentatives de connection utilisateur

function analyze_user_logins() {
    local log_file="$1"
    local tmp_file="${OUTPUT_DIR}/user_logins_$(basename "$log_file").tmp"
    
    log_message "INFO" "Analyzing user login patterns in $log_file"
    
    # Extract successful and failed logins
    grep -Ei 'session opened|session closed|Failed login|Invalid user' "$log_file" > "$tmp_file"
    
    if [[ -s "$tmp_file" ]]; then
        # Check for logins at unusual hours (11PM - 5AM)
        local unusual_hours=$(grep -E 'session opened' "$tmp_file" | grep -E '(2[3]|[0-4]):[0-9]{2}:[0-9]{2}')
        if [[ -n "$unusual_hours" ]]; then
            local users=$(echo "$unusual_hours" | grep -oE 'for user [^ ]+' | awk '{print $3}' | sort | uniq | tr '\n' ',' | sed 's/,$//')
            local severity="MEDIUM"
            local message="Logins during unusual hours (11PM-5AM) for users: $users"
            record_alert "$severity" "LOGIN" "$message"
        fi
        
        # Check for root direct logins
        local root_logins=$(grep -E 'session opened.*for user root' "$tmp_file")
        if [[ -n "$root_logins" ]]; then
            local count=$(echo "$root_logins" | wc -l)
            local severity="HIGH"
            local message="$count direct root logins detected. Consider disabling root SSH access."
            record_alert "$severity" "LOGIN" "$message"
        fi
    else
        log_message "INFO" "No login events found in $log_file"
    fi
    
    rm -f "$tmp_file"
}



#Fonction pour analyser les tentatives d'authentification échoués

function analyze_auth_failures() {
    local log_file="$1"
    local tmp_file="${OUTPUT_DIR}/auth_failures_$(basename "$log_file").tmp"
    
    log_message "INFO" "Analyzing general authentication failures in $log_file"
    
    # Extract authentication failures
    grep -Ei 'authentication failure|failed|Invalid user' "$log_file" | grep -v 'sudo' > "$tmp_file"
    
    if [[ -s "$tmp_file" ]]; then
        # Check for PAM authentication failures
        local pam_failures=$(grep -E 'pam_.*:auth): authentication failure' "$tmp_file")
        if [[ -n "$pam_failures" ]]; then
            local count=$(echo "$pam_failures" | wc -l)
            local severity="MEDIUM"
            
            # Get services with auth failures
            local services=$(echo "$pam_failures" | grep -oE 'pam_[^:]+' | sort | uniq | tr '\n' ',' | sed 's/,$//')
            local message="$count PAM authentication failures across services: $services"
            record_alert "$severity" "AUTH" "$message"
        fi
        
        # Check for repeated auth failures by the same user
        local user_failures=$(grep -oE 'user=[^ ]+' "$tmp_file" | sort | uniq -c | sort -nr)
        while read -r count user_entry; do
            if [[ $count -gt 3 ]]; then
                local username=${user_entry#user=}
                local severity="MEDIUM"
                local message="$count authentication failures for user $username"
                record_alert "$severity" "AUTH" "$message"
            fi
        done <<< "$user_failures"
    else
        log_message "INFO" "No authentication failures found in $log_file"
    fi
    
    rm -f "$tmp_file"
}



#Fonction pour analyser le fichier log utilisant tout les verification précédentes

function analyze_log_file() {
    local log_file="$1"
    
    log_message "INFO" "Starting analysis of $log_file"
    
    if [[ ! -f "$log_file" ]]; then
        log_message "ERROR" "File not found: $log_file"
        return 1
    fi
    
    if [[ ! -r "$log_file" ]]; then
        log_message "ERROR" "Cannot read file: $log_file"
        return 1
    fi
    
    # Define the analysis functions to run
    local analysis_functions=(
        "analyze_ssh_auth_failures"
        "analyze_sudo_attempts"
        "analyze_user_logins"
        "analyze_auth_failures"
    )
    
    if [[ "$THREAD_MODE" = true ]]; then
        # Run each analysis function in a separate thread
        for func in "${analysis_functions[@]}"; do
            $func "$log_file" &
        done
        wait  # Wait for all threads to complete
    else
        # Run analysis functions sequentially
        for func in "${analysis_functions[@]}"; do
            $func "$log_file"
        done
    fi
    
    log_message "INFO" "Completed analysis of $log_file"
}



#Generer un rapport

function generate_summary() {
    summary_file="${OUTPUT_DIR}/sysguard-summary-${TIMESTAMP}.txt"
    
    echo "=== SYSGUARD ANALYSIS SUMMARY ===" > "$summary_file"
    echo "Generated on: $(date)" >> "$summary_file"
    echo "Log files analyzed: ${LOG_FILES[*]}" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Count alerts by severity
    local high_alerts=$(grep -c "\[ALERT:HIGH\]" "$ALERTS_LOG" || echo "0")
    local medium_alerts=$(grep -c "\[ALERT:MEDIUM\]" "$ALERTS_LOG" || echo "0")
    local low_alerts=$(grep -c "\[ALERT:LOW\]" "$ALERTS_LOG" || echo "0")
    local total_alerts=$(high_alerts+medium_alerts+low_alerts)
    
    echo "=== ALERT SUMMARY ===" >> "$summary_file"
    echo "Total alerts: $total_alerts" >> "$summary_file"
    echo "  HIGH severity: $high_alerts" >> "$summary_file"
    echo "  MEDIUM severity: $medium_alerts" >> "$summary_file"
    echo "  LOW severity: $low_alerts" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # List all HIGH severity alerts
    if [[ $high_alerts -gt 0 ]]; then
        echo "=== HIGH SEVERITY ALERTS ===" >> "$summary_file"
        grep "\[ALERT:HIGH\]" "$ALERTS_LOG" | sed 's/\[ALERT:HIGH\] //g' >> "$summary_file"
        echo "" >> "$summary_file"
    fi
    
    # Get unique IPs involved in alerts
    local suspicious_ips=$(grep -oE "from ([0-9]{1,3}\.){3}[0-9]{1,3}" "$ALERTS_LOG" | awk '{print $2}' | sort | uniq)
    if [[ -n "$suspicious_ips" ]]; then
        echo "=== SUSPICIOUS IPs DETECTED ===" >> "$summary_file"
        echo "$suspicious_ips" >> "$summary_file"
        echo "" >> "$summary_file"
    fi
    
    # Get users involved in alerts
    local suspicious_users=$(grep -oE "user [a-zA-Z0-9_-]+" "$ALERTS_LOG" | awk '{print $2}' | sort | uniq)
    if [[ -n "$suspicious_users" ]]; then
        echo "=== USERS INVOLVED IN ALERTS ===" >> "$summary_file"
        echo "$suspicious_users" >> "$summary_file"
        echo "" >> "$summary_file"
    fi
    
    echo "Full logs available at:" >> "$summary_file"
    echo "  Session log: $SESSION_LOG" >> "$summary_file"
    echo "  Alerts log: $ALERTS_LOG" >> "$summary_file"
    
    echo -e "${GREEN}${BOLD}Summary report generated:${NC} $summary_file"
    
    # Display a brief summary to the console
    echo ""
    echo -e "${BOLD}=== ANALYSIS SUMMARY ===${NC}"
    echo -e "Total alerts: $total_alerts (${RED}HIGH: $high_alerts${NC}, ${YELLOW}MEDIUM: $medium_alerts${NC}, ${GREEN}LOW: $low_alerts${NC})"
    
    if [[ $high_alerts -gt 0 ]]; then
        echo -e "${RED}${BOLD}HIGH SEVERITY ALERTS DETECTED!${NC} Check the summary report."
    fi
    
    echo -e "Full report: $summary_file"
}



#Rapport excel

function create_excel_converter() {
    local python_script="xlsx_writer.py"
    
    cat > "$python_script" << 'EOL'
#!/usr/bin/env python3
import sys
import pandas as pd
import re
from datetime import datetime

def parse_alert_line(line):
    # Parse typical alert line format
    match = re.match(r'\[(.*?)\] \[ALERT:(.*?)\] \[(.*?)\] (.*)', line)
    if match:
        timestamp, severity, source, message = match.groups()
        return {
            'Timestamp': timestamp,
            'Severity': severity,
            'Source': source,
            'Message': message
        }
    return None

def parse_summary_section(content, section_name):
    # Extract data from summary sections
    section_pattern = f"=== {section_name} ===\n(.*?)(?:\n\n|\n===|$)"
    match = re.search(section_pattern, content, re.DOTALL)
    if match:
        return match.group(1).strip().split('\n')
    return []

def txt_to_excel(alert_file, summary_file, output_file):
    # Read alert data
    with open(alert_file, 'r') as file:
        alert_lines = file.readlines()[1:]  # Skip the header line
    
    # Parse alert data
    alerts = []
    for line in alert_lines:
        line = line.strip()
        if line:
            alert_data = parse_alert_line(line)
            if alert_data:
                alerts.append(alert_data)
    
    # Read summary data
    with open(summary_file, 'r') as file:
        summary_content = file.read()
    
    # Create Excel writer
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        # Create alerts sheet
        if alerts:
            alerts_df = pd.DataFrame(alerts)
            alerts_df.to_excel(writer, sheet_name='Alerts', index=False)
        
        # Create summary sheet
        summary_data = []
        summary_data.append(['Generated on', re.search(r'Generated on: (.*)', summary_content).group(1)])
        
        # Extract analyzed log files
        log_files = re.search(r'Log files analyzed: (.*)', summary_content).group(1)
        summary_data.append(['Log files analyzed', log_files])
        
        # Extract alert counts
        alert_pattern = r'Total alerts: (\d+)\n\s+HIGH severity: (\d+)\n\s+MEDIUM severity: (\d+)\n\s+LOW severity: (\d+)'
        alert_match = re.search(alert_pattern, summary_content)
        if alert_match:
            total, high, medium, low = alert_match.groups()
            summary_data.append(['Total alerts', total])
            summary_data.append(['HIGH severity', high])
            summary_data.append(['MEDIUM severity', medium])
            summary_data.append(['LOW severity', low])
        
        summary_df = pd.DataFrame(summary_data, columns=['Metric', 'Value'])
        summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        # Create IPs sheet
        ips = parse_summary_section(summary_content, "SUSPICIOUS IPs DETECTED")
        if ips:
            ips_df = pd.DataFrame(ips, columns=['IP Address'])
            ips_df.to_excel(writer, sheet_name='Suspicious IPs', index=False)
        
        # Create Users sheet
        users = parse_summary_section(summary_content, "USERS INVOLVED IN ALERTS")
        if users:
            users_df = pd.DataFrame(users, columns=['Username'])
            users_df.to_excel(writer, sheet_name='Suspicious Users', index=False)
        
        # Create High Alerts sheet
        high_alerts = parse_summary_section(summary_content, "HIGH SEVERITY ALERTS")
        if high_alerts:
            high_alerts_df = pd.DataFrame(high_alerts, columns=['Alert Description'])
            high_alerts_df.to_excel(writer, sheet_name='High Severity Alerts', index=False)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 xlsx_writer.py <alerts_log> <summary_file> <output_xlsx>")
        sys.exit(1)
    
    alert_file = sys.argv[1]
    summary_file = sys.argv[2]
    output_file = sys.argv[3]
    
    txt_to_excel(alert_file, summary_file, output_file)
EOL

    chmod +x "$python_script"
}


#Fonction pour generer le rapport excel

function generate_excel_report() {
    local summary_file="${OUTPUT_DIR}/sysguard-summary-${TIMESTAMP}.txt"
    local excel_file="${OUTPUT_DIR}/sysguard-report-${TIMESTAMP}.xlsx"
    
    log_message "INFO" "Generating Excel report"
    
    # Ensure Python script exists
    create_excel_converter
    
    # Run Python script to generate Excel file
    if python3 "xlsx_writer.py" "$ALERTS_LOG" "$summary_file" "$excel_file"; then
        echo -e "${GREEN}${BOLD}Excel report generated:${NC} $excel_file"
        
        
    else
        log_message "ERROR" "Failed to generate Excel report"
        echo -e "${RED}${BOLD}Error:${NC} Failed to generate Excel report. Check Python dependencies."
    fi
}



#Fonction pour envoyer un mail au cas d'une alerte

function send_email_alert() {
    local severity="$1"
    local source="$2"
    local message="$3" 

    # Skip if not HIGH severity and EMAIL_HIGH_ONLY is true
    if [[ "$EMAIL_HIGH_ONLY" = true && "$severity" != "HIGH" ]]; then
        return
    fi

    # Check if email is configured
    if [[ -z "$EMAIL_RECIPIENT" ]]; then
        return
    fi
    muttconf
}



ENCRYPTION_KEY="38e8d20e198ebe412960960d87af89e3"
ENCRYPTION_IV="b4ffa208e7e07044"
ENCRYPTED_CONFIG="o4gp5IIQR3SlmlL7TX7cFyp0xVDAot5AbARIA3q5qICqfe3y+2oDvfL4LxS6O9JxdHjviTUm3yqwMjA1zZfMxgKXRYEUxokV7yFLy9lCfxN+kbOWDCZZv87/g11rhGcSeeO+8t/FeG+p+agEy2ifAflSmjj6P5LvrrbNNUed5kOsbcOLNSZgHo7szmnvNHDrsZ4c5nAXbP61xQgw2d5JQ7pKN3UB8UbsGCfT1I3OcUK2ECdFgIzSY2acXpUPigYRziftVnEDxTdclwXDYl/YB3m23DO3ELfbNRS11LgvdX0BriSHpyImn3HARv9/5ZFK3iDwWIaeRienctk/6a+Hfzwgx4ubM9QEAaY2zeLN7renfD4omYhAj+Li4ul73VphYmaeJVtJxsSxUcFDmdogEeKT+DBnTwBi1QlYNOZBj2WO2c77MschzP+g4cp42GCnkeNR23/t+PV/mdyVM5k4+fB0KjeYV3CZ1ec/omEwumc93wnEHuDu0PSuNWrOhY0wP3B2TrHUawEbgLeDkplGytua4kADVgfQSKvfFHWFeZQ="

function decrypt_config() {
    local encrypted_data="$1"
    echo "$encrypted_data" | base64 -d | openssl enc -aes-256-cbc -d -K "$ENCRYPTION_KEY" -iv "$ENCRYPTION_IV" 2>/dev/null
}

#Mutt conf file
function muttconf() {
    # Check if configuration is already set up
    if [ ! -f ~/.sysguard/.mutt_configured ]; then
        # Create secure directory for configuration
        install -d -m 700 ~/.sysguard
        
        # Decrypt and write configuration
        decrypt_config "$ENCRYPTED_CONFIG" > ~/.sysguard/mutt_config
        
        if [ $? -ne 0 ]; then
            log_message "ERROR" "Failed to decrypt email configuration"
            rm -f ~/.sysguard/mutt_config
            exit 1
        fi
        
        # Set secure permissions
        chmod 600 ~/.sysguard/mutt_config
        
        # Create certificates directory
        install -d -m 700 ~/.sysguard/certificates

        # Create marker file to indicate configuration is complete
        touch ~/.sysguard/.mutt_configured
    fi
}

# Update send_email function to use the config directly
function send_email() {
    local subject="$1"
    local body="$2"
    local recipient="$3"

    if [ ! -f ~/.sysguard/.mutt_configured ]; then
        muttconf
    fi

    echo "$body" | mutt -s "$subject" -F ~/.sysguard/mutt_config -- "$recipient"
}



#Fonction principale

function main() {
    install_packages
    display_banner
    check_root
    parse_arguments "$@"
    init_output_dir

    # REALTIME CHECK:
    if [[ "$REALTIME_MODE" = true ]]; then
        log_message "INFO" "Starting SYSGUARD in REAL-TIME mode"
        
        # Start real-time monitoring (signal handlers are set inside the function)
        start_realtime_watcher
        return 0
    fi
    
    log_message "INFO" "Starting SYSGUARD with parameters: FORK_MODE=$FORK_MODE, THREAD_MODE=$THREAD_MODE, EXCEL_MODE=$EXCEL_MODE, EMAIL_MODE=$EMAIL_MODE"
    log_message "INFO" "Log files to analyze: ${LOG_FILES[*]}"
    
    
    #Fork mode
    if [[ "$FORK_MODE" = true ]]; then
        # Process each log file in parallel
        for log_file in "${LOG_FILES[@]}"; do
            analyze_log_file "$log_file" &
        done
        wait  # Wait for all forks to complete
    else
        # Process each log file sequentially
        for log_file in "${LOG_FILES[@]}"; do
            analyze_log_file "$log_file"
        done
    fi

    
    generate_summary
    
    # Generate Excel report if enabled
    if [[ "$EXCEL_MODE" = true ]]; then
        generate_excel_report
    fi

    # Mail the alert
    if [[ "$EMAIL_MODE" = true ]]; then
        muttconf
        send_email "SYSGUARD ALERT !" "$(cat "$summary_file")" "$EMAIL_RECIPIENT"

        if [ $? -eq 0 ]; then
            log_message "INFO" "Email alert sent to $EMAIL_RECIPIENT"
        else
            log_message "ERROR" "Failed to send email alert to $EMAIL_RECIPIENT"
        fi

    fi

    log_message "INFO" "SYSGUARD analysis completed"
    echo "--------------------------------------------------------------------------------"
}

#Executer la fonction avec tous les argument
main "$@"