#Fonction pour afficher les infos du script

function display_banner() {
    echo -e "${BLUE}${BOLD}"
    echo "  ███████╗██╗   ██╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ "
    echo "  ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
    echo "  ███████╗ ╚████╔╝ ███████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
    echo "  ╚════██║  ╚██╔╝  ╚════██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
    echo "  ███████║   ██║   ███████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
    echo "  ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
    echo -e "${NC}"
    echo -e "${BOLD}SYSGUARD: Syslog & Suspicious Activity Analyzer${NC}"
    echo -e "${BOLD}Authors: y4hya - y0ussef - wiss4l ${NC}"
    echo -e "${BOLD}Version: 1.0${NC}"
    echo ""
}



#Les couleurs de text, niveau de risque

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'



#Configuration 
#Si aucun fichier log n'est spécifié, le script vérifie par défaut /var/log/auth.log et /var/log/syslog.
#si le path de sortie n'est pas spécifié, par défaut la sortie est stocké dans /var/log/sysguard

FORK_MODE=false
THREAD_MODE=false
LOG_FILES=()
OUTPUT_DIR="/var/log/sysguard"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
SESSION_LOG="${OUTPUT_DIR}/sysguard-${TIMESTAMP}.log"
ALERTS_LOG="${OUTPUT_DIR}/alerts-${TIMESTAMP}.log"




#Fonction pour afficher un tutorial du script

function display_help() {
    echo -e "${BOLD}Usage:${NC} $0 [options] [log_file1] [log_file2] ..."
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  -h, --help            Display this help message"
    echo "  -f, --fork            Fork to analyze multiple files in parallel"
    echo "  -t, --thread          Spawn a thread per detection rule"
    echo "  -o, --output DIR      Specify output directory (default: /var/log/sysguard)"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 /var/log/auth.log"
    echo "  $0 -f /var/log/auth.log /var/log/syslog"
    echo "  $0 -t -o /tmp/sysguard_output /var/log/auth.log"
    echo ""
    echo -e "${BOLD}Default log files if none specified:${NC}"
    echo "  /var/log/auth.log"
    echo "  /var/log/syslog"
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
}



#Fonction pour la Configuration des options (-h -t -f -o)

function parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                display_banner
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
    fi
}



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
    local summary_file="${OUTPUT_DIR}/sysguard-summary-${TIMESTAMP}.txt"
    
    echo "=== SYSGUARD ANALYSIS SUMMARY ===" > "$summary_file"
    echo "Generated on: $(date)" >> "$summary_file"
    echo "Log files analyzed: ${LOG_FILES[*]}" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Count alerts by severity
    local high_alerts=$(grep -c "\[ALERT:HIGH\]" "$ALERTS_LOG" || echo "0")
    local medium_alerts=$(grep -c "\[ALERT:MEDIUM\]" "$ALERTS_LOG" || echo "0")
    local low_alerts=$(grep -c "\[ALERT:LOW\]" "$ALERTS_LOG" || echo "0")
    local total_alerts=$((high_alerts+medium_alerts+low_alerts))
    
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



#Fonction principale

function main() {
    display_banner
    check_root
    parse_arguments "$@"
    init_output_dir
    
    log_message "INFO" "Starting SYSGUARD with parameters: FORK_MODE=$FORK_MODE, THREAD_MODE=$THREAD_MODE"
    log_message "INFO" "Log files to analyze: ${LOG_FILES[*]}"
    
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
    
    log_message "INFO" "SYSGUARD analysis completed"
    echo -e "${GREEN}${BOLD}SYSGUARD analysis completed.${NC}"
}

#Executer la fonction avec tous les argument
main "$@"