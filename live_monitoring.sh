
RED='\033[0;31m'
NC='\033[0m' # No Color


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
        echo "HIGH SEVERITY ALERT | Direct root login detected: $line" "$source_file" | mutt -s "SYSGUARD ALERT !" -F "$TMP_MUTTRC" -- "$EMAIL_RECIPIENT"
    fi
    
    # Check for unusual login hours (11PM - 5AM)
    if echo "$line" | grep -qE 'session opened' && echo "$line" | grep -qE '(2[3]|[0-4]):[0-9]{2}:[0-9]{2}'; then
        local username=$(echo "$line" | grep -oE 'for user [^ ]+' | awk '{print $3}')
        echo "MEDIUM SEVERITY ALERT | UNUSUAL_HOURS" "Login during unusual hours by user $username: $line" "$source_file" | mutt -s "SYSGUARD ALERT !" -F "$TMP_MUTTRC" -- "$EMAIL_RECIPIENT"
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
    muttconf
    ((current_count++))
    echo "$current_count" > "$ssh_track_file"
    if [[ $current_count -ge 5 ]]; then
        echo "HIGH SEVERITY ALERT | SSH_BRUTE_FORCE" "Brute force attack detected:  failed SSH attempts from IP $ip" "$source_file" | mutt -s "SYSGUARD ALERT !" -F "$TMP_MUTTRC" -- "$EMAIL_RECIPIENT"
        echo "0" > "$ssh_track_file"
    elif [[ $current_count -ge 3 ]]; then
        echo "MEDIUM SEVERITY ALERT | SSH_SUSPICIOUS | Multiple SSH failures from IP $ip " "$source_file" | mutt -s "SYSGUARD ALERT !" -F "$TMP_MUTTRC" -- "$EMAIL_RECIPIENT"
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
    if [[ $current_count -ge 3 ]]; then
		muttconf
        echo "HIGH" "SUDO_ABUSE" "Potential sudo abuse: failed attempts by user $username" "$source_file" | mutt -s "SYSGUARD ALERT !" -F "$TMP_MUTTRC" -- "$EMAIL_RECIPIENT"
        echo "0" > "$sudo_track_file"
    fi
    
    find "${OUTPUT_DIR}/realtime_watch" -name "sudo_failures_*.count" -mmin +60 -delete 2>/dev/null
}