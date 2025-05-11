
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