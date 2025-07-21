#!/bin/bash

# Advanced Email Spam Detection & Analysis Tool - Interactive Edition
# Version: 3.0 (Enhanced with Interactive Features)
# Description: Comprehensive spam analysis with interactive menu system

# Disable strict mode initially for better error handling
set -uo pipefail

# Configuration and Variables
DEFAULT_EXIM_LOG="/var/log/exim_mainlog"
DEFAULT_MAIL_LOG="/var/log/mail.log"
DEFAULT_POSTFIX_LOG="/var/log/postfix.log"
DEFAULT_DOVECOT_LOG="/var/log/dovecot.log"
SCRIPT_NAME=$(basename "$0")
SCRIPT_VERSION="3.0"

# Initialize all variables
EXIM_LOG="${DEFAULT_EXIM_LOG}"
MAIL_LOG="${DEFAULT_MAIL_LOG}"
POSTFIX_LOG="${DEFAULT_POSTFIX_LOG}"
DOVECOT_LOG="${DEFAULT_DOVECOT_LOG}"
TOP=20
HOURS=24
OUTPUT_FILE=""
QUIET=false
SUMMARY_ONLY=false
BLOCKED_ONLY=false
ADMIN_FULL=false
PERFORMANCE_ONLY=false
INTERACTIVE_MODE=true
REFRESH_INTERVAL=30
AUTO_REFRESH=false
UBE_UCE_ONLY=false

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'
BLINK='\033[5m'

# Spam indicators and patterns
declare -a SPAM_SUBJECTS=("viagra" "cialis" "loan" "lottery" "winner" "congratulations" "urgent" "free money" "investment" "nigeria" "prince" "inheritance")
declare -a SPAM_DOMAINS=("temp-mail" "10minutemail" "guerrillamail" "mailinator" "yopmail" "throwaway" "discard")
declare -a SUSPICIOUS_TLD=(".tk" ".ml" ".ga" ".cf" ".pw" ".top" ".click" ".download")

# ============================================
# UTILITY FUNCTIONS
# ============================================

print_header() {
    echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║${BOLD}           🛡️  SPAM DETECTION & ANALYSIS TOOL 🛡️           ${NC}${RED}║${NC}"
    echo -e "${RED}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║${NC} 📧 Email Server Security Analysis                        ${RED}║${NC}"
    echo -e "${RED}║${NC} 🔍 Spam Pattern Detection                               ${RED}║${NC}"
    echo -e "${RED}║${NC} 📊 Threat Intelligence Report                           ${RED}║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
    echo -e "${CYAN}Analysis Date: ${GREEN}$(date)${NC}"
    echo -e "${CYAN}Hostname: ${GREEN}$(hostname)${NC}\n"
}

print_usage() {
    cat << EOF
${BOLD}Usage:${NC} $SCRIPT_NAME [OPTIONS]

${BOLD}OPTIONS:${NC}
    -i, --interactive        Run in interactive mode (default)
    -n, --non-interactive    Run in non-interactive mode
    -e, --exim-log PATH      Exim log file path (default: $DEFAULT_EXIM_LOG)
    -m, --mail-log PATH      Mail log file path (default: $DEFAULT_MAIL_LOG)
    -p, --postfix-log PATH   Postfix log file path (default: $DEFAULT_POSTFIX_LOG)
    -d, --dovecot-log PATH   Dovecot log file path (default: $DEFAULT_DOVECOT_LOG)
    -t, --top NUMBER         Number of top entries to display (default: 20)
    -h, --hours NUMBER       Analyze last N hours (default: 24)
    -o, --output FILE        Save report to file
    -q, --quiet              Suppress interactive prompts
    -s, --summary            Show only summary report
    --blocked-only           Show only blocked/rejected emails
    --admin-full             Show full admin analysis (auth, scripts, delivery)
    --performance            Show server performance metrics
    --ube-uce                Show UBE/UCE detection analysis
    --help                   Show this help message

${BOLD}ANALYSIS MODES:${NC}
    Default: Full spam detection analysis
    --admin-full: Complete admin monitoring (recommended for daily use)
    --performance: Server performance and volume analysis
    --summary: Quick executive summary only
    --blocked-only: Security-focused blocked email analysis
    --ube-uce: Marketing campaigns and bulk email detection

${BOLD}EXAMPLES:${NC}
    $SCRIPT_NAME                         # Launch interactive mode
    $SCRIPT_NAME -n --summary            # Non-interactive summary
    $SCRIPT_NAME -n --admin-full -t 30   # Complete admin analysis
    $SCRIPT_NAME -n --ube-uce            # Check for marketing campaigns
    $SCRIPT_NAME --performance -h 12     # Performance metrics, last 12h
    $SCRIPT_NAME -t 50 -h 12            # Spam analysis, top 50, last 12h
    $SCRIPT_NAME --blocked-only -o spam_report.txt
    $SCRIPT_NAME -e /custom/exim.log --summary
EOF
}

validate_file() {
    if [[ -f "$1" && -r "$1" ]]; then
        return 0
    else
        return 1
    fi
}

validate_number() {
    if [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -gt 0 ]]; then
        return 0
    else
        return 1
    fi
}

safe_count() {
    local count="$1"
    if [[ -n "$count" ]] && [[ "$count" =~ ^[0-9]+$ ]]; then
        echo "$count"
    else
        echo "0"
    fi
}

clear_screen() {
    clear
    tput cup 0 0
}

press_any_key() {
    echo
    echo -e "${YELLOW}Press any key to continue...${NC}"
    read -n 1 -s -r
}

get_available_logs() {
    local available_logs=()
    
    if validate_file "$EXIM_LOG"; then
        available_logs+=("Exim: $EXIM_LOG")
    fi
    if validate_file "$MAIL_LOG"; then
        available_logs+=("Mail: $MAIL_LOG")
    fi
    if validate_file "$POSTFIX_LOG"; then
        available_logs+=("Postfix: $POSTFIX_LOG")
    fi
    if validate_file "$DOVECOT_LOG"; then
        available_logs+=("Dovecot: $DOVECOT_LOG")
    fi
    
    if [[ ${#available_logs[@]} -eq 0 ]]; then
        # Try to find alternative log files
        echo -e "${YELLOW}⚠️  Default log files not found. Searching for alternatives...${NC}"
        
        local alt_logs=("/var/log/exim4/mainlog" "/var/log/mail.log" "/var/log/maillog" "/var/log/messages" "/var/log/syslog")
        for log in "${alt_logs[@]}"; do
            if validate_file "$log"; then
                EXIM_LOG="$log"
                available_logs+=("Found: $log")
                echo -e "${GREEN}✓ Using alternative log: $log${NC}"
                break
            fi
        done
        
        if [[ ${#available_logs[@]} -eq 0 ]]; then
            echo -e "${RED}❌ No readable log files found!${NC}" >&2
            echo -e "${YELLOW}💡 Tips:${NC}" >&2
            echo -e "   - Run with sudo: ${GREEN}sudo $0${NC}" >&2
            echo -e "   - Specify log file: ${GREEN}$0 -e /path/to/logfile${NC}" >&2
            echo -e "   - Check permissions: ${GREEN}ls -la /var/log/exim* /var/log/mail*${NC}" >&2
            return 1
        fi
    fi
    
    echo -e "${GREEN}📂 Available Log Files:${NC}"
    printf '%s\n' "${available_logs[@]}" | sed 's/^/   /'
    echo
    return 0
}

# ============================================
# ANALYSIS FUNCTIONS
# ============================================

analyze_smtp_authenticated() {
    echo -e "${PURPLE}🔐 SMTP AUTHENTICATED SENDERS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}📧 Top $TOP SMTP Authenticated Users:${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        result=$(grep -E "A=(dovecot_plain|dovecot_login|cram_md5|plain|login)" "$EXIM_LOG" 2>/dev/null | \
        awk -F"A=" '{print $2}' | awk -F":" '{print $2}' | awk '{print $1}' | \
        grep -v "^$" | sort | uniq -c | sort -nr | head -n "$TOP" || true)
        
        if [[ -n "$result" ]]; then
            echo "$result" | awk '{printf "   📧 %s emails sent by: %s\n", $1, $2}'
        else
            echo "   ✅ No SMTP authenticated senders found"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    echo -e "${YELLOW}⚠️  High Volume Authenticated Users (>100 emails):${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        result=$(grep -E "A=(dovecot_plain|dovecot_login|cram_md5|plain|login)" "$EXIM_LOG" 2>/dev/null | \
        awk -F"A=" '{print $2}' | awk -F":" '{print $2}' | awk '{print $1}' | \
        sort | uniq -c | sort -nr || true)
        
        if [[ -n "$result" ]]; then
            local high_volume
            high_volume=$(echo "$result" | awk '$1 > 100 {printf "   🚨 %s emails from: %s\n", $1, $2}')
            if [[ -n "$high_volume" ]]; then
                echo "$high_volume"
            else
                echo "   ✅ No high-volume authenticated users detected"
            fi
        fi
    fi
    echo
}

analyze_script_senders() {
    echo -e "${PURPLE}🛠️ SCRIPT SENDERS ANALYSIS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}📂 Top $TOP PHP/Script Senders (by directory):${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        result=$(grep "cwd=" "$EXIM_LOG" 2>/dev/null | grep -v "/var/spool" | \
        awk -F"cwd=" '{print $2}' | awk '{print $1}' | \
        sort | uniq -c | sort -nr | head -n "$TOP" || true)
        
        if [[ -n "$result" ]]; then
            echo "$result" | while IFS= read -r line; do
                local count=$(echo "$line" | awk '{print $1}')
                local path=$(echo "$line" | sed 's/^[[:space:]]*[0-9]* //')
                
                # Color code based on volume
                if [[ "$count" -gt 100 ]]; then
                    echo -e "   ${RED}🚨 HIGH:${NC} ${RED}$count${NC} emails from: ${YELLOW}$path${NC}"
                elif [[ "$count" -gt 50 ]]; then
                    echo -e "   ${YELLOW}⚠️  MED:${NC} ${YELLOW}$count${NC} emails from: $path"
                else
                    echo -e "   📂 $count emails from: $path"
                fi
            done
        else
            echo "   ✅ No script senders detected"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    echo -e "${YELLOW}👤 'nobody' User Activity (Common for compromised scripts):${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        result=$(grep "U=nobody" "$EXIM_LOG" 2>/dev/null | \
        grep -o "cwd=[^ ]*" | sed 's/cwd=//' | \
        sort | uniq -c | sort -nr | head -n "$TOP" || true)
        
        if [[ -n "$result" ]]; then
            echo "$result" | awk '{printf "   👤 %s emails from nobody in: %s\n", $1, $2}'
            
            # Warning if high nobody usage
            local nobody_total=$(grep -c "U=nobody" "$EXIM_LOG" 2>/dev/null || echo "0")
            if [[ "$nobody_total" -gt 100 ]]; then
                echo -e "   ${RED}⚠️  WARNING: High 'nobody' user activity ($nobody_total emails) - possible compromised scripts!${NC}"
            fi
        else
            echo "   ✅ No 'nobody' user activity detected"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    echo -e "${YELLOW}🌐 Web Application Senders (Apache/Nginx/PHP):${NC}"
    if validate_file "$EXIM_LOG"; then
        # Check for common web users
        local web_users=("www-data" "apache" "nginx" "httpd" "php-fpm" "php")
        local found_web=false
        
        for user in "${web_users[@]}"; do
            # Fix: Ensure we get a single numeric value
            local count=$(grep -c "U=${user}" "$EXIM_LOG" 2>/dev/null | head -1 || echo "0")
            
            # Additional validation to ensure count is a valid number
            count=$(echo "$count" | tr -d ' \n' | grep -o '^[0-9]*$' || echo "0")
            if [[ -z "$count" ]]; then
                count="0"
            fi
            
            if [[ "$count" -gt 0 ]]; then
                if [[ "$found_web" == false ]]; then
                    echo -e "   ${CYAN}Web application email activity detected:${NC}"
                    found_web=true
                fi
                
                # Get directories for this user
                local dirs=$(grep "U=${user}" "$EXIM_LOG" 2>/dev/null | \
                grep -o "cwd=[^ ]*" | sed 's/cwd=//' | \
                sort | uniq -c | sort -nr | head -5 || true)
                
                echo -e "   🌐 User ${YELLOW}$user${NC}: $count total emails"
                if [[ -n "$dirs" ]]; then
                    echo "$dirs" | awk '{printf "      📁 %s emails from: %s\n", $1, $2}'
                fi
                echo
            fi
        done
        
        if [[ "$found_web" == false ]]; then
            echo "   ✅ No web application senders detected"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    echo -e "${YELLOW}📝 Script File Analysis (Specific PHP files):${NC}"
    if validate_file "$EXIM_LOG"; then
        # Look for specific PHP files in the logs
        local php_files=$(grep -E "\.php" "$EXIM_LOG" 2>/dev/null | \
        grep -oE "cwd=[^ ]*\.php" | sed 's/cwd=//' | \
        sort | uniq -c | sort -nr | head -n "$TOP" || true)
        
        if [[ -n "$php_files" ]]; then
            echo -e "   ${RED}🚨 Specific PHP files sending emails:${NC}"
            echo "$php_files" | awk '{printf "   📄 %s emails from: %s\n", $1, $2}'
            echo -e "   ${YELLOW}💡 Tip: Review these PHP files for potential malicious code${NC}"
        else
            # Try alternative pattern
            local script_patterns=$(grep -E "cwd=.*\.(php|pl|py|cgi|sh)" "$EXIM_LOG" 2>/dev/null | \
            awk -F"cwd=" '{print $2}' | awk '{print $1}' | \
            grep -E "\.(php|pl|py|cgi|sh)" | \
            sort | uniq -c | sort -nr | head -n "$TOP" || true)
            
            if [[ -n "$script_patterns" ]]; then
                echo -e "   ${YELLOW}Script files detected in email activity:${NC}"
                echo "$script_patterns" | awk '{printf "   📄 %s emails from: %s\n", $1, $2}'
            else
                echo "   ✅ No specific script files detected in email activity"
            fi
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
}

analyze_envelope_patterns() {
    echo -e "${PURPLE}📮 ENVELOPE & ROUTING ANALYSIS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}📤 Top $TOP Envelope From Addresses:${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        # Method 1: Look for envelope sender in angle brackets
        result=$(grep "=>" "$EXIM_LOG" 2>/dev/null | \
        awk '{
            # Find envelope sender (format: <sender@domain>)
            for(i=1; i<=NF; i++) {
                if($i ~ /@/ && $i ~ /^<.*>$/) {
                    gsub(/[<>]/, "", $i)
                    print $i
                    break
                }
            }
        }' | \
        grep -v "^$" | sort | uniq -c | sort -nr | head -n "$TOP" || true)
        
        # If first method fails, try alternative
        if [[ -z "$result" ]]; then
            result=$(grep "=>" "$EXIM_LOG" 2>/dev/null | \
            awk '{
                # Look for any email address pattern
                for(i=1; i<=NF; i++) {
                    if($i ~ /@/ && $i !~ /^[A-Z]+=/) {
                        gsub(/[<>]/, "", $i)
                        if($i ~ /^[^@]+@[^@]+\.[^@]+$/) {
                            print $i
                            break
                        }
                    }
                }
            }' | \
            grep -v "^$" | sort | uniq -c | sort -nr | head -n "$TOP" || true)
        fi
        
        if [[ -n "$result" ]]; then
            echo "$result" | awk '{printf "   📤 %s emails from: %s\n", $1, $2}'
        else
            echo "   ❌ No envelope from data found"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    echo -e "${YELLOW}🌐 Top $TOP Sending Domains:${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        # Extract domains from email addresses
        result=$(grep "=>" "$EXIM_LOG" 2>/dev/null | \
        awk '{
            for(i=1; i<=NF; i++) {
                if($i ~ /@/) {
                    gsub(/[<>]/, "", $i)
                    split($i, parts, "@")
                    if(length(parts) >= 2) {
                        print parts[2]
                        break
                    }
                }
            }
        }' | \
        grep -v "^$" | sort | uniq -c | sort -nr | head -n "$TOP" || true)
        
        if [[ -n "$result" ]]; then
            echo "$result" | awk '{printf "   🌐 %s emails from domain: %s\n", $1, $2}'
        else
            echo "   ❌ No sending domain data found"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    echo -e "${YELLOW}📨 Top $TOP Destination Domains:${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        # Extract destination domains after =>
        result=$(grep "=>" "$EXIM_LOG" 2>/dev/null | \
        awk '{
            found_arrow = 0
            for(i=1; i<=NF; i++) {
                if($i == "=>") {
                    found_arrow = 1
                    continue
                }
                if(found_arrow && $i ~ /@/ && $i !~ /^[A-Z]+=/) {
                    gsub(/[<>]/, "", $i)
                    split($i, parts, "@")
                    if(length(parts) >= 2) {
                        print parts[2]
                        found_arrow = 0
                        break
                    }
                }
            }
        }' | \
        grep -v "^$" | sort | uniq -c | sort -nr | head -n "$TOP" || true)
        
        if [[ -n "$result" ]]; then
            echo "$result" | awk '{printf "   📨 %s emails to domain: %s\n", $1, $2}'
        else
            echo "   ❌ No destination domain data found"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
}

analyze_delivery_status() {
    echo -e "${PURPLE}📊 DELIVERY STATUS ANALYSIS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}✅ Recent Successful Deliveries:${NC}"
    if validate_file "$EXIM_LOG"; then
        local today
        today=$(date '+%Y-%m-%d')
        local delivered_count
        delivered_count=$(safe_count "$(grep "$today" "$EXIM_LOG" 2>/dev/null | grep "=>" | wc -l)")
        
        echo -e "   📧 Successfully delivered today: ${GREEN}$delivered_count${NC}"
        
        # Recent delivery samples
        local recent_deliveries
        recent_deliveries=$(grep "$today" "$EXIM_LOG" 2>/dev/null | grep "=>" | tail -5 || true)
        if [[ -n "$recent_deliveries" ]]; then
            echo -e "   📋 Recent delivery samples:"
            echo "$recent_deliveries" | awk '{printf "      %s %s → %s\n", $1, $6, $7}'
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    echo -e "${YELLOW}❌ Failed Deliveries & Bounces:${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        result=$(grep "^.* == " "$EXIM_LOG" 2>/dev/null | \
        awk '{print $6}' | sort | uniq -c | sort -nr | head -n "$TOP" || true)
        
        if [[ -n "$result" ]]; then
            echo "$result" | awk '{printf "   ❌ %s bounces for: %s\n", $1, $2}'
        else
            echo "   ✅ No failed deliveries found"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    echo -e "${YELLOW}⏳ Deferred Messages:${NC}"
    if validate_file "$EXIM_LOG"; then
        local deferred_count
        deferred_count=$(safe_count "$(grep "deferred" "$EXIM_LOG" 2>/dev/null | wc -l)")
        
        if [[ "$deferred_count" -gt 0 ]]; then
            echo -e "   ⏳ Deferred messages: ${YELLOW}$deferred_count${NC}"
            
            # Show top deferred reasons
            local deferred_reasons
            deferred_reasons=$(grep "deferred" "$EXIM_LOG" 2>/dev/null | \
            awk -F"deferred" '{print $2}' | sort | uniq -c | sort -nr | head -5 || true)
            
            if [[ -n "$deferred_reasons" ]]; then
                echo -e "   📋 Top deferral reasons:"
                echo "$deferred_reasons" | awk '{printf "      %s: %s\n", $1, substr($0, index($0,$2))}'
            fi
        else
            echo "   ✅ No deferred messages found"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
}

analyze_spam_patterns() {
    echo -e "${PURPLE}🔍 SPAM PATTERN ANALYSIS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}📊 High Volume Senders (Potential Spam):${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        result=$(grep "=>" "$EXIM_LOG" 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++) if($i ~ /@/) {print $i; break}}' | \
        grep -v "^$" | sort | uniq -c | sort -nr | head -n "$TOP" || true)
        
        if [[ -n "$result" ]]; then
            echo "$result" | awk '$1 > 50 {printf "   🚨 %s emails from: %s\n", $1, $2}'
            local high_volume_count=$(echo "$result" | awk '$1 > 50' | wc -l)
            if [[ "$high_volume_count" -eq 0 ]]; then
                echo "   ✅ No high-volume senders detected (threshold: 50+ emails)"
            fi
        else
            echo "   ❌ No email data found in logs"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    # Suspicious domains
    echo -e "${YELLOW}🌐 Suspicious Domains Analysis:${NC}"
    if validate_file "$EXIM_LOG"; then
        local temp_domains="/tmp/domains_$$"
        
        # Extract domains safely
        if grep "=>" "$EXIM_LOG" 2>/dev/null | \
           awk '{for(i=1;i<=NF;i++) if($i ~ /@/) {gsub(/[<>]/, "", $i); print $i}}' | \
           awk -F@ '{if(NF>=2) print $2}' | \
           sort | uniq -c | sort -nr > "$temp_domains" 2>/dev/null; then
            
            local found_suspicious=false
            
            # Check against known spam TLDs
            for tld in "${SUSPICIOUS_TLD[@]}"; do
                if grep -q "$tld" "$temp_domains" 2>/dev/null; then
                    if [[ "$found_suspicious" == false ]]; then
                        echo -e "   ⚠️  Suspicious TLD patterns detected:"
                        found_suspicious=true
                    fi
                    grep "$tld" "$temp_domains" | head -3 | awk -v tld="$tld" '{printf "      🚫 %s emails from domain ending in %s: %s\n", $1, tld, $2}'
                fi
            done
            
            # Check against spam domain patterns
            for pattern in "${SPAM_DOMAINS[@]}"; do
                if grep -qi "$pattern" "$temp_domains" 2>/dev/null; then
                    if [[ "$found_suspicious" == false ]]; then
                        echo -e "   🚫 Temporary/Disposable email domains detected:"
                        found_suspicious=true
                    fi
                    grep -i "$pattern" "$temp_domains" | head -3 | awk '{printf "      📧 %s emails from: %s\n", $1, $2}'
                fi
            done
            
            if [[ "$found_suspicious" == false ]]; then
                echo "   ✅ No suspicious domain patterns detected"
            fi
        else
            echo "   ❌ Unable to extract domain information"
        fi
        
        rm -f "$temp_domains" 2>/dev/null || true
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    # Rapid-fire sending patterns
    echo -e "${YELLOW}⚡ Rapid-Fire Sending Patterns (Current Hour):${NC}"
    if validate_file "$EXIM_LOG"; then
        local current_hour
        current_hour=$(date '+%Y-%m-%d %H')
        local result
        result=$(grep "$current_hour" "$EXIM_LOG" 2>/dev/null | \
        grep "=>" | \
        awk '{for(i=1;i<=NF;i++) if($i ~ /@/) {print $i; break}}' | \
        sort | uniq -c | sort -nr | head -10 || true)
        
        if [[ -n "$result" ]]; then
            local rapid_fire
            rapid_fire=$(echo "$result" | awk '$1 > 10 {printf "   ⚡ %s emails in current hour from: %s\n", $1, $2}')
            if [[ -n "$rapid_fire" ]]; then
                echo "$rapid_fire"
            else
                echo "   ✅ No rapid-fire patterns detected (threshold: 10+ emails/hour)"
            fi
        else
            echo "   ℹ️  No recent email activity in current hour"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
}

analyze_rejected_spam() {
    echo -e "${PURPLE}🛡️ REJECTED SPAM ANALYSIS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}🚫 Rejected Emails:${NC}"
    if validate_file "$EXIM_LOG"; then
        local rejected_count
        rejected_count=$(grep -ic "rejected" "$EXIM_LOG" 2>/dev/null || echo "0")
        echo -e "   📊 Total rejected: ${RED}$rejected_count${NC}"
        
        # Show sample rejections
        echo -e "\n   📋 Recent rejections:"
        grep -i "rejected" "$EXIM_LOG" 2>/dev/null | tail -5 | \
        while IFS= read -r line; do
            echo -e "      ${CYAN}→${NC} ${line:0:80}..."
        done
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    # Rejected by RBL
    echo -e "${YELLOW}🚫 RBL (Real-time Blacklist) Rejections:${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        result=$(grep -i "rejected.*rbl\|rejected.*blacklist\|rejected.*dnsbl" "$EXIM_LOG" 2>/dev/null | \
        head -n "$TOP" | \
        awk '{for(i=1;i<=NF;i++) if($i ~ /H=/) print $i}' | \
        sort | uniq -c | sort -nr || true)
        
        if [[ -n "$result" ]]; then
            echo "$result" | awk '{printf "   🚫 %s attempts blocked from: %s\n", $1, $2}'
        else
            echo "   ✅ No RBL rejections found"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    # Rejected due to spam score
    echo -e "${YELLOW}📊 High Spam Score Rejections:${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        result=$(grep -i "rejected.*spam\|rejected.*score" "$EXIM_LOG" 2>/dev/null | \
        head -n "$TOP" | \
        awk '{for(i=1;i<=NF;i++) if($i ~ /@/) print $i}' | \
        sort | uniq -c | sort -nr || true)
        
        if [[ -n "$result" ]]; then
            echo "$result" | awk '{printf "   📊 %s rejections for: %s\n", $1, $2}'
        else
            echo "   ✅ No spam score rejections found"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    # Authentication failures (potential spam/brute force)
    echo -e "${YELLOW}🔐 Authentication Failures:${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        result=$(grep -i "authentication.*failed\|login.*failed\|auth.*failed" "$EXIM_LOG" 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++) if($i ~ /\[.*\]/) print $i}' | \
        tr -d '[]' | \
        sort | uniq -c | sort -nr | head -n "$TOP" || true)
        
        if [[ -n "$result" ]]; then
            echo "$result" | awk '{printf "   🔐 %s failed attempts from IP: %s\n", $1, $2}'
        else
            echo "   ✅ No authentication failures detected"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
}

analyze_content_patterns() {
    echo -e "${PURPLE}📝 CONTENT PATTERN ANALYSIS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    # Spam subject patterns
    echo -e "${YELLOW}📧 Spam Subject Patterns:${NC}"
    if validate_file "$EXIM_LOG"; then
        local found_patterns=false
        for subject in "${SPAM_SUBJECTS[@]}"; do
            local count
            count=$(safe_count "$(grep -i "subject.*$subject" "$EXIM_LOG" 2>/dev/null | wc -l)")
            if [[ "$count" -gt 0 ]]; then
                echo -e "   📧 ${RED}$count${NC} emails with subject containing: ${YELLOW}$subject${NC}"
                found_patterns=true
            fi
        done
        
        if [[ "$found_patterns" == false ]]; then
            echo "   ✅ No common spam subject patterns detected"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    # Large attachment patterns (potential malware)
    echo -e "${YELLOW}📎 Large Attachment Analysis:${NC}"
    if validate_file "$EXIM_LOG"; then
        local result
        result=$(grep -i "size.*[0-9][0-9][0-9][0-9][0-9]" "$EXIM_LOG" 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++) if($i ~ /size=/) print $i, $6}' | \
        sort -k1 -nr | head -n 10 || true)
        
        if [[ -n "$result" ]]; then
            echo "$result" | awk '{printf "   📎 Large email (%s) from: %s\n", $1, $2}'
        else
            echo "   ✅ No unusually large emails detected"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
}

analyze_subject_patterns() {
    echo -e "${PURPLE}📧 SUBJECT/TITLE ANALYSIS - UBE/UCE DETECTION${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}🎯 Top $TOP Email Subjects (Marketing Campaigns & Bulk Senders):${NC}"
    if validate_file "$EXIM_LOG"; then
        local temp_subjects="/tmp/subjects_$$"
        
        # Extract subjects from log - multiple methods for different log formats
        # Method 1: Look for T= pattern (common in Exim logs)
        grep "T=" "$EXIM_LOG" 2>/dev/null | \
        sed -n 's/.*T="\([^"]*\)".*/\1/p' > "$temp_subjects" 2>/dev/null
        
        # Method 2: Look for T= without quotes
        if [[ ! -s "$temp_subjects" ]]; then
            grep "T=" "$EXIM_LOG" 2>/dev/null | \
            sed -n 's/.*T=\([^ ]*\).*/\1/p' >> "$temp_subjects" 2>/dev/null
        fi
        
        # Method 3: Look for subject= pattern
        if [[ ! -s "$temp_subjects" ]]; then
            grep -i "subject=" "$EXIM_LOG" 2>/dev/null | \
            sed -n 's/.*subject="\([^"]*\)".*/\1/p' >> "$temp_subjects" 2>/dev/null
        fi
        
        # Method 4: Look for Subject: header
        if [[ ! -s "$temp_subjects" ]]; then
            grep -i "Subject:" "$EXIM_LOG" 2>/dev/null | \
            sed -n 's/.*Subject: *\(.*\)/\1/p' >> "$temp_subjects" 2>/dev/null
        fi
        
        if [[ -s "$temp_subjects" ]]; then
            # Count and sort subjects
            local result
            result=$(cat "$temp_subjects" | \
            sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
            grep -v "^$" | \
            sort | uniq -c | sort -nr | head -n "$TOP")
            
            if [[ -n "$result" ]]; then
                echo "$result" | while IFS= read -r line; do
                    local count=$(echo "$line" | awk '{print $1}')
                    local subject=$(echo "$line" | sed 's/^[[:space:]]*[0-9]* //')
                    
                    # Color code based on volume
                    if [[ "$count" -gt 100 ]]; then
                        echo -e "   ${RED}🚨 BULK:${NC} ${RED}$count${NC} emails - \"${YELLOW}$subject${NC}\""
                    elif [[ "$count" -gt 50 ]]; then
                        echo -e "   ${YELLOW}⚠️  HIGH:${NC} ${YELLOW}$count${NC} emails - \"$subject\""
                    elif [[ "$count" -gt 20 ]]; then
                        echo -e "   ${CYAN}📊 MED:${NC} ${CYAN}$count${NC} emails - \"$subject\""
                    else
                        echo -e "   📧 ${GREEN}$count${NC} emails - \"$subject\""
                    fi
                done
                
                # Analysis summary
                echo
                echo -e "${YELLOW}📊 Bulk Email Analysis Summary:${NC}"
                local total_unique=$(cat "$temp_subjects" | grep -v "^$" | sort -u | wc -l)
                local bulk_campaigns=$(echo "$result" | awk '$1 > 50' | wc -l)
                local marketing_campaigns=$(echo "$result" | awk '$1 > 20' | wc -l)
                
                echo -e "   📧 Total unique subjects: ${GREEN}$total_unique${NC}"
                echo -e "   🚨 Bulk campaigns (>50 emails): ${RED}$bulk_campaigns${NC}"
                echo -e "   📢 Marketing campaigns (>20 emails): ${YELLOW}$marketing_campaigns${NC}"
            else
                echo "   ❌ No subject data could be extracted"
            fi
        else
            echo "   ❌ No subject information found in logs"
            echo "   💡 Tip: Your log format might not include subject lines"
            echo "   💡 Try checking mail headers or using a different log"
        fi
        
        rm -f "$temp_subjects" 2>/dev/null || true
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
    
    # UBE/UCE Detection based on subject patterns
    echo -e "${YELLOW}🚫 UBE/UCE Pattern Detection (Unsolicited Bulk/Commercial Email):${NC}"
    if validate_file "$EXIM_LOG"; then
        local ube_patterns=("SALE" "% OFF" "FREE" "DISCOUNT" "OFFER" "DEAL" "BUY NOW" "LIMITED TIME" "ACT NOW" "CLICK HERE" "UNSUBSCRIBE" "PROMOTION" "WINNER" "CONGRATULATIONS" "URGENT" "IMPORTANT" "NOTICE" "INVOICE" "REFUND" "CREDIT")
        local found_ube=false
        
        for pattern in "${ube_patterns[@]}"; do
            local count
            # Case insensitive search for UBE patterns - ensure we get a single number
            count=$(grep -E "T=|subject=|Subject:" "$EXIM_LOG" 2>/dev/null | grep -ic "$pattern" 2>/dev/null | head -1 || echo "0")
            
            # Ensure count is a valid number
            count=$(echo "$count" | tr -d ' \n' | grep -o '^[0-9]*$' || echo "0")
            if [[ -z "$count" ]]; then
                count="0"
            fi
            
            if [[ "$count" -gt 10 ]]; then
                if [[ "$found_ube" == false ]]; then
                    echo -e "   ${RED}⚠️  Detected UBE/UCE patterns:${NC}"
                    found_ube=true
                fi
                echo -e "      🚫 ${RED}$count${NC} emails containing: \"${YELLOW}$pattern${NC}\""
            fi
        done
        
        if [[ "$found_ube" == false ]]; then
            echo "   ✅ No significant UBE/UCE patterns detected"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
}

analyze_geographic_patterns() {
    echo -e "${PURPLE}🌍 GEOGRAPHIC THREAT ANALYSIS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    # Extract and analyze source IPs
    echo -e "${YELLOW}🌐 Top Source IPs Analysis:${NC}"
    if validate_file "$EXIM_LOG"; then
        local result=""
        
        # Method 1: Look for H= pattern (most common)
        result=$(grep "H=" "$EXIM_LOG" 2>/dev/null | \
        awk '{
            for(i=1; i<=NF; i++) {
                if($i ~ /^H=/) {
                    # Extract IP from H=hostname[IP] or H=IP
                    if(match($i, /\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]/, arr)) {
                        print arr[1]
                    } else if(match($i, /H=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/, arr)) {
                        print arr[1]
                    }
                }
            }
        }' | sort | uniq -c | sort -nr | head -n 20 || true)
        
        # Method 2: Look for any IP pattern in square brackets
        if [[ -z "$result" ]]; then
            result=$(grep -oE '\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\]' "$EXIM_LOG" 2>/dev/null | \
            tr -d '[]' | sort | uniq -c | sort -nr | head -n 20 || true)
        fi
        
        if [[ -n "$result" ]]; then
            echo "   🌐 Top sender IPs:"
            echo "$result" | awk '{printf "   📍 %s connections from: %s\n", $1, $2}'
        else
            echo "   ❌ No source IPs found in logs"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
}

analyze_time_patterns() {
    echo -e "${PURPLE}⏰ TEMPORAL SPAM ANALYSIS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    # Hourly spam distribution
    echo -e "${YELLOW}📊 Hourly Email Distribution (Last 24h):${NC}"
    if validate_file "$EXIM_LOG"; then
        local today
        today=$(date '+%Y-%m-%d')
        local max_count=0
        local has_data=false
        
        # Find max count for scaling
        for hour in {00..23}; do
            local count
            count=$(safe_count "$(grep "$today $hour:" "$EXIM_LOG" 2>/dev/null | grep "=>" | wc -l)")
            if [[ "$count" -gt "$max_count" ]]; then
                max_count="$count"
            fi
            if [[ "$count" -gt 0 ]]; then
                has_data=true
            fi
        done
        
        # Display with simple bar chart
        if [[ "$has_data" == true ]]; then
            for hour in {00..23}; do
                local count
                count=$(safe_count "$(grep "$today $hour:" "$EXIM_LOG" 2>/dev/null | grep "=>" | wc -l)")
                if [[ "$count" -gt 0 ]]; then
                    local bar_length=0
                    if [[ "$max_count" -gt 0 ]]; then
                        bar_length=$(( (count * 20) / max_count ))
                    fi
                    local bar=""
                    if [[ "$bar_length" -gt 0 ]]; then
                        bar=$(printf "%*s" "$bar_length" | tr ' ' '█')
                    fi
                    printf "   %s:00 │%-20s %s emails\n" "$hour" "$bar" "$count"
                fi
            done
        else
            echo "   ℹ️  No email activity detected in the last 24 hours"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
}

analyze_mail_queue() {
    echo -e "${PURPLE}📮 MAIL QUEUE ANALYSIS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    # Check queue size
    echo -e "${YELLOW}📊 Current Mail Queue Status:${NC}"
    if command -v exim4 >/dev/null 2>&1; then
        local queue_count
        queue_count=$(exim4 -bpc 2>/dev/null || echo "0")
        queue_count=$(safe_count "$queue_count")
        echo -e "   📧 Messages in queue: ${GREEN}$queue_count${NC}"
        
        if [[ "$queue_count" -gt 100 ]]; then
            echo -e "   ⚠️  ${YELLOW}High queue count detected - possible spam backlog${NC}"
        fi
    elif command -v exim >/dev/null 2>&1; then
        local queue_count
        queue_count=$(exim -bpc 2>/dev/null || echo "0")
        queue_count=$(safe_count "$queue_count")
        echo -e "   📧 Messages in queue: ${GREEN}$queue_count${NC}"
        
        if [[ "$queue_count" -gt 100 ]]; then
            echo -e "   ⚠️  ${YELLOW}High queue count detected - possible spam backlog${NC}"
        fi
    else
        echo -e "   ❌ Exim command not available"
    fi
    echo
    
    # Frozen messages (often spam)
    echo -e "${YELLOW}🧊 Frozen Messages Analysis:${NC}"
    if command -v exim4 >/dev/null 2>&1; then
        local frozen_count
        frozen_count=$(safe_count "$(exim4 -bp 2>/dev/null | grep -c "frozen")")
        echo -e "   🧊 Frozen messages: ${RED}$frozen_count${NC}"
        
        if [[ "$frozen_count" -gt 0 ]]; then
            echo -e "   💡 Tip: Review frozen messages with 'exim4 -bp | grep frozen'"
        fi
    elif command -v exim >/dev/null 2>&1; then
        local frozen_count
        frozen_count=$(safe_count "$(exim -bp 2>/dev/null | grep -c "frozen")")
        echo -e "   🧊 Frozen messages: ${RED}$frozen_count${NC}"
        
        if [[ "$frozen_count" -gt 0 ]]; then
            echo -e "   💡 Tip: Review frozen messages with 'exim -bp | grep frozen'"
        fi
    fi
    echo
}

analyze_server_performance() {
    echo -e "${PURPLE}⚡ SERVER PERFORMANCE METRICS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}📊 Email Volume Statistics:${NC}"
    if validate_file "$EXIM_LOG"; then
        local today
        today=$(date '+%Y-%m-%d')
        
        # Hourly breakdown for today
        echo -e "   📅 Today's hourly email volume:"
        local has_activity=false
        for hour in {00..23}; do
            local count
            count=$(safe_count "$(grep "$today $hour:" "$EXIM_LOG" 2>/dev/null | grep "=>" | wc -l)")
            if [[ "$count" -gt 0 ]]; then
                printf "      %s:00 - %s emails\n" "$hour" "$count"
                has_activity=true
            fi
        done
        
        if [[ "$has_activity" == false ]]; then
            echo "      ℹ️  No email activity detected today"
        fi
        
        # Queue processing time analysis
        echo -e "\n   ⏱️ Processing Time Analysis:"
        local queue_times
        queue_times=$(grep "QT=" "$EXIM_LOG" 2>/dev/null | \
        awk -F"QT=" '{print $2}' | awk '{print $1}' | head -100 || true)
        
        if [[ -n "$queue_times" ]]; then
            echo -e "      ⚡ Recent queue processing times (sample):"
            echo "$queue_times" | head -10 | awk '{printf "         %s\n", $1}'
        else
            echo -e "      ℹ️  No queue processing time data available"
        fi
    else
        echo "   ❌ Log file not accessible"
    fi
    echo
}

generate_summary_report() {
    echo -e "${BLUE}📊 EXECUTIVE SUMMARY${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    if validate_file "$EXIM_LOG"; then
        local total_sent
        total_sent=$(safe_count "$(grep "=>" "$EXIM_LOG" 2>/dev/null | wc -l)")
        echo -e "   📤 Total emails processed: ${GREEN}$total_sent${NC}"
        
        local total_rejected
        total_rejected=$(safe_count "$(grep -i "rejected" "$EXIM_LOG" 2>/dev/null | wc -l)")
        echo -e "   🚫 Total rejections: ${RED}$total_rejected${NC}"
        
        local auth_failures
        auth_failures=$(safe_count "$(grep -i "auth.*failed" "$EXIM_LOG" 2>/dev/null | wc -l)")
        echo -e "   🔐 Authentication failures: ${RED}$auth_failures${NC}"
        
        if [[ "$total_sent" -gt 0 ]]; then
            local rejection_rate
            rejection_rate=$(( (total_rejected * 100) / (total_sent + 1) ))
            echo -e "   📊 Rejection rate: ${YELLOW}${rejection_rate}%${NC}"
        fi
        
        # Threat level assessment
        local threat_level="LOW"
        local threat_color="$GREEN"
        
        if [[ "$total_rejected" -gt 1000 || "$auth_failures" -gt 500 ]]; then
            threat_level="HIGH"
            threat_color="$RED"
        elif [[ "$total_rejected" -gt 100 || "$auth_failures" -gt 50 ]]; then
            threat_level="MEDIUM"
            threat_color="$YELLOW"
        fi
        
        echo -e "   🚨 Current threat level: ${threat_color}${BOLD}$threat_level${NC}"
    else
        echo -e "   ❌ Unable to generate summary - log file not accessible"
    fi
    echo
}

generate_security_recommendations() {
    echo -e "${PURPLE}🛡️ SECURITY RECOMMENDATIONS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}📋 Recommended Actions:${NC}"
    echo -e "   1. 🔒 Enable SPF, DKIM, and DMARC for all domains"
    echo -e "   2. 🛡️  Configure real-time blacklists (RBLs)"
    echo -e "   3. 📊 Set up SpamAssassin with custom rules"
    echo -e "   4. 🚫 Implement rate limiting for outbound emails"
    echo -e "   5. 🔍 Monitor authentication failures regularly"
    echo -e "   6. 📝 Review and update spam detection rules"
    echo -e "   7. 🧊 Regularly clean frozen messages from queue"
    echo -e "   8. 📈 Set up automated spam reporting"
    echo
    
    echo -e "${YELLOW}⚠️  Alert Thresholds:${NC}"
    echo -e "   • ${RED}Critical:${NC} >1000 emails from single source/hour"
    echo -e "   • ${YELLOW}Warning:${NC} >100 authentication failures/hour"
    echo -e "   • ${YELLOW}Warning:${NC} >500 messages in mail queue"
    echo -e "   • ${RED}Critical:${NC} >50 frozen messages"
    echo
}

# ============================================
# INTERACTIVE MENU FUNCTIONS
# ============================================

interactive_menu() {
    local choice
    while true; do
        clear_screen
        echo -e "${BOLD}${CYAN}════════════════════════════════════════${NC}"
        echo -e "${BOLD}${CYAN}       SPAM DETECTION MENU${NC}"
        echo -e "${BOLD}${CYAN}════════════════════════════════════════${NC}\n"
        
        echo -e "${GREEN}[1]${NC} 📊 Quick Summary Report"
        echo -e "${GREEN}[2]${NC} 🔍 Spam Pattern Analysis"
        echo -e "${GREEN}[3]${NC} 🛡️  Rejected/Blocked Emails"
        echo -e "${GREEN}[4]${NC} 🔐 Authentication Analysis"
        echo -e "${GREEN}[5]${NC} 🛠️  Script Senders Analysis"
        echo -e "${GREEN}[6]${NC} 📮 Envelope & Routing Analysis"
        echo -e "${GREEN}[7]${NC} 📊 Delivery Status Analysis"
        echo -e "${GREEN}[8]${NC} 📧 UBE/UCE Detection (Marketing)"
        echo -e "${GREEN}[9]${NC} 📝 Content Pattern Analysis"
        echo -e "${GREEN}[10]${NC} 🌍 Geographic Threat Analysis"
        echo -e "${GREEN}[11]${NC} ⏰ Time Pattern Analysis"
        echo -e "${GREEN}[12]${NC} 📮 Mail Queue Analysis"
        echo -e "${GREEN}[13]${NC} ⚡ Performance Metrics"
        echo -e "${GREEN}[14]${NC} 📋 Complete Admin Report"
        echo -e "${GREEN}[15]${NC} 🎯 Custom Analysis Builder"
        echo -e "${GREEN}[0]${NC} 🚪 Exit"
        
        echo
        echo -e "${YELLOW}Enter your choice [0-15]:${NC} "
        read -r choice
        
        case $choice in
            1) 
                clear_screen
                print_header
                generate_summary_report
                generate_security_recommendations
                press_any_key
                ;;
            2) 
                clear_screen
                print_header
                analyze_spam_patterns
                press_any_key
                ;;
            3) 
                clear_screen
                print_header
                analyze_rejected_spam
                press_any_key
                ;;
            4) 
                clear_screen
                print_header
                analyze_smtp_authenticated
                press_any_key
                ;;
            5) 
                clear_screen
                print_header
                analyze_script_senders
                press_any_key
                ;;
            6) 
                clear_screen
                print_header
                analyze_envelope_patterns
                press_any_key
                ;;
            7) 
                clear_screen
                print_header
                analyze_delivery_status
                press_any_key
                ;;
            8) 
                clear_screen
                print_header
                analyze_subject_patterns
                press_any_key
                ;;
            9) 
                clear_screen
                print_header
                analyze_content_patterns
                press_any_key
                ;;
            10) 
                clear_screen
                print_header
                analyze_geographic_patterns
                press_any_key
                ;;
            11) 
                clear_screen
                print_header
                analyze_time_patterns
                press_any_key
                ;;
            12) 
                clear_screen
                print_header
                analyze_mail_queue
                press_any_key
                ;;
            13) 
                clear_screen
                print_header
                analyze_server_performance
                press_any_key
                ;;
            14) 
                clear_screen
                print_header
                # Complete admin analysis
                analyze_smtp_authenticated
                analyze_script_senders
                analyze_envelope_patterns
                analyze_delivery_status
                analyze_spam_patterns
                analyze_rejected_spam
                analyze_subject_patterns
                analyze_content_patterns
                analyze_geographic_patterns
                analyze_time_patterns
                analyze_mail_queue
                analyze_server_performance
                generate_summary_report
                generate_security_recommendations
                press_any_key
                ;;
            15)
                custom_analysis_builder
                ;;
            0) 
                echo -e "${GREEN}Thank you for using Spam Detection Tool!${NC}"
                exit 0
                ;;
            *) 
                echo -e "${RED}Invalid option! Please try again.${NC}"
                sleep 1
                ;;
        esac
    done
}

custom_analysis_builder() {
    clear_screen
    echo -e "${BOLD}${CYAN}════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}    CUSTOM ANALYSIS BUILDER${NC}"
    echo -e "${BOLD}${CYAN}════════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}Select analyses to include (space-separated numbers):${NC}"
    echo
    echo -e "${GREEN}[1]${NC} SMTP Authentication"
    echo -e "${GREEN}[2]${NC} Script Senders"
    echo -e "${GREEN}[3]${NC} Envelope Patterns"
    echo -e "${GREEN}[4]${NC} Delivery Status"
    echo -e "${GREEN}[5]${NC} Spam Patterns"
    echo -e "${GREEN}[6]${NC} Rejected Spam"
    echo -e "${GREEN}[7]${NC} Subject/UBE Analysis"
    echo -e "${GREEN}[8]${NC} Content Patterns"
    echo -e "${GREEN}[9]${NC} Geographic Analysis"
    echo -e "${GREEN}[10]${NC} Time Patterns"
    echo -e "${GREEN}[11]${NC} Mail Queue"
    echo -e "${GREEN}[12]${NC} Performance"
    echo
    echo -e "${YELLOW}Enter selections (e.g., 1 3 5 7):${NC} "
    read -r selections
    
    clear_screen
    print_header
    
    for selection in $selections; do
        case $selection in
            1) analyze_smtp_authenticated ;;
            2) analyze_script_senders ;;
            3) analyze_envelope_patterns ;;
            4) analyze_delivery_status ;;
            5) analyze_spam_patterns ;;
            6) analyze_rejected_spam ;;
            7) analyze_subject_patterns ;;
            8) analyze_content_patterns ;;
            9) analyze_geographic_patterns ;;
            10) analyze_time_patterns ;;
            11) analyze_mail_queue ;;
            12) analyze_server_performance ;;
        esac
    done
    
    generate_summary_report
    press_any_key
}

# ============================================
# MAIN SCRIPT EXECUTION
# ============================================

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--interactive)
            INTERACTIVE_MODE=true
            shift
            ;;
        -n|--non-interactive)
            INTERACTIVE_MODE=false
            shift
            ;;
        -e|--exim-log)
            if [[ -n "${2:-}" ]]; then
                EXIM_LOG="$2"
                shift 2
            else
                echo -e "${RED}❌ Error: --exim-log requires a path${NC}" >&2
                exit 1
            fi
            ;;
        -m|--mail-log)
            if [[ -n "${2:-}" ]]; then
                MAIL_LOG="$2"
                shift 2
            else
                echo -e "${RED}❌ Error: --mail-log requires a path${NC}" >&2
                exit 1
            fi
            ;;
        -p|--postfix-log)
            if [[ -n "${2:-}" ]]; then
                POSTFIX_LOG="$2"
                shift 2
            else
                echo -e "${RED}❌ Error: --postfix-log requires a path${NC}" >&2
                exit 1
            fi
            ;;
        -d|--dovecot-log)
            if [[ -n "${2:-}" ]]; then
                DOVECOT_LOG="$2"
                shift 2
            else
                echo -e "${RED}❌ Error: --dovecot-log requires a path${NC}" >&2
                exit 1
            fi
            ;;
        -t|--top)
            if [[ -n "${2:-}" ]] && validate_number "$2"; then
                TOP="$2"
                shift 2
            else
                echo -e "${RED}❌ Error: --top requires a valid number${NC}" >&2
                exit 1
            fi
            ;;
        -h|--hours)
            if [[ -n "${2:-}" ]] && validate_number "$2"; then
                HOURS="$2"
                shift 2
            else
                echo -e "${RED}❌ Error: --hours requires a valid number${NC}" >&2
                exit 1
            fi
            ;;
        -o|--output)
            if [[ -n "${2:-}" ]]; then
                OUTPUT_FILE="$2"
                shift 2
            else
                echo -e "${RED}❌ Error: --output requires a filename${NC}" >&2
                exit 1
            fi
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -s|--summary)
            SUMMARY_ONLY=true
            INTERACTIVE_MODE=false
            shift
            ;;
        --blocked-only)
            BLOCKED_ONLY=true
            INTERACTIVE_MODE=false
            shift
            ;;
        --admin-full)
            ADMIN_FULL=true
            INTERACTIVE_MODE=false
            shift
            ;;
        --performance)
            PERFORMANCE_ONLY=true
            INTERACTIVE_MODE=false
            shift
            ;;
        --ube-uce)
            UBE_UCE_ONLY=true
            INTERACTIVE_MODE=false
            shift
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}" >&2
            print_usage
            exit 1
            ;;
    esac
done

# Redirect output if specified
if [[ -n "$OUTPUT_FILE" ]]; then
    exec > >(tee "$OUTPUT_FILE")
fi

# Main execution
echo -e "${GREEN}Starting Mail Analyzer v${SCRIPT_VERSION}...${NC}"

# Check for available logs
if ! get_available_logs; then
    exit 1
fi

if [[ "$INTERACTIVE_MODE" == true ]]; then
    # Check if running in a terminal
    if [ -t 0 ] && [ -t 1 ]; then
        interactive_menu
    else
        echo -e "${YELLOW}Not running in terminal, switching to non-interactive mode...${NC}"
        SUMMARY_ONLY=true
        INTERACTIVE_MODE=false
    fi
fi

if [[ "$INTERACTIVE_MODE" == false ]]; then
    print_header
    
    if [[ "$SUMMARY_ONLY" == true ]]; then
        generate_summary_report
        generate_security_recommendations
    elif [[ "$ADMIN_FULL" == true ]]; then
        # Complete admin analysis - all features from original script
        analyze_smtp_authenticated
        analyze_script_senders
        analyze_envelope_patterns
        analyze_delivery_status
        analyze_spam_patterns
        analyze_rejected_spam
        analyze_content_patterns
        analyze_subject_patterns
        analyze_geographic_patterns
        analyze_time_patterns
        analyze_mail_queue
        analyze_server_performance
        generate_summary_report
        generate_security_recommendations
    elif [[ "$UBE_UCE_ONLY" == true ]]; then
        analyze_subject_patterns
        analyze_content_patterns
        generate_summary_report
    elif [[ "$PERFORMANCE_ONLY" == true ]]; then
        analyze_server_performance
        analyze_time_patterns
        analyze_mail_queue
        generate_summary_report
    elif [[ "$BLOCKED_ONLY" == true ]]; then
        analyze_rejected_spam
        generate_summary_report
    else
        # Default analysis - comprehensive spam detection
        analyze_spam_patterns
        analyze_rejected_spam
        analyze_content_patterns
        analyze_subject_patterns
        analyze_geographic_patterns
        analyze_time_patterns
        analyze_mail_queue
        generate_summary_report
        generate_security_recommendations
    fi
    
    echo -e "${GREEN}✅ Analysis completed at $(date)${NC}"
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo -e "${CYAN}📄 Report saved to: $OUTPUT_FILE${NC}"
    fi
fi