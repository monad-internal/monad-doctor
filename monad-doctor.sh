#!/usr/bin/env bash
#
# monad-doctor - Diagnostic tool for Monad node operators
#
# Automatically detects hardware, configuration, network, and operational issues.
#
# Usage:
#   curl -fsSL https://example.com/monad-doctor.sh | bash
#   curl -fsSL https://example.com/monad-doctor.sh -o monad-doctor && chmod +x monad-doctor && ./monad-doctor
#
# Examples:
#   monad-doctor                      # Run all tests
#   monad-doctor --category hardware  # Specific category
#   monad-doctor --priority critical  # Critical only
#   monad-doctor --json              # Machine-readable
#   monad-doctor --verbose           # Debug output

set -o pipefail

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

VERSION="1.0.0"
SCRIPT_START_TIME=$(date +%s)

# Output modes
OUTPUT_MODE="human"  # human|json
VERBOSE=false
FILTER_CATEGORY=""
FILTER_PRIORITY=""

# Exit codes
EXIT_HEALTHY=0
EXIT_WARNINGS=1
EXIT_CRITICAL=2

# Test results storage
declare -a TEST_RESULTS=()
declare -A TEST_COUNTS=(
  [total]=0
  [pass]=0
  [warn]=0
  [fail]=0
  [info]=0
  [skip]=0
)

# Color codes (disabled in JSON mode)
COLOR_RED='\033[0;31m'
COLOR_YELLOW='\033[1;33m'
COLOR_GREEN='\033[0;32m'
COLOR_BLUE='\033[0;34m'
COLOR_CYAN='\033[0;36m'
COLOR_PURPLE='\033[0;35m'
COLOR_MAGENTA='\033[1;35m'
COLOR_BOLD_PURPLE='\033[1;35m'
COLOR_DIM='\033[2m'
COLOR_BOLD='\033[1m'
COLOR_RESET='\033[0m'

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Print colored output (respects OUTPUT_MODE)
print_color() {
  local color="$1"
  shift
  if [[ "$OUTPUT_MODE" == "human" ]]; then
    echo -e "${color}$*${COLOR_RESET}"
  fi
}

# Verbose logging
log_verbose() {
  if [[ "$VERBOSE" == "true" ]]; then
    echo "[DEBUG] $*" >&2
  fi
}

# Safe command execution - returns empty string on failure
safe_exec() {
  local output
  output=$(eval "$*" 2>/dev/null) || return 1
  echo "$output"
}

# Check if command exists
command_exists() {
  command -v "$1" &>/dev/null
}

# Check if file exists and is readable
file_readable() {
  [[ -f "$1" && -r "$1" ]]
}

# Parse TOML value (simple grep-based parser)
parse_toml_value() {
  local file="$1"
  local key="$2"
  if file_readable "$file"; then
    grep "^${key} = " "$file" 2>/dev/null | cut -d '=' -f2- | sed 's/^ *//;s/ *$//;s/"//g'
  fi
}

# Get metrics from Prometheus endpoint
get_metric() {
  local metric="$1"
  local endpoint="${2:-http://localhost:8889/metrics}"

  if ! command_exists curl; then
    return 1
  fi

  local data
  data=$(safe_exec "curl -s --max-time 2 '$endpoint'") || return 1

  echo "$data" | awk -v m="$metric" '
    $1 ~ /^#/ { next }
    $1 == m || $1 ~ ("^" m "\\{") {
      print $2
      exit
    }
  '
}

# Get RPC response
rpc_call() {
  local method="$1"
  local params="${2:-[]}"
  local endpoint="${3:-http://localhost:8080}"

  if ! command_exists curl; then
    return 1
  fi

  local response
  response=$(safe_exec "curl -s --max-time 3 -X POST '$endpoint' \
    -H 'Content-Type: application/json' \
    --data '{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}'")

  if [[ -z "$response" ]]; then
    return 1
  fi

  # Extract result field (simple JSON parsing without jq)
  echo "$response" | grep -o '"result":"[^"]*"' | cut -d'"' -f4
}

# ============================================================================
# TEST FRAMEWORK
# ============================================================================

# Record test result
# Usage: record_result ID NAME CATEGORY PRIORITY STATUS MESSAGE [VALUE] [EXPECTED] [REMEDIATION] [RUNBOOK_REFS]
record_result() {
  local test_id="$1"
  local name="$2"
  local category="$3"
  local priority="$4"
  local status="$5"
  local message="$6"
  local value="${7:-}"
  local expected="${8:-}"
  local remediation="${9:-}"
  local runbook_refs="${10:-}"

  # Apply filters
  if [[ -n "$FILTER_CATEGORY" && "$category" != "$FILTER_CATEGORY" ]]; then
    return
  fi

  if [[ -n "$FILTER_PRIORITY" && "$priority" != "$FILTER_PRIORITY" ]]; then
    return
  fi

  # Store result
  local result_json
  result_json=$(cat <<-EOF
{
  "test_id": "$test_id",
  "name": "$name",
  "category": "$category",
  "priority": "$priority",
  "status": "$status",
  "message": "$message",
  "value": "$value",
  "expected": "$expected",
  "remediation": "$remediation",
  "runbook_references": "$runbook_refs"
}
EOF
  )

  TEST_RESULTS+=("$result_json")
  ((TEST_COUNTS[total]++))

  case "$status" in
    PASS) ((TEST_COUNTS[pass]++)) ;;
    WARN) ((TEST_COUNTS[warn]++)) ;;
    FAIL) ((TEST_COUNTS[fail]++)) ;;
    INFO) ((TEST_COUNTS[info]++)) ;;
    SKIP) ((TEST_COUNTS[skip]++)) ;;
  esac

  # Print result immediately in human mode
  if [[ "$OUTPUT_MODE" == "human" ]]; then
    print_test_result "$test_id" "$name" "$status" "$message" "$remediation"
  fi
}

# Print a single test result (human-readable)
print_test_result() {
  local test_id="$1"
  local name="$2"
  local status="$3"
  local message="$4"
  local remediation="$5"

  local color="$COLOR_RESET"
  local symbol="•"
  local status_display="$status"

  case "$status" in
    PASS)
      color="$COLOR_GREEN"
      symbol="✓"
      ;;
    WARN)
      color="$COLOR_YELLOW"
      symbol="⚠"
      ;;
    FAIL)
      color="$COLOR_RED"
      symbol="✗"
      ;;
    INFO)
      color="$COLOR_PURPLE"
      symbol="ℹ"
      ;;
    SKIP)
      color="$COLOR_DIM"
      symbol="⊘"
      ;;
  esac

  printf "${color}${symbol}${COLOR_RESET} ${COLOR_BOLD}%-4s${COLOR_RESET} ${COLOR_DIM}[${COLOR_RESET}${COLOR_MAGENTA}%-12s${COLOR_RESET}${COLOR_DIM}]${COLOR_RESET} %s${COLOR_DIM}:${COLOR_RESET} %s\n" \
    "$status_display" "$test_id" "$name" "$message"

  if [[ -n "$remediation" && ("$status" == "FAIL" || "$status" == "WARN") ]]; then
    printf "      ${COLOR_PURPLE}→${COLOR_RESET} ${COLOR_DIM}%s${COLOR_RESET}\n" "$remediation"
  fi
}

# ============================================================================
# PREREQUISITES TESTS
# ============================================================================

test_required_tools() {
  local required_tools=("curl" "ss" "lsblk" "systemctl" "journalctl")
  local optional_tools=("nvme" "parted" "aria2")
  local missing_required=()
  local missing_optional=()

  for tool in "${required_tools[@]}"; do
    if ! command_exists "$tool"; then
      missing_required+=("$tool")
    fi
  done

  for tool in "${optional_tools[@]}"; do
    if ! command_exists "$tool"; then
      missing_optional+=("$tool")
    fi
  done

  if ((${#missing_required[@]} == 0)); then
    if ((${#missing_optional[@]} == 0)); then
      record_result "PREREQ-001" "Required Tools" "Prerequisites" "High" "PASS" \
        "All required and optional tools present" "present" "present" "" ""
    else
      local optional_str="${missing_optional[*]}"
      record_result "PREREQ-001" "Required Tools" "Prerequisites" "High" "INFO" \
        "Required tools present, missing optional: $optional_str" "mostly present" "present" \
        "Install optional tools: apt install nvme-cli parted aria2" ""
    fi
  else
    local required_str="${missing_required[*]}"
    record_result "PREREQ-001" "Required Tools" "Prerequisites" "High" "FAIL" \
      "Missing required tools: $required_str" "missing" "present" \
      "Install missing tools with apt" ""
  fi
}

# ============================================================================
# HARDWARE TESTS
# ============================================================================

test_cpu_cores() {
  local cores
  cores=$(nproc 2>/dev/null)

  if [[ -z "$cores" ]]; then
    record_result "HW-CPU-001" "CPU Core Count" "Hardware" "Critical" "SKIP" \
      "Unable to detect CPU cores" "" "≥16" "" ""
    return
  fi

  if ((cores >= 16)); then
    record_result "HW-CPU-001" "CPU Core Count" "Hardware" "Critical" "PASS" \
      "Detected $cores cores" "$cores" "≥16" "" ""
  else
    record_result "HW-CPU-001" "CPU Core Count" "Hardware" "Critical" "FAIL" \
      "Detected only $cores cores" "$cores" "≥16" \
      "Upgrade to CPU with at least 16 cores (official requirement)" ""
  fi
}

test_hyperthreading() {
  if ! file_readable "/proc/cpuinfo"; then
    record_result "HW-CPU-003" "HyperThreading/SMT" "Hardware" "High" "SKIP" \
      "Unable to check hyperthreading" "" "Disabled" "" ""
    return
  fi

  local siblings cores
  siblings=$(grep -E "^siblings" /proc/cpuinfo | head -1 | awk '{print $3}')
  cores=$(grep -E "^cpu cores" /proc/cpuinfo | head -1 | awk '{print $4}')

  if [[ -z "$siblings" || -z "$cores" ]]; then
    record_result "HW-CPU-003" "HyperThreading/SMT" "Hardware" "High" "SKIP" \
      "Unable to determine HT status" "" "Disabled" "" ""
    return
  fi

  if ((siblings > cores)); then
    record_result "HW-CPU-003" "HyperThreading/SMT" "Hardware" "High" "WARN" \
      "HyperThreading is enabled ($siblings threads per core)" "Enabled" "Disabled" \
      "Disable HyperThreading/SMT in BIOS for best performance" ""
  else
    record_result "HW-CPU-003" "HyperThreading/SMT" "Hardware" "High" "PASS" \
      "HyperThreading is disabled" "Disabled" "Disabled" "" ""
  fi
}

test_thermal_throttling() {
  local throttle_events=0
  local checked=false

  # Check thermal throttling counters
  for cpu_dir in /sys/devices/system/cpu/cpu*/thermal_throttle/; do
    if [[ -d "$cpu_dir" ]]; then
      checked=true
      for counter_file in "$cpu_dir"/*_throttle_count; do
        if file_readable "$counter_file"; then
          local count
          count=$(cat "$counter_file" 2>/dev/null)
          if [[ -n "$count" ]] && ((count > 0)); then
            ((throttle_events += count))
          fi
        fi
      done
    fi
  done

  if [[ "$checked" == "false" ]]; then
    record_result "HW-CPU-005" "Thermal Throttling" "Hardware" "High" "SKIP" \
      "Unable to check thermal throttling" "" "0 events" "" ""
    return
  fi

  if ((throttle_events == 0)); then
    record_result "HW-CPU-005" "Thermal Throttling" "Hardware" "High" "PASS" \
      "No thermal throttling detected" "0" "0 events" "" ""
  else
    record_result "HW-CPU-005" "Thermal Throttling" "Hardware" "High" "WARN" \
      "Thermal throttling detected ($throttle_events events)" "$throttle_events" "0 events" \
      "Improve cooling - thermal throttling causes block skips (runbook: validator thermal issues)" \
      "validator-discussion: thermal throttling block skips"
  fi
}

test_memory_capacity() {
  local mem_gb
  mem_gb=$(awk '/MemTotal/ {printf "%.0f\n", $2/1024/1024}' /proc/meminfo 2>/dev/null)

  if [[ -z "$mem_gb" ]]; then
    record_result "HW-MEM-001" "RAM Capacity" "Hardware" "Critical" "SKIP" \
      "Unable to detect RAM" "" "≥32GB" "" ""
    return
  fi

  if ((mem_gb >= 32)); then
    record_result "HW-MEM-001" "RAM Capacity" "Hardware" "Critical" "PASS" \
      "Detected ${mem_gb}GB RAM" "${mem_gb}GB" "≥32GB" "" ""
  else
    record_result "HW-MEM-001" "RAM Capacity" "Hardware" "Critical" "FAIL" \
      "Only ${mem_gb}GB RAM detected" "${mem_gb}GB" "≥32GB" \
      "Upgrade to at least 32GB RAM (official requirement)" ""
  fi
}

test_memory_available() {
  local avail_gb
  avail_gb=$(awk '/MemAvailable/ {printf "%.1f\n", $2/1024/1024}' /proc/meminfo 2>/dev/null)

  if [[ -z "$avail_gb" ]]; then
    record_result "HW-MEM-002" "Available Memory" "Hardware" "Medium" "SKIP" \
      "Unable to check available memory" "" ">8GB" "" ""
    return
  fi

  local avail_int=${avail_gb%.*}
  if ((avail_int >= 8)); then
    record_result "HW-MEM-002" "Available Memory" "Hardware" "Medium" "PASS" \
      "${avail_gb}GB available" "${avail_gb}GB" ">8GB" "" ""
  else
    record_result "HW-MEM-002" "Available Memory" "Hardware" "Medium" "WARN" \
      "Low available memory: ${avail_gb}GB" "${avail_gb}GB" ">8GB" \
      "System under memory pressure - close other applications or add more RAM" ""
  fi
}

test_oom_events() {
  if ! command_exists dmesg; then
    record_result "HW-MEM-003" "OOM Killer Events" "Hardware" "Medium" "SKIP" \
      "dmesg unavailable" "" "0 events" "" ""
    return
  fi

  local oom_count
  oom_count=$(safe_exec "dmesg | grep -i 'out of memory' | wc -l")

  if [[ -z "$oom_count" ]]; then
    oom_count=0
  fi

  if ((oom_count == 0)); then
    record_result "HW-MEM-003" "OOM Killer Events" "Hardware" "Medium" "PASS" \
      "No OOM events found" "0" "0 events" "" ""
  else
    record_result "HW-MEM-003" "OOM Killer Events" "Hardware" "Medium" "WARN" \
      "Found $oom_count OOM events in kernel log" "$oom_count" "0 events" \
      "Increase RAM or reduce other processes" ""
  fi
}

test_environment_type() {
  local virt_type="none"

  if command_exists systemd-detect-virt; then
    virt_type=$(safe_exec "systemd-detect-virt")
  fi

  if [[ -z "$virt_type" || "$virt_type" == "none" ]]; then
    record_result "HW-ENV-001" "Environment Type" "Hardware" "High" "PASS" \
      "Running on bare metal" "bare metal" "bare metal" "" ""
  else
    record_result "HW-ENV-001" "Environment Type" "Hardware" "High" "WARN" \
      "Running in virtualized environment: $virt_type" "$virt_type" "bare metal" \
      "Cloud/VM environments not officially supported due to strict timing requirements" ""
  fi
}

test_os_version() {
  if ! file_readable "/etc/os-release"; then
    record_result "HW-ENV-002" "OS Version" "Hardware" "High" "SKIP" \
      "Unable to detect OS" "" "Ubuntu 24.04+" "" ""
    return
  fi

  local os_name os_version
  os_name=$(grep "^NAME=" /etc/os-release | cut -d'"' -f2)
  os_version=$(grep "^VERSION_ID=" /etc/os-release | cut -d'"' -f2)

  if [[ "$os_name" =~ Ubuntu ]]; then
    local version_major="${os_version%%.*}"
    if ((version_major >= 24)); then
      record_result "HW-ENV-002" "OS Version" "Hardware" "High" "PASS" \
        "Running $os_name $os_version" "$os_name $os_version" "Ubuntu 24.04+" "" ""
    else
      record_result "HW-ENV-002" "OS Version" "Hardware" "High" "WARN" \
        "Running $os_name $os_version" "$os_name $os_version" "Ubuntu 24.04+" \
        "Ubuntu 24.04 or newer recommended" ""
    fi
  else
    record_result "HW-ENV-002" "OS Version" "Hardware" "High" "WARN" \
      "Running $os_name $os_version (not Ubuntu)" "$os_name $os_version" "Ubuntu 24.04+" \
      "Ubuntu 24.04+ officially supported" ""
  fi
}

test_kernel_version() {
  local kernel_version
  kernel_version=$(uname -r)

  # Check for known bad kernel versions
  if [[ "$kernel_version" =~ ^6\.8\.0-5[6-9] ]]; then
    record_result "HW-ENV-003" "Kernel Version" "Hardware" "Critical" "FAIL" \
      "Running kernel $kernel_version (known issues)" "$kernel_version" "6.8.0-60+" \
      "Upgrade kernel - versions 6.8.0.56-59 cause uninterruptible sleep hangs" ""
  else
    record_result "HW-ENV-003" "Kernel Version" "Hardware" "Critical" "PASS" \
      "Running kernel $kernel_version" "$kernel_version" "Not 6.8.0-56 to 6.8.0-59" "" ""
  fi
}

test_cpu_governor() {
  # Check CPU governor (performance mode)
  local governor_file="/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"

  if [[ ! -f "$governor_file" ]]; then
    record_result "HW-CPU-006" "CPU Governor" "Hardware" "High" "SKIP" \
      "Unable to check CPU governor" "" "performance" "" ""
    return
  fi

  local governor
  governor=$(cat "$governor_file" 2>/dev/null)

  if [[ "$governor" == "performance" ]]; then
    record_result "HW-CPU-006" "CPU Governor" "Hardware" "High" "PASS" \
      "CPU governor set to performance" "performance" "performance" "" ""
  else
    record_result "HW-CPU-006" "CPU Governor" "Hardware" "High" "WARN" \
      "CPU governor set to $governor (not performance)" "$governor" "performance" \
      "Set CPU governor to performance mode for best results: echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" \
      "validator-discussion: CPU power save mode"
  fi
}

# ============================================================================
# STORAGE TESTS
# ============================================================================

test_nvme_count() {
  local nvme_count
  nvme_count=$(lsblk -d -o NAME,TYPE 2>/dev/null | grep -c nvme || echo "0")

  if ((nvme_count >= 2)); then
    record_result "STOR-001" "NVMe Drive Count" "Storage" "Critical" "PASS" \
      "Found $nvme_count NVMe drives" "$nvme_count" "≥2" "" ""
  else
    record_result "STOR-001" "NVMe Drive Count" "Storage" "Critical" "FAIL" \
      "Only $nvme_count NVMe drive(s) found" "$nvme_count" "≥2" \
      "Monad requires 2 separate NVMe drives (one for TrieDB, one for OS/BFT)" ""
  fi
}

test_triedb_device() {
  if [[ ! -e "/dev/triedb" ]]; then
    record_result "STOR-MPT-002" "TrieDB Device" "Storage" "Critical" "FAIL" \
      "/dev/triedb not found" "not found" "exists" \
      "Create /dev/triedb symlink to NVMe partition for TrieDB" ""
    return
  fi

  # Check if it's a block device
  if [[ ! -b "/dev/triedb" ]]; then
    record_result "STOR-MPT-002" "TrieDB Device" "Storage" "Critical" "FAIL" \
      "/dev/triedb exists but is not a block device" "not block device" "block device" \
      "/dev/triedb must be a block device or symlink to one" ""
    return
  fi

  # Check if it has a filesystem (it shouldn't)
  local fs_type
  fs_type=$(lsblk -no FSTYPE /dev/triedb 2>/dev/null)

  if [[ -n "$fs_type" ]]; then
    record_result "STOR-MPT-002" "TrieDB Device" "Storage" "Critical" "WARN" \
      "/dev/triedb has filesystem: $fs_type" "$fs_type" "raw device" \
      "TrieDB should use raw device without filesystem for best performance" ""
  else
    record_result "STOR-MPT-002" "TrieDB Device" "Storage" "Critical" "PASS" \
      "/dev/triedb configured correctly (raw device)" "raw device" "raw device" "" ""
  fi
}

test_nvme_lba_format() {
  if ! command_exists nvme; then
    record_result "STOR-LBA-001" "NVMe LBA Format" "Storage" "High" "SKIP" \
      "nvme command not available" "" "512 bytes" "" ""
    return
  fi

  if [[ ! -e "/dev/triedb" ]]; then
    record_result "STOR-LBA-001" "NVMe LBA Format" "Storage" "High" "SKIP" \
      "/dev/triedb not found" "" "512 bytes" "" ""
    return
  fi

  # Resolve symlink to actual device
  local actual_device
  actual_device=$(readlink -f /dev/triedb 2>/dev/null)

  if [[ -z "$actual_device" ]]; then
    actual_device="/dev/triedb"
  fi

  # Check LBA format
  local lba_info
  lba_info=$(safe_exec "nvme id-ns '$actual_device'" | grep "in use")

  if [[ -z "$lba_info" ]]; then
    record_result "STOR-LBA-001" "NVMe LBA Format" "Storage" "High" "SKIP" \
      "Unable to read LBA format" "" "512 bytes" "" ""
    return
  fi

  if echo "$lba_info" | grep -q "lbaf 0.*512.*in use"; then
    record_result "STOR-LBA-001" "NVMe LBA Format" "Storage" "High" "PASS" \
      "LBA format is 512 bytes" "512 bytes" "512 bytes" "" ""
  else
    local detected_lba
    detected_lba=$(echo "$lba_info" | grep -oE '[0-9]+.*in use' | awk '{print $1}')
    record_result "STOR-LBA-001" "NVMe LBA Format" "Storage" "High" "FAIL" \
      "LBA format is $detected_lba (expected 512 bytes)" "$detected_lba" "512 bytes" \
      "Reformat NVMe with 512-byte LBA: nvme format /dev/nvmeXnY --lbaf=0" ""
  fi
}

test_triedb_capacity() {
  if [[ ! -e "/dev/triedb" ]]; then
    record_result "STOR-002" "TrieDB Capacity" "Storage" "Critical" "SKIP" \
      "/dev/triedb not found" "" "≥2TB" "" ""
    return
  fi

  local size_bytes size_tb
  size_bytes=$(lsblk -bno SIZE /dev/triedb 2>/dev/null | head -1)

  if [[ -z "$size_bytes" ]]; then
    record_result "STOR-002" "TrieDB Capacity" "Storage" "Critical" "SKIP" \
      "Unable to determine size" "" "≥2TB" "" ""
    return
  fi

  # Convert to TB (1TB = 1000^4 bytes for storage)
  size_tb=$(awk -v bytes="$size_bytes" 'BEGIN {printf "%.2f", bytes/1000/1000/1000/1000}')

  # Accept >= 1.9TB (allows for 2TB drives with actual usable space of ~1.92TB)
  if awk -v size="$size_tb" 'BEGIN {exit (size >= 1.9) ? 0 : 1}'; then
    record_result "STOR-002" "TrieDB Capacity" "Storage" "Critical" "PASS" \
      "TrieDB drive is ${size_tb}TB" "${size_tb}TB" "≥1.9TB" "" ""
  else
    record_result "STOR-002" "TrieDB Capacity" "Storage" "Critical" "FAIL" \
      "TrieDB drive is only ${size_tb}TB" "${size_tb}TB" "≥1.9TB" \
      "TrieDB requires at least 2TB NVMe drive (1.9TB+ usable space)" ""
  fi
}

test_mpt_initialization() {
  if ! command_exists monad-mpt; then
    record_result "STOR-MPT-004" "MPT Initialization" "Storage" "High" "SKIP" \
      "monad-mpt command not available" "" "no errors" "" ""
    return
  fi

  if [[ ! -e "/dev/triedb" ]]; then
    record_result "STOR-MPT-004" "MPT Initialization" "Storage" "High" "SKIP" \
      "/dev/triedb not found" "" "no errors" "" ""
    return
  fi

  local mpt_output
  mpt_output=$(safe_exec "monad-mpt --storage /dev/triedb 2>&1")

  if [[ -z "$mpt_output" ]]; then
    record_result "STOR-MPT-004" "MPT Initialization" "Storage" "High" "WARN" \
      "No output from monad-mpt" "" "valid output" \
      "Unable to query MPT status" ""
    return
  fi

  # Check for common errors
  if echo "$mpt_output" | grep -qi "assertion.*failed"; then
    record_result "STOR-MPT-004" "MPT Initialization" "Storage" "High" "FAIL" \
      "MPT assertion failure detected" "assertion failed" "no errors" \
      "MPT database error - may need reset or drive replacement (runbook: MPT failures)" \
      "validator-discussion: MPT assertion errors"
  elif echo "$mpt_output" | grep -qi "block size mismatch"; then
    record_result "STOR-MPT-004" "MPT Initialization" "Storage" "High" "FAIL" \
      "MPT block size mismatch" "block size error" "no errors" \
      "TrieDB LBA format issue - must use 512-byte blocks" ""
  elif echo "$mpt_output" | grep -qi "MPT database has"; then
    record_result "STOR-MPT-004" "MPT Initialization" "Storage" "High" "PASS" \
      "MPT database initialized and healthy" "healthy" "no errors" "" ""
  else
    record_result "STOR-MPT-004" "MPT Initialization" "Storage" "High" "INFO" \
      "MPT status unclear" "" "valid output" "" ""
  fi
}

test_nvme_model() {
  local models=""
  local has_nextorage=false

  for nvme in /dev/nvme*n1; do
    [[ -e "$nvme" ]] || continue

    local model
    model=$(lsblk -no MODEL "$nvme" 2>/dev/null | head -1)

    if [[ -n "$model" ]]; then
      models+="$model, "

      if [[ "$model" =~ Nextorage ]]; then
        has_nextorage=true
      fi
    fi
  done

  models="${models%, }"

  if [[ -z "$models" ]]; then
    record_result "STOR-005" "NVMe Model" "Storage" "Medium" "SKIP" \
      "Unable to detect NVMe models" "" "" "" ""
    return
  fi

  if [[ "$has_nextorage" == "true" ]]; then
    record_result "STOR-005" "NVMe Model" "Storage" "Medium" "WARN" \
      "Detected Nextorage SSD: $models" "$models" "Reliable models" \
      "Nextorage SSDs reported as unreliable and prone to overheating under load (official docs)" ""
  else
    record_result "STOR-005" "NVMe Model" "Storage" "Medium" "INFO" \
      "NVMe models: $models" "$models" "" "" ""
  fi
}

test_disk_space() {
  # Check TrieDB drive space
  if [[ -e "/dev/triedb" ]]; then
    local triedb_avail_gb
    local triedb_mount
    triedb_mount=$(lsblk -no MOUNTPOINT /dev/triedb 2>/dev/null | head -1)

    if [[ -z "$triedb_mount" ]]; then
      # Raw device, check partition size
      record_result "STOR-SPACE-001" "TrieDB Free Space" "Storage" "High" "INFO" \
        "TrieDB is raw device (no filesystem to check)" "raw device" "" "" ""
    else
      triedb_avail_gb=$(df -BG "$triedb_mount" | awk 'NR==2 {print $4}' | sed 's/G//')

      if [[ -n "$triedb_avail_gb" ]]; then
        if ((triedb_avail_gb >= 200)); then
          record_result "STOR-SPACE-001" "TrieDB Free Space" "Storage" "High" "PASS" \
            "TrieDB has ${triedb_avail_gb}GB free" "${triedb_avail_gb}GB" ">200GB" "" ""
        elif ((triedb_avail_gb >= 50)); then
          record_result "STOR-SPACE-001" "TrieDB Free Space" "Storage" "High" "WARN" \
            "TrieDB has ${triedb_avail_gb}GB free (low)" "${triedb_avail_gb}GB" ">200GB" \
            "Free up space - low disk space can cause database corruption" ""
        else
          record_result "STOR-SPACE-001" "TrieDB Free Space" "Storage" "High" "FAIL" \
            "TrieDB has only ${triedb_avail_gb}GB free (critical)" "${triedb_avail_gb}GB" ">200GB" \
            "CRITICAL: Free up space immediately - node may crash or corrupt data" ""
        fi
      fi
    fi
  fi

  # Check root/OS drive space
  local root_avail_gb
  root_avail_gb=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')

  if [[ -n "$root_avail_gb" ]]; then
    if ((root_avail_gb >= 50)); then
      record_result "STOR-SPACE-002" "OS Drive Free Space" "Storage" "Medium" "PASS" \
        "OS drive has ${root_avail_gb}GB free" "${root_avail_gb}GB" ">50GB" "" ""
    elif ((root_avail_gb >= 20)); then
      record_result "STOR-SPACE-002" "OS Drive Free Space" "Storage" "Medium" "WARN" \
        "OS drive has ${root_avail_gb}GB free (low)" "${root_avail_gb}GB" ">50GB" \
        "Free up space on OS drive" ""
    else
      record_result "STOR-SPACE-002" "OS Drive Free Space" "Storage" "Medium" "FAIL" \
        "OS drive has only ${root_avail_gb}GB free (critical)" "${root_avail_gb}GB" ">50GB" \
        "CRITICAL: Free up space - logs and artifacts may fill disk" ""
    fi
  fi
}

# ============================================================================
# NETWORK TESTS
# ============================================================================

test_internet_connectivity() {
  if ! command_exists curl; then
    record_result "NET-INET-001" "Internet Connectivity" "Network" "Critical" "SKIP" \
      "curl not available" "" "connected" "" ""
    return
  fi

  # Try to reach a reliable external endpoint
  if safe_exec "curl -s --max-time 5 https://1.1.1.1 >/dev/null"; then
    record_result "NET-INET-001" "Internet Connectivity" "Network" "Critical" "PASS" \
      "Internet connectivity verified" "connected" "connected" "" ""
  else
    record_result "NET-INET-001" "Internet Connectivity" "Network" "Critical" "FAIL" \
      "Cannot reach external internet" "no connection" "connected" \
      "Node requires internet access to sync and connect to peers" ""
  fi
}

test_bootstrap_peer_connectivity() {
  # Known Monad bootstrap peer from docs (64.31.29.190:8000)
  local bootstrap_ip="64.31.29.190"
  local bootstrap_port="8000"

  if ! command_exists nc; then
    record_result "NET-BOOT-001" "Bootstrap Peer Access" "Network" "High" "SKIP" \
      "nc command unavailable" "" "accessible" "" ""
    return
  fi

  # Test TCP connectivity to bootstrap peer
  if timeout 3 nc -z "$bootstrap_ip" "$bootstrap_port" 2>/dev/null; then
    record_result "NET-BOOT-001" "Bootstrap Peer Access" "Network" "High" "PASS" \
      "Can reach bootstrap peer $bootstrap_ip:$bootstrap_port" "accessible" "accessible" "" ""
  else
    record_result "NET-BOOT-001" "Bootstrap Peer Access" "Network" "High" "WARN" \
      "Cannot reach bootstrap peer $bootstrap_ip:$bootstrap_port" "blocked" "accessible" \
      "Check firewall egress rules for TCP port 8000" ""
  fi
}

test_port_8000_listening() {
  if ! command_exists ss; then
    record_result "NET-PORT-001" "Port 8000 Status" "Network" "Critical" "SKIP" \
      "ss command unavailable" "" "listening" "" ""
    return
  fi

  if ss -ln | grep -q ":8000"; then
    record_result "NET-PORT-001" "Port 8000 Status" "Network" "Critical" "PASS" \
      "Port 8000 is listening" "listening" "listening" "" ""
  else
    record_result "NET-PORT-001" "Port 8000 Status" "Network" "Critical" "WARN" \
      "Port 8000 is not listening" "not listening" "listening" \
      "Monad P2P requires port 8000 TCP/UDP open and listening" ""
  fi
}

test_firewall_port_8000() {
  local firewall_status="unknown"
  local is_open=false

  # Check ufw
  if command_exists ufw; then
    local ufw_status
    ufw_status=$(safe_exec "ufw status" | grep "8000")

    if echo "$ufw_status" | grep -q "ALLOW"; then
      is_open=true
      firewall_status="allowed"
    elif echo "$ufw_status" | grep -q "DENY"; then
      firewall_status="blocked"
    fi
  fi

  # Check iptables if ufw didn't help
  if [[ "$firewall_status" == "unknown" ]] && command_exists iptables; then
    if safe_exec "iptables -L INPUT -n" | grep -q "8000"; then
      local rule
      rule=$(safe_exec "iptables -L INPUT -n" | grep "8000" | head -1)
      if echo "$rule" | grep -q "ACCEPT"; then
        is_open=true
        firewall_status="allowed"
      elif echo "$rule" | grep -q "DROP\|REJECT"; then
        firewall_status="blocked"
      fi
    fi
  fi

  if [[ "$is_open" == "true" ]]; then
    record_result "NET-PORT-004" "Firewall Port 8000" "Network" "Critical" "PASS" \
      "Port 8000 allowed through firewall" "allowed" "allowed" "" ""
  elif [[ "$firewall_status" == "blocked" ]]; then
    record_result "NET-PORT-004" "Firewall Port 8000" "Network" "Critical" "FAIL" \
      "Port 8000 blocked by firewall" "blocked" "allowed" \
      "Open port 8000 TCP/UDP: ufw allow 8000/tcp && ufw allow 8000/udp" ""
  else
    record_result "NET-PORT-004" "Firewall Port 8000" "Network" "Critical" "INFO" \
      "Firewall status unclear or no firewall detected" "unknown" "allowed" "" ""
  fi
}

test_self_address_config() {
  local config_file="/home/monad/monad-bft/config/node.toml"

  if ! file_readable "$config_file"; then
    record_result "NET-CONF-001" "Self Address Config" "Network" "Critical" "SKIP" \
      "node.toml not found" "" "matches public IP" "" ""
    return
  fi

  local self_address
  self_address=$(parse_toml_value "$config_file" "self_address")

  if [[ -z "$self_address" ]]; then
    record_result "NET-CONF-001" "Self Address Config" "Network" "Critical" "WARN" \
      "self_address not configured" "" "matches public IP" \
      "Set self_address in node.toml to your public IP" ""
    return
  fi

  # Extract IP from self_address (format: /ip4/x.x.x.x/tcp/8000 or /ip6/xxxx::x/tcp/8000)
  local config_ip
  config_ip=$(echo "$self_address" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')

  # If no IPv4, try IPv6
  if [[ -z "$config_ip" ]]; then
    config_ip=$(echo "$self_address" | grep -oE '([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}')
  fi

  # Get actual public IP (try IPv4 first, then IPv6)
  local public_ip
  public_ip=$(safe_exec "curl -s4 --max-time 3 ifconfig.me")

  if [[ -z "$public_ip" ]]; then
    public_ip=$(safe_exec "curl -s6 --max-time 3 ifconfig.me")
  fi

  if [[ -n "$public_ip" && -n "$config_ip" ]]; then
    if [[ "$config_ip" == "$public_ip" ]]; then
      record_result "NET-CONF-001" "Self Address Config" "Network" "Critical" "PASS" \
        "self_address matches public IP: $public_ip" "$config_ip" "$public_ip" "" ""
    else
      # Check if this is just IPv4 vs IPv6 mismatch
      local ip_type_mismatch=false
      if [[ "$config_ip" =~ \. ]] && [[ "$public_ip" =~ : ]]; then
        ip_type_mismatch=true
      elif [[ "$config_ip" =~ : ]] && [[ "$public_ip" =~ \. ]]; then
        ip_type_mismatch=true
      fi

      if [[ "$ip_type_mismatch" == "true" ]]; then
        record_result "NET-CONF-001" "Self Address Config" "Network" "Critical" "INFO" \
          "self_address is IPv4/IPv6, public IP is IPv6/IPv4 (config: $config_ip, public: $public_ip)" "$config_ip" "$public_ip" \
          "Consider using consistent IP protocol (both IPv4 or both IPv6)" ""
      else
        record_result "NET-CONF-001" "Self Address Config" "Network" "Critical" "FAIL" \
          "self_address ($config_ip) does not match public IP ($public_ip)" "$config_ip" "$public_ip" \
          "Common NAT issue - update self_address with correct public IP (runbook: NAT issues)" \
          "fullnode-discussion: NAT configuration"
      fi
    fi
  else
    record_result "NET-CONF-001" "Self Address Config" "Network" "Critical" "INFO" \
      "self_address: $self_address (unable to verify against public IP)" "$self_address" "" "" ""
  fi
}

test_name_record_signature() {
  local config_file="/home/monad/monad-bft/config/node.toml"

  if ! file_readable "$config_file"; then
    record_result "NET-CONF-003" "Name Record Signature" "Network" "High" "SKIP" \
      "node.toml not found" "" "present" "" ""
    return
  fi

  local signature
  signature=$(parse_toml_value "$config_file" "self_name_record_sig")

  if [[ -z "$signature" ]]; then
    record_result "NET-CONF-003" "Name Record Signature" "Network" "High" "WARN" \
      "self_name_record_sig missing" "" "present" \
      "Run monad-sign-name-record to generate signature" ""
  elif [[ "${#signature}" -lt 64 ]]; then
    record_result "NET-CONF-003" "Name Record Signature" "Network" "High" "WARN" \
      "self_name_record_sig appears invalid (too short)" "$signature" "valid hex" \
      "Regenerate signature with monad-sign-name-record" ""
  else
    record_result "NET-CONF-003" "Name Record Signature" "Network" "High" "PASS" \
      "self_name_record_sig present" "present" "present" "" ""
  fi
}

test_peer_count() {
  if ! command_exists monad-debug-node; then
    record_result "NET-PEER-001" "Peer Count" "Network" "High" "SKIP" \
      "monad-debug-node not available" "" "≥10" "" ""
    return
  fi

  local peer_count
  peer_count=$(safe_exec "monad-debug-node -c /home/monad/monad-bft/controlpanel.sock get-peers" | grep -c "address" || echo "0")

  if ((peer_count >= 10)); then
    record_result "NET-PEER-001" "Peer Count" "Network" "High" "PASS" \
      "$peer_count peers connected" "$peer_count" "≥10" "" ""
  elif ((peer_count > 0)); then
    record_result "NET-PEER-001" "Peer Count" "Network" "High" "WARN" \
      "Only $peer_count peers connected" "$peer_count" "≥10" \
      "Low peer count - check firewall, port forwarding, and self_address configuration" ""
  else
    record_result "NET-PEER-001" "Peer Count" "Network" "High" "FAIL" \
      "No peers connected" "0" "≥10" \
      "No peers - check firewall, port forwarding, self_address (runbook: connectivity issues)" \
      "fullnode-discussion: peer connectivity"
  fi
}

test_bind_address_port() {
  local config_file="/home/monad/monad-bft/config/node.toml"

  if ! file_readable "$config_file"; then
    record_result "NET-CONF-004" "bind_address_port Match" "Network" "Critical" "SKIP" \
      "node.toml not found" "" "matches self_address port" "" ""
    return
  fi

  local self_address bind_address_port
  self_address=$(parse_toml_value "$config_file" "self_address")
  bind_address_port=$(parse_toml_value "$config_file" "bind_address_port")

  if [[ -z "$self_address" || -z "$bind_address_port" ]]; then
    record_result "NET-CONF-004" "bind_address_port Match" "Network" "Critical" "SKIP" \
      "Unable to read config values" "" "matches self_address port" "" ""
    return
  fi

  # Extract port from self_address (format: /ip4/x.x.x.x/tcp/8000)
  local self_port
  self_port=$(echo "$self_address" | grep -oE '/tcp/[0-9]+' | grep -oE '[0-9]+')

  if [[ -z "$self_port" ]]; then
    record_result "NET-CONF-004" "bind_address_port Match" "Network" "Critical" "INFO" \
      "Cannot extract port from self_address" "" "matches self_address port" "" ""
    return
  fi

  if [[ "$bind_address_port" == "$self_port" ]]; then
    record_result "NET-CONF-004" "bind_address_port Match" "Network" "Critical" "PASS" \
      "bind_address_port ($bind_address_port) matches self_address port" "$bind_address_port" "$self_port" "" ""
  else
    record_result "NET-CONF-004" "bind_address_port Match" "Network" "Critical" "FAIL" \
      "bind_address_port ($bind_address_port) does not match self_address port ($self_port)" "$bind_address_port" "$self_port" \
      "Set bind_address_port = $self_port in node.toml (v0.12.3 requirement for NAT)" \
      "fullnode-discussion: NAT configuration v0.12.3"
  fi
}

test_port_8080_exposure() {
  if ! command_exists ss; then
    record_result "NET-SEC-001" "Port 8080 Exposure" "Network" "High" "SKIP" \
      "ss command unavailable" "" "not public" "" ""
    return
  fi

  # Check if port 8080 is listening
  if ! ss -ln | grep -q ":8080"; then
    record_result "NET-SEC-001" "Port 8080 Exposure" "Network" "High" "INFO" \
      "Port 8080 not listening" "not listening" "not public" "" ""
    return
  fi

  # Check if it's listening on all interfaces
  if ss -ln | grep ":8080" | grep -q "0.0.0.0:8080\|:::8080"; then
    record_result "NET-SEC-001" "Port 8080 Exposure" "Network" "High" "WARN" \
      "Port 8080 listening on all interfaces (potential security risk)" "public" "localhost only" \
      "For validators: RPC should only listen on localhost or be behind authentication. Consider binding to 127.0.0.1:8080 only" \
      "validator-discussion: RPC security"
  else
    record_result "NET-SEC-001" "Port 8080 Exposure" "Network" "High" "PASS" \
      "Port 8080 listening on localhost only" "localhost" "localhost only" "" ""
  fi
}

# ============================================================================
# CONFIGURATION TESTS
# ============================================================================

test_monad_user_exists() {
  if id monad &>/dev/null; then
    record_result "CONF-001" "Monad User" "Configuration" "Critical" "PASS" \
      "monad user exists" "exists" "exists" "" ""
  else
    record_result "CONF-001" "Monad User" "Configuration" "Critical" "FAIL" \
      "monad user not found" "not found" "exists" \
      "Create monad user for running services" ""
  fi
}

test_config_files_exist() {
  local missing_files=()

  if ! file_readable "/home/monad/.env"; then
    missing_files+=(".env")
  fi

  if ! file_readable "/home/monad/monad-bft/config/node.toml"; then
    missing_files+=("node.toml")
  fi

  if ((${#missing_files[@]} == 0)); then
    record_result "CONF-002" "Config Files" "Configuration" "Critical" "PASS" \
      "Required config files present" "present" "present" "" ""
  else
    local missing_str="${missing_files[*]}"
    record_result "CONF-002" "Config Files" "Configuration" "Critical" "FAIL" \
      "Missing config files: $missing_str" "missing" "present" \
      "Ensure Monad is properly installed with all config files" ""
  fi
}

test_node_toml_syntax() {
  local config_file="/home/monad/monad-bft/config/node.toml"

  if ! file_readable "$config_file"; then
    record_result "CONF-003" "node.toml Syntax" "Configuration" "Critical" "SKIP" \
      "node.toml not found" "" "valid" "" ""
    return
  fi

  # Basic TOML syntax check (look for common errors)
  local errors=""

  # Check for lines with odd number of quotes (likely unclosed quotes)
  while IFS= read -r line; do
    # Skip comments and empty lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$line" ]] && continue

    # Count quotes in line
    local quote_count=$(echo "$line" | grep -o '"' | wc -l)
    if ((quote_count % 2 != 0)); then
      errors+="unclosed quotes on line; "
      break
    fi
  done < "$config_file"

  if [[ -z "$errors" ]]; then
    record_result "CONF-003" "node.toml Syntax" "Configuration" "Critical" "PASS" \
      "TOML syntax appears valid" "valid" "valid" "" ""
  else
    record_result "CONF-003" "node.toml Syntax" "Configuration" "Critical" "WARN" \
      "Possible TOML syntax issues: $errors" "possible issues" "valid" \
      "Review node.toml for syntax errors if services fail to start" ""
  fi
}

test_beneficiary_config() {
  local config_file="/home/monad/monad-bft/config/node.toml"

  if ! file_readable "$config_file"; then
    record_result "CONF-004" "Beneficiary Address" "Configuration" "Medium" "SKIP" \
      "node.toml not found" "" "" "" ""
    return
  fi

  local beneficiary
  beneficiary=$(parse_toml_value "$config_file" "beneficiary")

  if [[ -z "$beneficiary" ]]; then
    record_result "CONF-004" "Beneficiary Address" "Configuration" "Medium" "WARN" \
      "beneficiary not set" "" "configured" \
      "Set beneficiary address for rewards (use burn address 0x0...0 for fullnode)" ""
    return
  fi

  # Check if it's the burn address
  if [[ "$beneficiary" =~ ^0x0+$ ]]; then
    record_result "CONF-004" "Beneficiary Address" "Configuration" "Medium" "INFO" \
      "beneficiary set to burn address (OK for fullnode)" "$beneficiary" "" "" ""
  else
    record_result "CONF-004" "Beneficiary Address" "Configuration" "Medium" "INFO" \
      "beneficiary: $beneficiary" "$beneficiary" "" "" ""
  fi
}

test_enable_client_config() {
  local config_file="/home/monad/monad-bft/config/node.toml"

  if ! file_readable "$config_file"; then
    record_result "CONF-006" "Raptorcast Client" "Configuration" "Medium" "SKIP" \
      "node.toml not found" "" "" "" ""
    return
  fi

  local enable_client
  enable_client=$(grep -A5 "^\[fullnode_raptorcast\]" "$config_file" | parse_toml_value - "enable_client")

  if [[ "$enable_client" == "true" ]]; then
    record_result "CONF-006" "Raptorcast Client" "Configuration" "Medium" "PASS" \
      "fullnode_raptorcast.enable_client is enabled" "true" "true (for fullnode)" "" ""
  elif [[ "$enable_client" == "false" ]]; then
    record_result "CONF-006" "Raptorcast Client" "Configuration" "Medium" "WARN" \
      "fullnode_raptorcast.enable_client is disabled" "false" "true (for fullnode)" \
      "Enable raptorcast client for faster sync (runbook: no raptorcast peers)" \
      "fullnode-discussion: raptorcast issues"
  else
    record_result "CONF-006" "Raptorcast Client" "Configuration" "Medium" "INFO" \
      "fullnode_raptorcast.enable_client not configured" "" "" "" ""
  fi
}

test_keystore_files() {
  local bls_keystore="/home/monad/monad-bft/config/id-bls"
  local secp_keystore="/home/monad/monad-bft/config/id-secp"
  local missing=()

  if ! file_readable "$bls_keystore"; then
    missing+=("BLS keystore")
  fi

  if ! file_readable "$secp_keystore"; then
    missing+=("SECP keystore")
  fi

  if ((${#missing[@]} == 0)); then
    record_result "CONF-KEY-001" "Keystore Files" "Configuration" "Critical" "PASS" \
      "BLS and SECP keystores present" "present" "present" "" ""
  else
    local missing_str="${missing[*]}"
    record_result "CONF-KEY-001" "Keystore Files" "Configuration" "Critical" "FAIL" \
      "Missing keystores: $missing_str" "missing" "present" \
      "Generate keystores with monad-keystore tool" ""
  fi
}

test_keystore_backups() {
  local bls_backup="/opt/monad/backup/bls-backup"
  local secp_backup="/opt/monad/backup/secp-backup"
  local password_backup="/opt/monad/backup/keystore-password-backup"
  local missing=()

  if ! file_readable "$bls_backup"; then
    missing+=("BLS")
  fi

  if ! file_readable "$secp_backup"; then
    missing+=("SECP")
  fi

  if ! file_readable "$password_backup"; then
    missing+=("password")
  fi

  if ((${#missing[@]} == 0)); then
    record_result "CONF-KEY-002" "Keystore Backups" "Configuration" "High" "PASS" \
      "Keystore backups present" "present" "present" "" ""
  elif ((${#missing[@]} == 3)); then
    record_result "CONF-KEY-002" "Keystore Backups" "Configuration" "High" "WARN" \
      "No keystore backups found" "missing" "present" \
      "CRITICAL: Backup keystores to /opt/monad/backup/ immediately - losing these means losing access to node" ""
  else
    local missing_str="${missing[*]}"
    record_result "CONF-KEY-002" "Keystore Backups" "Configuration" "High" "WARN" \
      "Missing backups: $missing_str" "incomplete" "present" \
      "Backup missing keystores to /opt/monad/backup/" ""
  fi
}

test_env_variables() {
  local env_file="/home/monad/.env"

  if ! file_readable "$env_file"; then
    record_result "CONF-ENV-001" ".env Variables" "Configuration" "Critical" "FAIL" \
      ".env file not found or not readable" "missing" "present" \
      "Create /home/monad/.env with required variables" ""
    return
  fi

  local missing=()

  # Check for KEYSTORE_PASSWORD
  if ! grep -q "^KEYSTORE_PASSWORD=" "$env_file"; then
    missing+=("KEYSTORE_PASSWORD")
  fi

  if ((${#missing[@]} == 0)); then
    record_result "CONF-ENV-001" ".env Variables" "Configuration" "Critical" "PASS" \
      "Required environment variables present" "present" "present" "" ""
  else
    local missing_str="${missing[*]}"
    record_result "CONF-ENV-001" ".env Variables" "Configuration" "Critical" "FAIL" \
      "Missing variables: $missing_str" "missing" "present" \
      "Add missing variables to /home/monad/.env" ""
  fi
}

test_remote_config_urls() {
  local env_file="/home/monad/.env"

  if ! file_readable "$env_file"; then
    record_result "CONF-ENV-002" "Remote Config URLs" "Configuration" "Medium" "SKIP" \
      ".env file not found" "" "" "" ""
    return
  fi

  local has_validators=false
  local has_forkpoint=false

  if grep -q "^REMOTE_VALIDATORS_URL=" "$env_file"; then
    has_validators=true
  fi

  if grep -q "^REMOTE_FORKPOINT_URL=" "$env_file"; then
    has_forkpoint=true
  fi

  if [[ "$has_validators" == "true" && "$has_forkpoint" == "true" ]]; then
    record_result "CONF-ENV-002" "Remote Config URLs" "Configuration" "Medium" "PASS" \
      "Remote validators and forkpoint URLs configured" "configured" "configured (recommended)" "" ""
  else
    record_result "CONF-ENV-002" "Remote Config URLs" "Configuration" "Medium" "INFO" \
      "Remote config URLs not configured (manual updates required)" "not configured" "configured (recommended)" \
      "Set REMOTE_VALIDATORS_URL and REMOTE_FORKPOINT_URL for automatic updates" ""
  fi
}

test_node_name() {
  local config_file="/home/monad/monad-bft/config/node.toml"

  if ! file_readable "$config_file"; then
    record_result "CONF-007" "Node Name" "Configuration" "High" "SKIP" \
      "node.toml not found" "" "unique" "" ""
    return
  fi

  local node_name
  node_name=$(parse_toml_value "$config_file" "node_name")

  if [[ -z "$node_name" ]]; then
    record_result "CONF-007" "Node Name" "Configuration" "High" "WARN" \
      "node_name not set" "" "unique name" \
      "Set unique node_name in node.toml (format: full_<PROVIDER>-<SUFFIX>)" ""
  elif [[ "$node_name" =~ ^full_ ]]; then
    record_result "CONF-007" "Node Name" "Configuration" "High" "PASS" \
      "node_name: $node_name" "$node_name" "unique name" "" ""
  else
    record_result "CONF-007" "Node Name" "Configuration" "High" "INFO" \
      "node_name: $node_name (non-standard format)" "$node_name" "full_<PROVIDER>-<SUFFIX>" "" ""
  fi
}

test_hugetlbfs_event_rings() {
  # Check if hugetlbfs is mounted
  if ! mount | grep -q "hugetlbfs"; then
    record_result "CONF-HUGE-001" "Hugetlbfs Mount" "Configuration" "Critical" "WARN" \
      "hugetlbfs not mounted" "not mounted" "mounted" \
      "hugetlbfs required for websocket/event rings support" ""
    return
  fi

  record_result "CONF-HUGE-001" "Hugetlbfs Mount" "Configuration" "Critical" "PASS" \
    "hugetlbfs is mounted" "mounted" "mounted" "" ""

  # Check event-rings directory
  local event_rings_dir="/var/lib/hugetlbfs/user/monad/pagesize-2MB/event-rings/monad-exec-events"

  if [[ ! -d "$event_rings_dir" ]]; then
    record_result "CONF-HUGE-002" "Event Rings Directory" "Configuration" "Critical" "WARN" \
      "Event rings directory not found" "missing" "exists" \
      "Create directory: mkdir -p $event_rings_dir && chown monad:monad $event_rings_dir (required for websockets)" \
      "fullnode-discussion: websocket event rings"
  else
    record_result "CONF-HUGE-002" "Event Rings Directory" "Configuration" "Critical" "PASS" \
      "Event rings directory exists" "exists" "exists" "" ""
  fi
}

test_config_file_freshness() {
  local validators_file="/home/monad/monad-bft/config/validators.toml"
  local forkpoint_file="/home/monad/monad-bft/config/forkpoint/forkpoint.toml"

  # Check validators.toml age
  if file_readable "$validators_file"; then
    local validators_age_days
    validators_age_days=$(( ($(date +%s) - $(stat -c %Y "$validators_file" 2>/dev/null || stat -f %m "$validators_file" 2>/dev/null)) / 86400 ))

    if ((validators_age_days > 7)); then
      record_result "CONF-FRESH-001" "validators.toml Age" "Configuration" "Medium" "WARN" \
        "validators.toml is $validators_age_days days old" "$validators_age_days days" "<7 days" \
        "Update validators.toml - stale validator sets cause sync issues (runbook: old validators)" \
        "fullnode-discussion: stale validators"
    else
      record_result "CONF-FRESH-001" "validators.toml Age" "Configuration" "Medium" "PASS" \
        "validators.toml is $validators_age_days days old" "$validators_age_days days" "<7 days" "" ""
    fi
  else
    record_result "CONF-FRESH-001" "validators.toml Age" "Configuration" "Medium" "SKIP" \
      "validators.toml not found" "" "<7 days" "" ""
  fi

  # Check forkpoint.toml age
  if file_readable "$forkpoint_file"; then
    local forkpoint_age_days
    forkpoint_age_days=$(( ($(date +%s) - $(stat -c %Y "$forkpoint_file" 2>/dev/null || stat -f %m "$forkpoint_file" 2>/dev/null)) / 86400 ))

    if ((forkpoint_age_days > 7)); then
      record_result "CONF-FRESH-002" "forkpoint.toml Age" "Configuration" "Medium" "WARN" \
        "forkpoint.toml is $forkpoint_age_days days old" "$forkpoint_age_days days" "<7 days" \
        "Update forkpoint.toml - stale forkpoints cause sync issues (runbook: old forkpoint)" \
        "fullnode-discussion: stale forkpoint"
    else
      record_result "CONF-FRESH-002" "forkpoint.toml Age" "Configuration" "Medium" "PASS" \
        "forkpoint.toml is $forkpoint_age_days days old" "$forkpoint_age_days days" "<7 days" "" ""
    fi
  else
    record_result "CONF-FRESH-002" "forkpoint.toml Age" "Configuration" "Medium" "SKIP" \
      "forkpoint.toml not found" "" "<7 days" "" ""
  fi
}

test_cruft_script_permissions() {
  local cruft_script="/opt/monad/scripts/clear-old-artifacts.sh"

  if [[ ! -f "$cruft_script" ]]; then
    record_result "CONF-CRUFT-001" "Cruft Script Permissions" "Configuration" "Medium" "SKIP" \
      "Cruft script not found" "" "executable" "" ""
    return
  fi

  if [[ -x "$cruft_script" ]]; then
    record_result "CONF-CRUFT-001" "Cruft Script Permissions" "Configuration" "Medium" "PASS" \
      "Cruft script is executable" "executable" "executable" "" ""
  else
    record_result "CONF-CRUFT-001" "Cruft Script Permissions" "Configuration" "Medium" "FAIL" \
      "Cruft script not executable" "not executable" "executable" \
      "Make executable: chmod +x $cruft_script (prevents cleanup from running)" \
      "validator-discussion: permission denied cruft"
  fi
}

# ============================================================================
# SERVICE TESTS
# ============================================================================

test_service_status() {
  local service="$1"
  local test_id="$2"
  local name="$3"
  local priority="${4:-Critical}"

  if ! command_exists systemctl; then
    record_result "$test_id" "$name" "Service" "$priority" "SKIP" \
      "systemctl not available" "" "running" "" ""
    return
  fi

  local status
  status=$(systemctl is-active "$service" 2>/dev/null || echo "unknown")
  # Clean up whitespace and newlines
  status=$(echo "$status" | tr -d '\n\r' | xargs)

  case "$status" in
    active)
      record_result "$test_id" "$name" "Service" "$priority" "PASS" \
        "$service is running" "running" "running" "" ""
      ;;
    inactive|dead)
      record_result "$test_id" "$name" "Service" "$priority" "FAIL" \
        "$service is not running" "stopped" "running" \
        "Start service with: systemctl start $service" ""
      ;;
    failed)
      record_result "$test_id" "$name" "Service" "$priority" "FAIL" \
        "$service has failed" "failed" "running" \
        "Check logs: journalctl -u $service -n 100" ""
      ;;
    *)
      record_result "$test_id" "$name" "Service" "$priority" "INFO" \
        "$service status: $status" "$status" "running" "" ""
      ;;
  esac
}

test_service_restart_count() {
  local service="$1"
  local test_id="$2"

  if ! command_exists systemctl; then
    record_result "$test_id" "Service Restart Count" "Service" "Medium" "SKIP" \
      "systemctl not available" "" "<5/hour" "" ""
    return
  fi

  # Get service status with restart count
  local restart_info
  restart_info=$(systemctl show "$service" -p NRestarts 2>/dev/null)

  if [[ -z "$restart_info" ]]; then
    record_result "$test_id" "$service Restart Count" "Service" "Medium" "SKIP" \
      "Unable to get restart count" "" "<5/hour" "" ""
    return
  fi

  local restart_count
  restart_count=$(echo "$restart_info" | cut -d'=' -f2)

  if ((restart_count > 5)); then
    record_result "$test_id" "$service Restart Count" "Service" "Medium" "WARN" \
      "$service has restarted $restart_count times" "$restart_count" "<5" \
      "Service crash loop detected - check logs for root cause" ""
  else
    record_result "$test_id" "$service Restart Count" "Service" "Medium" "PASS" \
      "$service restart count: $restart_count" "$restart_count" "<5" "" ""
  fi
}

test_service_enabled() {
  local service="$1"
  local test_id="$2"

  if ! command_exists systemctl; then
    record_result "$test_id" "$service Auto-start" "Service" "Medium" "SKIP" \
      "systemctl not available" "" "enabled" "" ""
    return
  fi

  local enabled_status
  enabled_status=$(systemctl is-enabled "$service" 2>/dev/null || echo "disabled")
  enabled_status=$(echo "$enabled_status" | tr -d '\n\r' | xargs)

  if [[ "$enabled_status" == "enabled" ]]; then
    record_result "$test_id" "$service Auto-start" "Service" "Medium" "PASS" \
      "$service will start on boot" "enabled" "enabled" "" ""
  else
    record_result "$test_id" "$service Auto-start" "Service" "Medium" "WARN" \
      "$service not enabled for auto-start" "$enabled_status" "enabled" \
      "Enable with: systemctl enable $service" ""
  fi
}

test_monad_cruft_timer() {
  if ! command_exists systemctl; then
    record_result "SVC-CRUFT-001" "Monad Cruft Timer" "Service" "Medium" "SKIP" \
      "systemctl not available" "" "active" "" ""
    return
  fi

  local timer_status
  timer_status=$(systemctl is-active monad-cruft.timer 2>/dev/null || echo "inactive")
  timer_status=$(echo "$timer_status" | tr -d '\n\r' | xargs)

  if [[ "$timer_status" == "active" ]]; then
    record_result "SVC-CRUFT-001" "Monad Cruft Timer" "Service" "Medium" "PASS" \
      "monad-cruft timer is active (hourly cleanup)" "active" "active" "" ""
  else
    record_result "SVC-CRUFT-001" "Monad Cruft Timer" "Service" "Medium" "WARN" \
      "monad-cruft timer not active" "$timer_status" "active" \
      "Start timer with: systemctl start monad-cruft.timer && systemctl enable monad-cruft.timer" ""
  fi
}

# ============================================================================
# SYNC STATUS TESTS
# ============================================================================

test_block_number() {
  local block_num
  block_num=$(rpc_call "eth_blockNumber")

  if [[ -z "$block_num" ]]; then
    record_result "SYNC-001" "Block Number" "Sync" "Critical" "WARN" \
      "Unable to query block number (RPC unavailable)" "" ">0" \
      "Check if monad-rpc service is running and port 8080 is accessible" ""
    return
  fi

  # Convert hex to decimal if needed
  if [[ "$block_num" =~ ^0x ]]; then
    block_num=$((block_num))
  fi

  if ((block_num > 0)); then
    record_result "SYNC-001" "Block Number" "Sync" "Critical" "PASS" \
      "Current block: $block_num" "$block_num" ">0" "" ""
  else
    record_result "SYNC-001" "Block Number" "Sync" "Critical" "FAIL" \
      "Block number is 0 or very low" "$block_num" ">0" \
      "Node not syncing - check service logs and network connectivity" ""
  fi
}

test_sync_status() {
  # Try to get statesync status from metrics
  local statesync_syncing
  statesync_syncing=$(get_metric "monad_statesync_syncing")

  if [[ "$statesync_syncing" == "1" ]]; then
    record_result "SYNC-004" "Sync Status" "Sync" "High" "INFO" \
      "Node is currently state syncing" "syncing" "" "" ""
  elif [[ "$statesync_syncing" == "0" ]]; then
    record_result "SYNC-004" "Sync Status" "Sync" "High" "INFO" \
      "Node is live (not state syncing)" "live" "" "" ""
  else
    # Fallback to RPC
    local syncing
    syncing=$(rpc_call "eth_syncing")

    if [[ "$syncing" == "false" ]]; then
      record_result "SYNC-004" "Sync Status" "Sync" "High" "INFO" \
        "eth_syncing reports not syncing" "not syncing" "" "" ""
    elif [[ -n "$syncing" ]]; then
      record_result "SYNC-004" "Sync Status" "Sync" "High" "INFO" \
        "Node is syncing" "syncing" "" "" ""
    else
      record_result "SYNC-004" "Sync Status" "Sync" "High" "SKIP" \
        "Unable to determine sync status" "" "" "" ""
    fi
  fi
}

test_statesync_progress() {
  local progress target
  progress=$(get_metric "monad_statesync_progress_estimate")
  target=$(get_metric "monad_statesync_last_target")

  if [[ -z "$progress" || -z "$target" ]]; then
    record_result "SYNC-STATE-001" "StateSync Progress" "Sync" "Medium" "SKIP" \
      "StateSync metrics unavailable" "" "" "" ""
    return
  fi

  if ((target == 0)); then
    record_result "SYNC-STATE-001" "StateSync Progress" "Sync" "Medium" "INFO" \
      "StateSync not active" "not active" "" "" ""
    return
  fi

  local pct
  pct=$(awk -v p="$progress" -v t="$target" 'BEGIN {printf "%.2f", (p/t)*100}')

  record_result "SYNC-STATE-001" "StateSync Progress" "Sync" "Medium" "INFO" \
    "StateSync: $progress/$target (${pct}%)" "${pct}%" "" "" ""
}

test_rpc_response() {
  if ! command_exists curl; then
    record_result "SYNC-RPC-001" "RPC Response" "Sync" "High" "SKIP" \
      "curl not available" "" "responsive" "" ""
    return
  fi

  # Test web3_clientVersion RPC call
  local client_version
  client_version=$(rpc_call "web3_clientVersion")

  if [[ -n "$client_version" && "$client_version" != "null" ]]; then
    record_result "SYNC-RPC-001" "RPC Response" "Sync" "High" "PASS" \
      "RPC responsive: $client_version" "$client_version" "responsive" "" ""
  else
    record_result "SYNC-RPC-001" "RPC Response" "Sync" "High" "FAIL" \
      "RPC not responding to queries" "not responsive" "responsive" \
      "Check if monad-rpc service is running and healthy" ""
  fi
}

test_metrics_endpoint() {
  if ! command_exists curl; then
    record_result "SYNC-MET-001" "Metrics Endpoint" "Sync" "Medium" "SKIP" \
      "curl not available" "" "accessible" "" ""
    return
  fi

  local metrics_response
  metrics_response=$(safe_exec "curl -s --max-time 2 http://localhost:8889/metrics" | head -5)

  if [[ -n "$metrics_response" ]]; then
    record_result "SYNC-MET-001" "Metrics Endpoint" "Sync" "Medium" "PASS" \
      "Metrics endpoint responding" "accessible" "accessible" "" ""
  else
    record_result "SYNC-MET-001" "Metrics Endpoint" "Sync" "Medium" "WARN" \
      "Metrics endpoint not accessible" "not accessible" "accessible" \
      "Check if otelcol service is running - required for monitoring" ""
  fi
}

# ============================================================================
# SECURITY TESTS
# ============================================================================

test_firewall_enabled() {
  local firewall_status="none"

  if command_exists ufw; then
    if safe_exec "ufw status" | grep -q "Status: active"; then
      firewall_status="ufw active"
    fi
  elif command_exists iptables; then
    local rule_count
    rule_count=$(safe_exec "iptables -L INPUT" | wc -l)
    if ((rule_count > 5)); then
      firewall_status="iptables configured"
    fi
  fi

  if [[ "$firewall_status" == "none" ]]; then
    record_result "SEC-FW-001" "Firewall Status" "Security" "High" "WARN" \
      "No firewall detected" "none" "active" \
      "Enable firewall (ufw or iptables) for security" ""
  else
    record_result "SEC-FW-001" "Firewall Status" "Security" "High" "PASS" \
      "Firewall active: $firewall_status" "$firewall_status" "active" "" ""
  fi
}

test_service_user() {
  if ! command_exists systemctl; then
    record_result "SEC-SEC-001" "Service User" "Security" "Medium" "SKIP" \
      "systemctl not available" "" "non-root" "" ""
    return
  fi

  local running_as_root=false

  for service in monad-mpt monad-bft monad-execution; do
    local user
    user=$(systemctl show "$service" -p User 2>/dev/null | cut -d'=' -f2)

    if [[ "$user" == "root" || -z "$user" ]]; then
      running_as_root=true
      break
    fi
  done

  if [[ "$running_as_root" == "true" ]]; then
    record_result "SEC-SEC-001" "Service User" "Security" "Medium" "WARN" \
      "Services running as root" "root" "non-root" \
      "Services should run as monad user, not root (security risk)" ""
  else
    record_result "SEC-SEC-001" "Service User" "Security" "Medium" "PASS" \
      "Services running as non-root user" "non-root" "non-root" "" ""
  fi
}

# ============================================================================
# LOG ANALYSIS TESTS
# ============================================================================

test_journal_errors() {
  if ! command_exists journalctl; then
    record_result "DIAG-LOG-001" "Journal Error Analysis" "Diagnostics" "Medium" "SKIP" \
      "journalctl not available" "" "" "" ""
    return
  fi

  local error_patterns=(
    "assertion.*failed"
    "panic"
    "fatal error"
    "segmentation fault"
  )

  local found_errors=()

  for service in monad-mpt monad-bft monad-execution; do
    for pattern in "${error_patterns[@]}"; do
      local count
      count=$(safe_exec "journalctl -u $service -n 1000 --no-pager" | grep -ciE "$pattern" || echo "0")
      # Strip whitespace and newlines
      count=$(echo "$count" | tr -d '\n\r' | xargs)

      if [[ -n "$count" ]] && ((count > 0)); then
        found_errors+=("$service: $pattern ($count)")
      fi
    done
  done

  if ((${#found_errors[@]} == 0)); then
    record_result "DIAG-LOG-001" "Journal Error Analysis" "Diagnostics" "Medium" "PASS" \
      "No critical errors in recent logs" "no errors" "no errors" "" ""
  else
    local errors_str="${found_errors[*]}"
    record_result "DIAG-LOG-001" "Journal Error Analysis" "Diagnostics" "Medium" "WARN" \
      "Critical errors found: ${errors_str:0:100}" "errors found" "no errors" \
      "Review service logs with: journalctl -u <service> -n 100" ""
  fi
}

# ============================================================================
# MAIN TEST EXECUTION
# ============================================================================

run_all_tests() {
  log_verbose "Starting diagnostic tests..."

  # Prerequisites Tests
  if [[ -z "$FILTER_CATEGORY" || "$FILTER_CATEGORY" == "Prerequisites" ]]; then
    echo ""
    print_color "$COLOR_BOLD_PURPLE" "╔════════════════════════════════════════════════════════════════╗"
    print_color "$COLOR_BOLD_PURPLE" "║               Prerequisites Tests                              ║"
    print_color "$COLOR_BOLD_PURPLE" "╚════════════════════════════════════════════════════════════════╝"
    test_required_tools
  fi

  # Hardware Tests
  if [[ -z "$FILTER_CATEGORY" || "$FILTER_CATEGORY" == "Hardware" ]]; then
    echo ""
    print_color "$COLOR_BOLD_PURPLE" "╔════════════════════════════════════════════════════════════════╗"
    print_color "$COLOR_BOLD_PURPLE" "║                  Hardware Tests                                ║"
    print_color "$COLOR_BOLD_PURPLE" "╚════════════════════════════════════════════════════════════════╝"
    test_cpu_cores
    test_hyperthreading
    test_thermal_throttling
    test_cpu_governor
    test_memory_capacity
    test_memory_available
    test_oom_events
    test_environment_type
    test_os_version
    test_kernel_version
  fi

  # Storage Tests
  if [[ -z "$FILTER_CATEGORY" || "$FILTER_CATEGORY" == "Storage" ]]; then
    echo ""
    print_color "$COLOR_BOLD_PURPLE" "╔════════════════════════════════════════════════════════════════╗"
    print_color "$COLOR_BOLD_PURPLE" "║                   Storage Tests                                ║"
    print_color "$COLOR_BOLD_PURPLE" "╚════════════════════════════════════════════════════════════════╝"
    test_nvme_count
    test_triedb_device
    test_nvme_lba_format
    test_triedb_capacity
    test_mpt_initialization
    test_nvme_model
    test_disk_space
  fi

  # Network Tests
  if [[ -z "$FILTER_CATEGORY" || "$FILTER_CATEGORY" == "Network" ]]; then
    echo ""
    print_color "$COLOR_BOLD_PURPLE" "╔════════════════════════════════════════════════════════════════╗"
    print_color "$COLOR_BOLD_PURPLE" "║                   Network Tests                                ║"
    print_color "$COLOR_BOLD_PURPLE" "╚════════════════════════════════════════════════════════════════╝"
    test_internet_connectivity
    test_bootstrap_peer_connectivity
    test_port_8000_listening
    test_firewall_port_8000
    test_self_address_config
    test_bind_address_port
    test_name_record_signature
    test_peer_count
    test_port_8080_exposure
  fi

  # Configuration Tests
  if [[ -z "$FILTER_CATEGORY" || "$FILTER_CATEGORY" == "Configuration" ]]; then
    echo ""
    print_color "$COLOR_BOLD_PURPLE" "╔════════════════════════════════════════════════════════════════╗"
    print_color "$COLOR_BOLD_PURPLE" "║                Configuration Tests                             ║"
    print_color "$COLOR_BOLD_PURPLE" "╚════════════════════════════════════════════════════════════════╝"
    test_monad_user_exists
    test_config_files_exist
    test_node_toml_syntax
    test_beneficiary_config
    test_enable_client_config
    test_node_name
    test_keystore_files
    test_keystore_backups
    test_env_variables
    test_remote_config_urls
    test_hugetlbfs_event_rings
    test_config_file_freshness
    test_cruft_script_permissions
  fi

  # Service Tests
  if [[ -z "$FILTER_CATEGORY" || "$FILTER_CATEGORY" == "Service" ]]; then
    echo ""
    print_color "$COLOR_BOLD_PURPLE" "╔════════════════════════════════════════════════════════════════╗"
    print_color "$COLOR_BOLD_PURPLE" "║                   Service Tests                                ║"
    print_color "$COLOR_BOLD_PURPLE" "╚════════════════════════════════════════════════════════════════╝"
    test_service_status "monad-mpt" "SVC-001" "monad-mpt Service" "Critical"
    test_service_status "monad-bft" "SVC-002" "monad-bft Service" "Critical"
    test_service_status "monad-execution" "SVC-003" "monad-execution Service" "Critical"
    test_service_status "monad-rpc" "SVC-004" "monad-rpc Service" "High"
    test_service_status "otelcol" "SVC-005" "otelcol Service" "Medium"
    test_monad_cruft_timer
    test_service_restart_count "monad-mpt" "SVC-007a"
    test_service_restart_count "monad-bft" "SVC-007b"
    test_service_restart_count "monad-execution" "SVC-007c"
    test_service_enabled "monad-bft" "SVC-008a"
    test_service_enabled "monad-execution" "SVC-008b"
    test_service_enabled "monad-rpc" "SVC-008c"
  fi

  # Sync Status Tests
  if [[ -z "$FILTER_CATEGORY" || "$FILTER_CATEGORY" == "Sync" ]]; then
    echo ""
    print_color "$COLOR_BOLD_PURPLE" "╔════════════════════════════════════════════════════════════════╗"
    print_color "$COLOR_BOLD_PURPLE" "║                 Sync Status Tests                              ║"
    print_color "$COLOR_BOLD_PURPLE" "╚════════════════════════════════════════════════════════════════╝"
    test_block_number
    test_sync_status
    test_statesync_progress
    test_rpc_response
    test_metrics_endpoint
  fi

  # Security Tests
  if [[ -z "$FILTER_CATEGORY" || "$FILTER_CATEGORY" == "Security" ]]; then
    echo ""
    print_color "$COLOR_BOLD_PURPLE" "╔════════════════════════════════════════════════════════════════╗"
    print_color "$COLOR_BOLD_PURPLE" "║                   Security Tests                               ║"
    print_color "$COLOR_BOLD_PURPLE" "╚════════════════════════════════════════════════════════════════╝"
    test_firewall_enabled
    test_service_user
  fi

  # Diagnostic Tests
  if [[ -z "$FILTER_CATEGORY" || "$FILTER_CATEGORY" == "Diagnostics" ]]; then
    echo ""
    print_color "$COLOR_BOLD_PURPLE" "╔════════════════════════════════════════════════════════════════╗"
    print_color "$COLOR_BOLD_PURPLE" "║                 Diagnostic Tests                               ║"
    print_color "$COLOR_BOLD_PURPLE" "╚════════════════════════════════════════════════════════════════╝"
    test_journal_errors
  fi

  log_verbose "All tests completed"
}

# ============================================================================
# OUTPUT FORMATTING
# ============================================================================

print_summary() {
  if [[ "$OUTPUT_MODE" == "json" ]]; then
    # JSON output
    echo "{"
    echo "  \"version\": \"$VERSION\","
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"summary\": {"
    echo "    \"total\": ${TEST_COUNTS[total]},"
    echo "    \"pass\": ${TEST_COUNTS[pass]},"
    echo "    \"warn\": ${TEST_COUNTS[warn]},"
    echo "    \"fail\": ${TEST_COUNTS[fail]},"
    echo "    \"info\": ${TEST_COUNTS[info]},"
    echo "    \"skip\": ${TEST_COUNTS[skip]}"
    echo "  },"
    echo "  \"results\": ["

    local first=true
    for result in "${TEST_RESULTS[@]}"; do
      if [[ "$first" == "true" ]]; then
        first=false
      else
        echo ","
      fi
      echo -n "    $result"
    done
    echo ""
    echo "  ]"
    echo "}"
  else
    # Human-readable summary
    local runtime=$(($(date +%s) - SCRIPT_START_TIME))

    echo ""
    print_color "$COLOR_BOLD_PURPLE" "╔════════════════════════════════════════════════════════════════╗"
    print_color "$COLOR_BOLD_PURPLE" "║                    DIAGNOSTIC SUMMARY                          ║"
    print_color "$COLOR_BOLD_PURPLE" "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    printf "  ${COLOR_DIM}Total tests:${COLOR_RESET}       ${COLOR_BOLD}%s${COLOR_RESET}\n" "${TEST_COUNTS[total]}"
    printf "  ${COLOR_GREEN}✓ Passed:${COLOR_RESET}          ${COLOR_BOLD}%s${COLOR_RESET}\n" "${TEST_COUNTS[pass]}"
    printf "  ${COLOR_YELLOW}⚠ Warnings:${COLOR_RESET}        ${COLOR_BOLD}%s${COLOR_RESET}\n" "${TEST_COUNTS[warn]}"
    printf "  ${COLOR_RED}✗ Failed:${COLOR_RESET}          ${COLOR_BOLD}%s${COLOR_RESET}\n" "${TEST_COUNTS[fail]}"
    printf "  ${COLOR_PURPLE}ℹ Informational:${COLOR_RESET}   ${COLOR_BOLD}%s${COLOR_RESET}\n" "${TEST_COUNTS[info]}"
    printf "  ${COLOR_DIM}⊘ Skipped:${COLOR_RESET}         ${COLOR_BOLD}%s${COLOR_RESET}\n" "${TEST_COUNTS[skip]}"
    echo ""
    printf "  ${COLOR_DIM}Runtime:${COLOR_RESET}           ${COLOR_BOLD}%ss${COLOR_RESET}\n" "$runtime"
    echo ""

    # Overall status
    print_color "$COLOR_BOLD_PURPLE" "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    if ((TEST_COUNTS[fail] > 0)); then
      printf "  ${COLOR_RED}${COLOR_BOLD}⚠ Overall Status: CRITICAL${COLOR_RESET}\n"
      printf "  ${COLOR_RED}%s test(s) failed${COLOR_RESET}\n" "${TEST_COUNTS[fail]}"
      echo ""
      printf "  ${COLOR_DIM}→ Action required: Fix critical failures immediately${COLOR_RESET}\n"
    elif ((TEST_COUNTS[warn] > 0)); then
      printf "  ${COLOR_YELLOW}${COLOR_BOLD}⚠ Overall Status: DEGRADED${COLOR_RESET}\n"
      printf "  ${COLOR_YELLOW}%s warning(s) detected${COLOR_RESET}\n" "${TEST_COUNTS[warn]}"
      echo ""
      printf "  ${COLOR_DIM}→ Action recommended: Address warnings to prevent issues${COLOR_RESET}\n"
    else
      printf "  ${COLOR_GREEN}${COLOR_BOLD}✓ Overall Status: HEALTHY${COLOR_RESET}\n"
      echo ""
      printf "  ${COLOR_DIM}→ Node appears to be configured correctly${COLOR_RESET}\n"
    fi

    echo ""
    print_color "$COLOR_BOLD_PURPLE" "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
  fi
}

# ============================================================================
# CLI ARGUMENT PARSING
# ============================================================================

print_usage() {
  cat <<EOF
monad-doctor v$VERSION - Diagnostic tool for Monad node operators

Usage: monad-doctor [OPTIONS]

Options:
  --category CATEGORY    Run only tests in category (Prerequisites, Hardware, Storage, Network, Configuration, Service, Sync, Security, Diagnostics)
  --priority PRIORITY    Run only tests with priority (Critical, High, Medium, Low)
  --json                 Output in JSON format
  --verbose              Enable verbose debug output
  --help                 Show this help message
  --version              Show version

Examples:
  monad-doctor                      # Run all tests
  monad-doctor --category Hardware  # Hardware tests only
  monad-doctor --priority Critical  # Critical tests only
  monad-doctor --json               # JSON output for automation

Exit codes:
  0 - Healthy (no warnings or failures)
  1 - Warnings (some non-critical issues)
  2 - Critical (one or more critical failures)

EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --category)
        FILTER_CATEGORY="$2"
        shift 2
        ;;
      --priority)
        FILTER_PRIORITY="$2"
        shift 2
        ;;
      --json)
        OUTPUT_MODE="json"
        shift
        ;;
      --verbose|-v)
        VERBOSE=true
        shift
        ;;
      --help|-h)
        print_usage
        exit 0
        ;;
      --version)
        echo "monad-doctor v$VERSION"
        exit 0
        ;;
      *)
        echo "Unknown option: $1"
        print_usage
        exit 1
        ;;
    esac
  done
}

# ============================================================================
# MAIN
# ============================================================================

print_monad_header() {
  echo ""
  print_color "$COLOR_BOLD_PURPLE" "  ███╗   ███╗ ██████╗ ███╗   ██╗ █████╗ ██████╗ "
  print_color "$COLOR_BOLD_PURPLE" "  ████╗ ████║██╔═══██╗████╗  ██║██╔══██╗██╔══██╗"
  print_color "$COLOR_BOLD_PURPLE" "  ██╔████╔██║██║   ██║██╔██╗ ██║███████║██║  ██║"
  print_color "$COLOR_MAGENTA" "  ██║╚██╔╝██║██║   ██║██║╚██╗██║██╔══██║██║  ██║"
  print_color "$COLOR_MAGENTA" "  ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║  ██║██████╔╝"
  print_color "$COLOR_MAGENTA" "  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ "
  echo ""
  print_color "$COLOR_BOLD_PURPLE" "  ╔══════════════════════════════════════════════════════════════╗"
  printf "  ${COLOR_BOLD_PURPLE}║${COLOR_RESET}                     ${COLOR_BOLD}DOCTOR v%-7s${COLOR_RESET}                    ${COLOR_BOLD_PURPLE}║${COLOR_RESET}\n" "$VERSION"
  printf "  ${COLOR_BOLD_PURPLE}║${COLOR_RESET}            ${COLOR_DIM}Diagnostic Tool for Node Operators${COLOR_RESET}            ${COLOR_BOLD_PURPLE}║${COLOR_RESET}\n"
  print_color "$COLOR_BOLD_PURPLE" "  ╚══════════════════════════════════════════════════════════════╝"
  echo ""
  printf "  ${COLOR_DIM}Starting comprehensive node diagnostics...${COLOR_RESET}\n"
  echo ""
}

main() {
  parse_args "$@"

  if [[ "$OUTPUT_MODE" == "human" ]]; then
    print_monad_header
  fi

  run_all_tests

  print_summary

  # Determine exit code
  if ((TEST_COUNTS[fail] > 0)); then
    exit $EXIT_CRITICAL
  elif ((TEST_COUNTS[warn] > 0)); then
    exit $EXIT_WARNINGS
  else
    exit $EXIT_HEALTHY
  fi
}

main "$@"
