#!/usr/bin/env bash
set -Eeuo pipefail

# ---------- Defaults ----------
MINT_URL="${MINT_URL:-http://localhost:8085}"
CAIRO_EXECUTABLE_PATH="${CAIRO_EXECUTABLE_PATH:-crates/cashu/src/nuts/nutxx/test/is_prime_executable.json}"
AMOUNT_MINT="${AMOUNT_MINT:-1000}"
AMOUNT_TOKEN="${AMOUNT_TOKEN:-200}"
CLI="${CLI:-./target/release/cdk-cli}"
POLL_TIMEOUT_SEC="${POLL_TIMEOUT_SEC:-60}"

# Colors (disabled if NO_COLOR is set)
if [[ -z "${NO_COLOR:-}" ]] && [[ -t 1 ]]; then
  readonly RED='\033[0;31m'
  readonly GREEN='\033[0;32m'
  readonly YELLOW='\033[0;33m'
  readonly BLUE='\033[0;34m'
  readonly PURPLE='\033[0;35m'
  readonly CYAN='\033[0;36m'
  readonly WHITE='\033[1;37m'
  readonly GRAY='\033[0;90m'
  readonly BOLD='\033[1m'
  readonly DIM='\033[2m'
  readonly RESET='\033[0m'
else
  readonly RED='' GREEN='' YELLOW='' BLUE='' PURPLE='' CYAN='' WHITE='' GRAY='' BOLD='' DIM='' RESET=''
fi

# Unicode symbols
readonly CHECK_MARK="✅"
readonly CROSS_MARK="❌"
readonly HOURGLASS="⏳"
readonly LIGHTNING="⚡"
readonly GEAR="⚙️"
readonly ROCKET="🚀"
readonly TARGET="🎯"

usage() {
  cat <<EOF
${BOLD}${BLUE}Cairo CLI Integration Test${RESET}

${BOLD}Usage:${RESET} $0 [URL] [options]

${BOLD}Positional:${RESET}
  ${WHITE}URL${RESET}                         Mint URL (e.g. http://localhost:8085)

${BOLD}Options:${RESET}
  ${WHITE}-m, --mint URL${RESET}              Mint URL (overrides positional)
  ${WHITE}    --amount-mint N${RESET}         Amount to mint (sats)      [default: ${CYAN}$AMOUNT_MINT${RESET}]
  ${WHITE}    --amount-token N${RESET}        Amount to send/receive     [default: ${CYAN}$AMOUNT_TOKEN${RESET}]
  ${WHITE}    --cli PATH${RESET}              Path to cdk-cli binary     [default: ${CYAN}$CLI${RESET}]
  ${WHITE}    --cairo PATH${RESET}            Path to Cairo JSON         [default: ${CYAN}$CAIRO_EXECUTABLE_PATH${RESET}]
  ${WHITE}-h, --help${RESET}                  Show this help

${BOLD}Examples:${RESET}
  $0                                    # Use defaults
  $0 http://localhost:8085              # Specify mint URL
  $0 --amount-mint 2000 --amount-token 500  # Custom amounts
EOF
}

# ---------- Args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -m|--mint) MINT_URL="$2"; shift 2 ;;
    --amount-mint) AMOUNT_MINT="$2"; shift 2 ;;
    --amount-token) AMOUNT_TOKEN="$2"; shift 2 ;;
    --cli) CLI="$2"; shift 2 ;;
    --cairo|--cairo-executable) CAIRO_EXECUTABLE_PATH="$2"; shift 2 ;;
    http*://*) MINT_URL="$1"; shift ;;
    *) echo "${RED}Unknown argument: $1${RESET}" >&2; usage; exit 1 ;;
  esac
done

# ---------- Nix wrap ----------
if [[ -z "${IN_NIX_SHELL:-}" ]] && command -v nix >/dev/null 2>&1; then
  echo "${YELLOW}${GEAR} Entering nix shell...${RESET}"
  exec nix develop -c "$0" "$@"
fi

# ---------- Utils ----------
log() { 
  printf "${GRAY}[%s]${RESET} %s\n" "$(date '+%H:%M:%S')" "$*"
}

success() {
  printf "${GREEN}${CHECK_MARK} %s${RESET}\n" "$*"
}

error() {
  printf "${RED}${CROSS_MARK} %s${RESET}\n" "$*"
}

info() {
  printf "${BLUE}${GEAR} %s${RESET}\n" "$*"
}

warn() {
  printf "${YELLOW}⚠️  %s${RESET}\n" "$*"
}

progress() {
  printf "${CYAN}${HOURGLASS} %s${RESET}\n" "$*"
}

die() { 
  error "$*"
  exit 1
}

need() { 
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: ${WHITE}$1${RESET}"
}

into() { 
  while IFS= read -r line; do
    printf "    ${DIM}%s${RESET}\n" "$line"
  done
}

extract_token() { 
  awk '/^cashu/{print; exit}'
}

received_amount() { 
  sed -n 's/^Received:[[:space:]]*//p' | tr -d '\r' | sed 's/[[:space:]]*$//'
}

pay_invoice_non_interactive() {
  local inv="$1"
  if command -v script >/dev/null 2>&1; then
    case "$(uname -s)" in
      Darwin) script -q /dev/null bash -lc "yes yes | just ln-lnd1 payinvoice \"$inv\"" ;;
      Linux)  script -qfc "yes yes | just ln-lnd1 payinvoice \"$inv\"" /dev/null ;;
      *)      script -q /dev/null sh  -c  "yes yes | just ln-lnd1 payinvoice \"$inv\"" ;;
    esac
  else
    yes yes | just ln-lnd1 payinvoice "$inv"
  fi
}

section() {
  echo
  printf "${BOLD}${WHITE}╭─────────────────────────────────────────────────────────────╮${RESET}\n"
  printf "${BOLD}${WHITE}│ %-59s │${RESET}\n" "$*"
  printf "${BOLD}${WHITE}╰─────────────────────────────────────────────────────────────╯${RESET}\n"
  echo
}

test_header() {
  local test_num="$1"
  local test_name="$2"
  echo
  printf "${BOLD}${PURPLE}${TARGET} Test ${test_num}: ${test_name}${RESET}\n"
  printf "${GRAY}%*s${RESET}\n" 60 | tr ' ' '─'
}

# Cleanup background jobs if we exit early
mint_pid="" pay_pid=""
cleanup() {
  [[ -n "$mint_pid" ]] && kill "$mint_pid" 2>/dev/null || true
  [[ -n "$pay_pid"  ]] && kill "$pay_pid"  2>/dev/null || true
}
trap cleanup EXIT

# ---------- Welcome & Setup ----------
clear
cat << 'EOF'
 ██████╗ █████╗ ██╗██████╗  ██████╗      ██████╗██╗     ██╗
██╔════╝██╔══██╗██║██╔══██╗██╔═══██╗    ██╔════╝██║     ██║
██║     ███████║██║██████╔╝██║   ██║    ██║     ██║     ██║
██║     ██╔══██║██║██╔══██╗██║   ██║    ██║     ██║     ██║
╚██████╗██║  ██║██║██║  ██║╚██████╔╝    ╚██████╗███████╗██║
 ╚═════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝      ╚═════╝╚══════╝╚═╝
EOF

echo
printf "${BOLD}${BLUE}Integration Test Suite${RESET}\n"
printf "${DIM}Testing Cairo proof functionality in CDK CLI${RESET}\n"
echo

# ---------- Preconditions ----------
info "Checking prerequisites..."
need awk; need sed; need just; need tee; need grep; need mktemp
[[ -x "$CLI" ]] || die "Binary not found at ${WHITE}$CLI${RESET}"

echo
printf "${BOLD}Configuration:${RESET}\n"
printf "  ${WHITE}Mint URL:${RESET}      ${CYAN}%s${RESET}\n" "$MINT_URL"
printf "  ${WHITE}CLI Binary:${RESET}    ${CYAN}%s${RESET}\n" "$CLI"
printf "  ${WHITE}Cairo JSON:${RESET}    ${CYAN}%s${RESET}\n" "$CAIRO_EXECUTABLE_PATH"
printf "  ${WHITE}Mint Amount:${RESET}   ${CYAN}%s${RESET} sats\n" "$AMOUNT_MINT"
printf "  ${WHITE}Token Amount:${RESET}  ${CYAN}%s${RESET} sats\n" "$AMOUNT_TOKEN"

# ---------- 1) Mint & pay (concurrent) ----------
section "${LIGHTNING} Minting ${AMOUNT_MINT} sats and paying invoice"

progress "Creating mint quote..."
mint_log="$(mktemp)"
( "$CLI" mint "$MINT_URL" "$AMOUNT_MINT" 2>&1 | tee "$mint_log" ) &
mint_pid=$!

progress "Waiting for invoice..."
invoice=""
spinner_chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
for i in {1..300}; do
  if line="$(grep -m1 '^Please pay: ' "$mint_log" 2>/dev/null || true)"; then
    invoice="${line#Please pay: }"
    [[ -n "$invoice" ]] && break
  fi
  if [[ $((i % 5)) -eq 0 ]]; then
    char_idx=$((i / 5 % ${#spinner_chars}))
    printf "\r${CYAN}${spinner_chars:$char_idx:1} Waiting for invoice... (${i}/300)${RESET}"
  fi
  sleep 0.2
done

if [[ -n "$invoice" ]]; then
  printf "\r${GREEN}${CHECK_MARK} Invoice received!${RESET}%*s\n" 20 ""
else
  kill "$mint_pid" 2>/dev/null || true
  die "Mint didn't generate an invoice"
fi

progress "Paying invoice automatically..."
pay_invoice_non_interactive "$invoice" >/dev/null 2>&1 & pay_pid=$!

progress "Waiting for mint completion..."
if wait "$mint_pid"; then
  success "Mint successful!"
else
  die "Mint command failed"
fi

if wait "$pay_pid"; then
  success "Payment completed!"
else
  warn "Payment process finished with warnings (this may be normal)"
fi

# ---------- 2) Test 1: Happy path ----------
test_header "1" "Cairo send + receive with prime proof (11)"

progress "Creating Cairo token with spending condition..."
SEND_OUT="$(printf "0\n%s\n" "$AMOUNT_TOKEN" | "$CLI" send \
  --cairo-executable "$CAIRO_EXECUTABLE_PATH" \
  --cairo-executable 1 \
  --cairo-executable 1 2>&1)" || die "Cairo send failed"

printf '%s\n' "$SEND_OUT" | into

TOKEN="$(printf '%s\n' "$SEND_OUT" | extract_token)"
[[ -n "$TOKEN" ]] || die "Failed to extract token from send output"

info "Token created successfully"
progress "Attempting to receive with prime proof (input: 11)..."

set +e
RECV_OUT="$("$CLI" receive --cairo "$CAIRO_EXECUTABLE_PATH" 1 11 -- "$TOKEN" 2>&1)"
RECV_CODE=$?
set -e

echo "${DIM}Receive output:${RESET}"
printf '%s\n' "$RECV_OUT" | into

AMT="$(printf '%s\n' "$RECV_OUT" | received_amount)"
if [[ $RECV_CODE -eq 0 && "${AMT:-0}" -eq "$AMOUNT_TOKEN" ]]; then
  success "Test 1 PASSED - Successfully received ${AMT} sats with prime proof!"
else
  die "Test 1 FAILED - Expected success with ${AMOUNT_TOKEN} sats (got exit=$RECV_CODE, received=${AMT:-<none>})"
fi

# ---------- 3) Test 2: Non-prime should be rejected ----------
test_header "2" "Cairo receive with non-prime input (9) should fail"

progress "Creating another Cairo token..."
SEND_OUT_NP="$(printf "0\n%s\n" "$AMOUNT_TOKEN" | "$CLI" send \
  --cairo-executable "$CAIRO_EXECUTABLE_PATH" \
  --cairo-executable 1 \
  --cairo-executable 1 2>&1)" || die "Cairo send (non-prime test) failed"

printf '%s\n' "$SEND_OUT_NP" | into

TOKEN_NP="$(printf '%s\n' "$SEND_OUT_NP" | extract_token)"
[[ -n "$TOKEN_NP" ]] || die "Failed to extract token (non-prime test)"

info "Token created successfully"
progress "Attempting to receive with non-prime proof (input: 9)..."

set +e
RECV_OUT_NP="$("$CLI" receive --cairo "$CAIRO_EXECUTABLE_PATH" 1 9 -- "$TOKEN_NP" 2>&1)"
RECV_CODE_NP=$?
set -e

echo "${DIM}Receive output:${RESET}"
printf '%s\n' "$RECV_OUT_NP" | into

AMT_NP="$(printf '%s\n' "$RECV_OUT_NP" | received_amount 2>/dev/null || true)"
if [[ $RECV_CODE_NP -eq 0 && -n "$AMT_NP" ]]; then
  die "Test 2 FAILED - Expected rejection for non-prime 9, but received ${AMT_NP} sats"
else
  success "Test 2 PASSED - Correctly rejected non-prime input!"
fi

trap - EXIT

# ---------- Final Results ----------
echo
printf "${BOLD}${WHITE}╭─────────────────────────────────────────────────────────────╮${RESET}\n"
printf "${BOLD}${WHITE}│${RESET}  ${BOLD}${GREEN}${ROCKET} ALL TESTS PASSED SUCCESSFULLY!${RESET}                     ${BOLD}${WHITE}│${RESET}\n"
printf "${BOLD}${WHITE}│${RESET}                                                           ${BOLD}${WHITE}│${RESET}\n"
printf "${BOLD}${WHITE}│${RESET}  ${GREEN}${CHECK_MARK} Cairo proof validation working correctly${RESET}            ${BOLD}${WHITE}│${RESET}\n"
printf "${BOLD}${WHITE}│${RESET}  ${GREEN}${CHECK_MARK} Prime number verification functional${RESET}               ${BOLD}${WHITE}│${RESET}\n"
printf "${BOLD}${WHITE}│${RESET}  ${GREEN}${CHECK_MARK} Non-prime rejection working as expected${RESET}            ${BOLD}${WHITE}│${RESET}\n"
printf "${BOLD}${WHITE}╰─────────────────────────────────────────────────────────────╯${RESET}\n"
echo

printf "${DIM}Test completed at $(date)${RESET}\n"