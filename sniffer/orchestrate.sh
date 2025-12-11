#!/bin/bash

# Since we are setting in extract_addresses script environmental variables
# the script should be called with source command.
# source ./orchestrate.sh

# Color definitions
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default file (matches previous scripts)
DEFAULT_FILE="/opt/tmp/hello.c"

# --- Argument Handling ---
if [ $# -eq 0 ]; then
    TARGET_FILE="$DEFAULT_FILE"
    echo -e "${YELLOW}No file provided, using default: ${GREEN}$TARGET_FILE${NC}" >&2
else
    TARGET_FILE="$1"
fi

# --- Phase 1: Compilation ---
echo -e "${BLUE}=== [1/3] Compiling $TARGET_FILE ===${NC}" >&2
COMPILED_BIN=$(./compilation_script.sh "$TARGET_FILE")
if [ $? -ne 0 ]; then
    echo -e "${RED}Compilation failed! Aborting.${NC}" >&2
    exit 1
fi
echo -e "${GREEN}Compilation successful: ${YELLOW}$COMPILED_BIN${NC}" >&2

# --- Phase 2: Address Extraction ---
echo -e "${BLUE}=== [2/3] Extracting function addresses ===${NC}" >&2
source ./extract_addresses.sh "$COMPILED_BIN" || {
    echo -e "${RED}Address extraction failed! Aborting.${NC}" >&2
    exit 1
}
#echo -e "${GREEN}Addresses set:${NC}" >&2
#echo -e "  START: ${GREEN}$SNIFFER_START_ADDR${NC}" >&2
#echo -e "  END:   ${GREEN}$SNIFFER_END_ADDR${NC}" >&2
#echo -e "  SIZE:  ${GREEN}$SNIFFER_FUN_SIZE${NC}" >&2

# --- Phase 3: Execution ---
echo -e "${BLUE}=== [3/3] Running with Spike ===${NC}" >&2
./runnable_script.sh "$COMPILED_BIN" || {
    echo -e "${RED}Execution failed!${NC}" >&2
    exit 1
}

echo -e "${GREEN}=== All steps completed successfully ===${NC}" >&2