#!/bin/bash

# Set colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default file path
DEFAULT_FILE="/opt/tmp/hello"

# Check if file path was provided
if [ $# -eq 0 ]; then
    TARGET_FILE="$DEFAULT_FILE"
    echo -e "${YELLOW}No file path provided, using default: $TARGET_FILE${NC}"
else
    TARGET_FILE="$1"
    echo -e "${GREEN}Using provided file path: $TARGET_FILE${NC}"
fi

# Verify the file exists
if [ ! -f "$TARGET_FILE" ]; then
    echo -e "${YELLOW}Error: File $TARGET_FILE does not exist${NC}"
    exit 1
fi

# Get the start address of main (formatted as 8-digit hex)
echo -e "${BLUE}Running: r2 -qc 'aaaa; s main; s' $TARGET_FILE 2>/dev/null${NC}"
RAW_START_ADDR=$(r2 -qc 'aaaa; s main; s' "$TARGET_FILE" 2>/dev/null)
SNIFFER_START_ADDR=$(printf "0x%08x" "$RAW_START_ADDR")  # Force 8-digit hex format
echo -e "${GREEN}Main function start address: $SNIFFER_START_ADDR${NC}"

# Get the size of main (formatted as 8-digit hex)
echo -e "${BLUE}Running: r2 -qc 'aaaa; afi main~size[1]' $TARGET_FILE 2>/dev/null${NC}"
RAW_FUN_SIZE=$(r2 -qc 'aaaa; afi main~size[1]' "$TARGET_FILE" 2>/dev/null)
SNIFFER_FUN_SIZE=$(printf "0x%08x" "$RAW_FUN_SIZE")  # Force 8-digit hex format
echo -e "${GREEN}Main function size: $SNIFFER_FUN_SIZE bytes${NC}"

# Calculate end address (formatted as 8-digit hex)
SNIFFER_END_ADDR=$(printf "0x%08x" $((RAW_START_ADDR + RAW_FUN_SIZE)))
echo -e "${GREEN}Calculated main function end address: $SNIFFER_END_ADDR${NC}"

# Export the environment variables
export SNIFFER_START_ADDR
export SNIFFER_END_ADDR
export SNIFFER_FUN_SIZE

echo -e "${YELLOW}Environment variables set:${NC}"
echo -e "SNIFFER_START_ADDR=${GREEN}$SNIFFER_START_ADDR${NC}"
echo -e "SNIFFER_END_ADDR=${GREEN}$SNIFFER_END_ADDR${NC}"
echo -e "SNIFFER_FUN_SIZE=${GREEN}$SNIFFER_FUN_SIZE${NC}"