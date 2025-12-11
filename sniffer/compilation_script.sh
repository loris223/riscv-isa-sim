#!/bin/bash

# Color definitions (for user feedback)
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default file (now .c)
DEFAULT_FILE="/opt/tmp/hello.c"

# --- Argument Handling ---
if [ $# -eq 0 ]; then
    TARGET_FILE="$DEFAULT_FILE"
    echo -e "${YELLOW}No file provided, using default: ${GREEN}$TARGET_FILE${NC}" >&2
else
    TARGET_FILE="$1"
fi

# --- File Validation ---
if [ ! -f "$TARGET_FILE" ]; then
    echo -e "${RED}Error: File ${YELLOW}$TARGET_FILE${RED} does not exist${NC}" >&2
    exit 1
fi

# --- Extract Path and Filename ---
source_dir=$(dirname "$TARGET_FILE")
filename=$(basename -- "$TARGET_FILE")
extension="${filename##*.}"
filename_noext="${filename%.*}"
output_path="${source_dir}/${filename_noext}"  # Full output path

# --- Check Extension ---
if [[ "$extension" != "c" && "$extension" != "cpp" ]]; then
    echo -e "${RED}Error: Only .c or .cpp files are supported${NC}" >&2
    exit 1
fi

# --- Compiler Selection ---
COMPILER="riscv32-unknown-elf-$([ "$extension" == "c" ] && echo "gcc" || echo "g++")"

# --- Compilation ---
echo -e "${BLUE}Compiling with: ${GREEN}$COMPILER -o $output_path $TARGET_FILE${NC}" >&2
if $COMPILER -o "$output_path" "$TARGET_FILE"; then
    echo -e "${GREEN}Success! Output file: ${YELLOW}$output_path${NC}" >&2
    # Print full output path for other scripts
    echo "$output_path"
    exit 0
else
    echo -e "${RED}Compilation failed!${NC}" >&2
    exit 1
fi