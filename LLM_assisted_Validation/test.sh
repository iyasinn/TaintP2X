#!/bin/bash
# --------------------------
# Configuration
# --------------------------
WORK_DIR="${1}"      # project working directory
ISSUE_NUMBER="${2}"  # issue number to inspect in `sapp explore`
PYSARUNS="${3}"      # project/log namespace

TAINT_FILE="./taint-output.json"  # 污点分析输出文件
DB_NAME="sapp.db"                # 分析数据库名称
LOG_FILE="sapp_interaction.log"  # 全局日志文件

# Validate required args
if [ -z "$PYSARUNS" ] || [ -z "$ISSUE_NUMBER" ]; then
    echo "Error: missing required arguments."
    echo "Usage: $0 <work_dir> <issue_number> <project_name>"
    echo "Example: $0 /path/to/repo/project 1 litellm-1.40.12"
    exit 1
fi

# Derive output directory in this repository (portable path, no hardcoded home dir)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/logs/log_zhipu/${PYSARUNS}/${ISSUE_NUMBER}"
mkdir -p "$OUTPUT_DIR"

# --------------------------
# Stage 1: static analysis
# --------------------------
echo "[Stage 1] Running static analysis..." | tee -a "$LOG_FILE"
cd "$WORK_DIR" || exit 1

# Run SAPP analyze and tee logs to terminal+file
sapp analyze "$TAINT_FILE" 2>&1 | tee -a "$LOG_FILE"

# --------------------------
# Stage 2: interactive session capture
# --------------------------
echo -e "\n[Stage 2] Starting interactive analysis..." | tee -a "$LOG_FILE"
script -c "sapp --database-name $DB_NAME explore" -q "$OUTPUT_DIR/sapp_session.log" << EOF
issue ${ISSUE_NUMBER}
trace
quit
EOF

# --------------------------
# Stage 3: post-process logs
# --------------------------
echo -e "\n[Stage 3] Processing analysis output..." | tee -a "$LOG_FILE"

# Extract interaction block for this issue
INTERACTION_LOG=$(sed -n "/issue ${ISSUE_NUMBER}/,/quit/p" "$OUTPUT_DIR/sapp_session.log" | grep -v 'exit' | grep -v '')

echo "$INTERACTION_LOG" > "$OUTPUT_DIR/${ISSUE_NUMBER}_output.log"
echo "$INTERACTION_LOG" > "$OUTPUT_DIR/${ISSUE_NUMBER}_trace_chain.log"
echo "Logs written to: $OUTPUT_DIR"