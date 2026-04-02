import os
import json
import sys

# Import refactored classes
from .ds_llm_source_determine_mul import SourceDeterminer
from .ds_llm_fully_determine_mul import FullyDeterminer

# Global variables
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(CURRENT_DIR)
LOG_DIR = os.path.join("logs", "log_zhipu")
PROJECT_NAMES = ["vanna-ai__vanna", "shibing624__agentica"]
PROJECT_BASE_PATH = os.path.join(REPO_ROOT, "project")
LOG_BASE_PATH = os.path.join(REPO_ROOT, "logs")  # Unified log base path


def main():
    os.makedirs(LOG_BASE_PATH, exist_ok=True)
    source_determiner = SourceDeterminer(PROJECT_BASE_PATH, LOG_DIR)
    fully_determiner = FullyDeterminer(PROJECT_BASE_PATH, LOG_DIR)

    all_unified_results = {}

    for project_name in PROJECT_NAMES:
        print(f"\n--- Start unified analysis for project: {project_name} ---")

        # 1. Run test script to generate taint logs
        # NOTE: adjust run_test_script invocation based on your environment.
        # If test.sh is single-project only, call it in a loop per project.
        print(f"1. Running test script to generate logs for project {project_name}...")
        # Assume run_test_script generates logs under LOG_BASE_PATH/LOG_DIR/project_name/
        # In a real setup, pass an explicit test_script_path if needed.
        # For simplicity, we currently only pass project_name.
        run_ok = source_determiner.run_test_script(
            project_name=project_name, issue_number=1
        )
        print("Test script execution finished.")
        if not run_ok:
            print(
                "Warning: test.sh failed. Skipping project to avoid empty downstream analysis."
            )
            continue

        # Assume log file paths are fixed, or returned by run_test_script
        project_log_dir = os.path.join(LOG_BASE_PATH, LOG_DIR, project_name)
        taint_output_file_pattern = os.path.join(project_log_dir, "*_output.log")
        trace_chain_log_file_pattern = os.path.join(
            project_log_dir, "*_trace_chain.log"
        )

        # Find all generated output.log and trace_chain.log files
        import glob

        taint_output_files = glob.glob(taint_output_file_pattern)
        trace_chain_log_files = glob.glob(trace_chain_log_file_pattern)

        if not taint_output_files or not trace_chain_log_files:
            print(
                f"Warning: no taint logs or trace-chain logs found for project {project_name}. Skipping."
            )
            continue

        # Assume each output.log corresponds to one trace_chain.log
        # This matching can be made more robust; simplified for now.
        # Expected filename format: <issue_number>_output.log and <issue_number>_trace_chain.log
        project_issues = {}
        for taint_file in taint_output_files:
            issue_id_str = os.path.basename(taint_file).split("_")[0]
            try:
                issue_id = int(issue_id_str)
            except ValueError:
                print(
                    f"Warning: failed to extract issue ID from filename {taint_file}. Skipping."
                )
                continue

            trace_file = os.path.join(project_log_dir, f"{issue_id}_trace_chain.log")
            if not os.path.exists(trace_file):
                print(
                    f"Warning: trace-chain log {trace_file} for issue {issue_id} not found. Skipping."
                )
                continue

            # 2. Extract file paths and line numbers (from taint_file)
            print(
                f"  Processing Issue {issue_id}: extracting file paths and line numbers..."
            )
            extracted_results = source_determiner.extract_file_paths_and_lines(
                taint_file
            )
            if not extracted_results:
                print(
                    f"    No file paths or line numbers extracted for Issue {issue_id}. Skipping."
                )
                continue

            # 3. Extract nearby context content (SourceDeterminer)
            print(f"  Processing Issue {issue_id}: extracting context...")
            context_content = source_determiner.extract_context_content(
                extracted_results, project_name
            )
            if not context_content:
                print(f"    No context extracted for Issue {issue_id}. Skipping.")
                continue

            # 4. Interact with DeepSeek for source determination (SourceDeterminer)
            print(
                f"  Processing Issue {issue_id}: running DeepSeek source determination..."
            )
            source_determination_result = source_determiner.interact_with_deepseek(
                issue_id, context_content, taint_file, project_name, issue_id
            )
            print(f"    Source determination result: {source_determination_result}")

            # 5. Parse trace_chain.log and extract call-chain info (FullyDeterminer)
            print(f"  Processing Issue {issue_id}: parsing call-chain info...")
            all_trace_chains = fully_determiner.parse_trace_chain(trace_file)
            current_trace_chain = all_trace_chains.get(issue_id)

            if not current_trace_chain:
                print(
                    f"    Call chain for Issue {issue_id} not found in {trace_file}. Skipping."
                )
                continue
            print("    Call-chain parsing completed.")

            # 6. Extract concrete implementations for functions in the call chain
            print(
                f"  Processing Issue {issue_id}: extracting function implementations..."
            )
            for call in current_trace_chain:
                file_path = os.path.join(
                    PROJECT_BASE_PATH, project_name, call["file_path"]
                )
                if os.path.exists(file_path):
                    call["content"] = fully_determiner.extract_method_by_line(
                        file_path, int(call["start_line"])
                    )
                else:
                    print(
                        f"    Warning: file {file_path} not found; cannot extract function content."
                    )
                    call["content"] = (
                        "Function implementation unavailable or file not found"
                    )
            print("    Function implementation extraction completed.")

            # 7. Analyze call chain with DeepSeek for taint propagation reliability
            print(
                f"  Processing Issue {issue_id}: analyzing taint propagation with DeepSeek..."
            )
            taint_propagation_result = fully_determiner.analyze_trace_with_deepseek(
                current_trace_chain, taint_file, project_name
            )
            print(f"    Taint propagation analysis result: {taint_propagation_result}")

            project_issues[issue_id] = {
                "source_determination": source_determination_result,
                "taint_propagation": taint_propagation_result,
                "extracted_file_info": extracted_results,
                "context_content": context_content,
                "trace_chain": current_trace_chain,
            }
        all_unified_results[project_name] = project_issues

    # 8. Write unified analysis results for all projects
    output_file = os.path.join(LOG_BASE_PATH, "unified_analysis_results.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_unified_results, f, ensure_ascii=False, indent=4)
    print(f"\nUnified analysis results for all projects written to {output_file}")

    print("\n--- Unified analysis process completed ---")


if __name__ == "__main__":
    main()
