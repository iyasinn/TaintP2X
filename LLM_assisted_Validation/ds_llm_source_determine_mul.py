import re
import json
import subprocess
import os
import sys

# from openai import OpenAI
from Source_Identification.llm_client import LLMClient


class SourceDeterminer:
    def __init__(self, project_base_path, log_dir):
        self.project_base_path = project_base_path
        self.log_dir = log_dir
        self.llm_client = LLMClient(api_key=os.getenv("SILICONFLOW_API_KEY", ""))
        self.system_prompt = """
You are a software security expert specializing in identifying taint-source functions in code.
For accurate analysis, you should have strong Python programming and taint-flow analysis skills.
Your task is to determine whether a function in a Python open-source project is used to call an LLM chat API.
Use the following criteria:

1. Functions that directly call LLM APIs:
   - OpenAI API (openai.OpenAI.chat.completions.create)
   - Anthropic API (anthropic.Anthropic.messages.create)
   - DeepSeek API
   - Other similar LLM API calls

2. Functions that indirectly request LLM APIs:
   - Use requests.post/get to call an LLM endpoint
   - URL contains obvious LLM API patterns (e.g., openai.com, api.anthropic.com, api.deepseek.com)
   - Headers include API keys (Authorization: Bearer sk-...)
   - Payload includes typical LLM parameters such as model and messages
   - Distinguish LLM chat/completion endpoints from image-generation endpoints.
     If it is image generation, exclude it.

3. Functions calling LLM APIs through third-party wrappers:
   - LiteLLM (litellm.completion, litellm.completion_with_retries)
   - LangChain (LLMChain, ChatOpenAI, etc.)
   - Other similar wrapper libraries (e.g., transformers, autotrain)

You only need to decide whether the given function matches these criteria.
The function you must evaluate is the first function in the call chain.

Return your analysis in this JSON format:
{
    "issue_number": <issue number>,
    "is_vulnerability": <true or false>,
    "reason": "<why it is or is not an LLM request function>",
    "triggering_conditions": "<if it is an LLM request function, describe call style and parameters>"
}
The "reason" and "triggering_conditions" fields must be written in Chinese.
Below is the suspicious code snippet and call chain to analyze:
"""

    def process_project(self, project_name, taint_output_file):
        """
        Process a project's taint-output.json and execute the full source-analysis flow.
        """
        print(f"--- Starting LLM Source validation: {project_name} ---")

        project_log_dir = os.path.join(self.log_dir, project_name)
        self.create_folder(project_log_dir)

        # Read taint-output.json
        issues = []
        try:
            with open(taint_output_file, "r") as f:
                content = f.read()
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        issues = [i for i in data if i.get("kind") == "issue"]
                    elif isinstance(data, dict) and data.get("kind") == "issue":
                        issues = [data]
                except json.JSONDecodeError:
                    for line in content.splitlines():
                        if not line.strip():
                            continue
                        try:
                            item = json.loads(line)
                            if item.get("kind") == "issue":
                                issues.append(item)
                        except:
                            pass
        except Exception as e:
            print(f"Failed to read taint-output.json: {e}")
            return

        print(f"Found {len(issues)} issues.")

        for i, issue_data in enumerate(issues, 1):
            issue_dir = os.path.join(project_log_dir, str(i))
            self.create_folder(issue_dir)

            with open(os.path.join(issue_dir, "issue_data.json"), "w") as f:
                json.dump(issue_data, f, indent=2)

            source_info = self._extract_source_info_from_issue(issue_data)

            if not source_info:
                print(f"Issue {i}: failed to extract source info, skipping.")
                continue

            with open(os.path.join(issue_dir, "file_paths_and_lines.json"), "w") as f:
                json.dump([source_info], f, indent=4)

            target_path = source_info["file_path"]
            # Try to resolve the target file path
            potential_paths = [
                os.path.join(self.project_base_path, project_name, target_path),
                os.path.join(self.project_base_path, target_path),
                os.path.abspath(target_path),
            ]
            if not os.path.isabs(target_path):
                potential_paths.append(
                    os.path.join(self.project_base_path, target_path)
                )

            final_path = None
            for p in potential_paths:
                if os.path.exists(p):
                    final_path = p
                    break

            if not final_path:
                print(f"Warning: cannot find file {target_path}")
                continue

            method_content = self.extract_method_by_line(
                final_path, source_info["line_number"]
            )

            context_file = os.path.join(issue_dir, "context_output.txt")
            with open(context_file, "w") as f:
                f.write(f"File: {final_path}, Line: {source_info['line_number']}\n")
                f.write("Method content:\n")
                f.write(method_content)

            self.interact_with_deepseek(i, method_content, project_name, i)

        self.check_and_merge_duplicate_issues(project_name)

    def _extract_source_info_from_issue(self, issue_data):
        try:
            traces = issue_data.get("data", {}).get("traces", [])
            for trace in traces:
                if trace.get("name") == "source":
                    roots = trace.get("roots", [])
                    if roots:
                        root = roots[0]
                        location = root.get("location")
                        if not location and root.get("leaves"):
                            location = root["leaves"][0].get("location")

                        if location:
                            filename = location.get("filename")
                            if filename and filename.startswith("/"):
                                filename = filename[1:]
                            return {
                                "file_path": filename,
                                "line_number": int(location.get("line")),
                                "function_name": issue_data.get("data", {}).get(
                                    "callable", "unknown"
                                ),
                            }
            return None
        except Exception as e:
            print(f"Error extracting source info: {e}")
            return None

    def count_issues(self, taint_output_file):
        try:
            with open(taint_output_file, "r") as file:
                content = file.read()
            target_string = '"kind":"issue"'
            issue_count = content.count(target_string)
            print(f"Detected {issue_count} occurrences of 'kind':'issue'.")
            return issue_count
        except FileNotFoundError:
            print(f"Error: file {taint_output_file} not found.")
            return 0
        except Exception as e:
            print(f"Unknown error: {e}")
            return 0

    def create_folder(self, folder_path):
        os.makedirs(folder_path, exist_ok=True)
        print(f"Folder created or already exists: {folder_path}")

    def run_test_script(self, project_name, issue_number=1):
        test_script_path = os.path.join(os.path.dirname(__file__), "test.sh")
        project_work_dir = os.path.join(self.project_base_path, project_name)
        try:
            print(f"Running test.sh to generate logs for project {project_name}...")

            # Ensure output directory exists; issue-level dirs should be handled by test.sh
            output_dir = os.path.join(self.log_dir, project_name)
            self.create_folder(output_dir)

            # Run script with required arguments:
            # <work_dir> <issue_number> <project_name>
            result = subprocess.run(
                [
                    "bash",
                    test_script_path,
                    project_work_dir,
                    str(issue_number),
                    project_name,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            print(f"test.sh completed successfully, check logs under {output_dir}.")
            if result.stdout and result.stdout.strip():
                print("--- test.sh stdout ---")
                print(result.stdout.strip())
            if result.stderr and result.stderr.strip():
                print("--- test.sh stderr ---")
                print(result.stderr.strip())
            return True

        except subprocess.CalledProcessError as e:
            print(f"test.sh failed (exit={e.returncode}).")
            if e.stdout and e.stdout.strip():
                print("--- test.sh stdout ---")
                print(e.stdout.strip())
            if e.stderr and e.stderr.strip():
                print("--- test.sh stderr ---")
                print(e.stderr.strip())
            return False
        except Exception as e:
            print(f"Error while running script: {str(e)}")
            return False

    def extract_file_paths_and_lines(self, input_file, output_file=None):
        try:
            with open(input_file, "r") as file:
                content = file.read()
        except FileNotFoundError:
            print(f"Error: file {input_file} not found.")
            return []

        # Match file path, line number, and function name with regex
        # Expected format: servers1/sweep/sweepai/utils/github_utils.py:76|24|23
        pattern = r"([^\s]+\.py):(\d+)\|(\d+)\|(\d+)\s*"
        matches = re.findall(pattern, content)
        results = []

        # Match function names with another regex
        func_pattern = r"(\S+)\s+(?:formal|result|leaf|root)"
        func_matches = re.findall(func_pattern, content)

        # Merge extracted results
        for i, (file_path, line_num, _, _) in enumerate(matches):
            func_name = func_matches[i] if i < len(func_matches) else "unknown"
            # Strip module/path prefix from function name
            func_name = func_name.split(".")[-1] if "." in func_name else func_name

            results.append(
                {
                    "file_path": file_path,
                    "line_number": int(line_num),
                    "function_name": func_name,
                }
            )

        if output_file:
            with open(output_file, "w") as file:
                json.dump(results, file, indent=4)
            print(f"Extraction results written to {output_file}")
        return results

    def extract_method_by_line(self, file_path: str, target_line: int) -> str:
        """Extract the full method content for a target line number."""
        try:
            with open(file_path, "r") as file:
                lines = file.readlines()

            # Ensure target line is within file bounds
            if target_line < 1 or target_line > len(lines):
                return "Target line number is out of file range"

            # Check if target line is blank
            if not lines[target_line - 1].strip():
                return "Target line is blank"

            # Search upward for method start
            start_line = target_line - 1
            method_found = False
            while start_line >= 0:
                if lines[start_line].strip().startswith("def "):
                    method_found = True
                    break
                start_line -= 1

            # If method definition is not found, return 5 lines of context before/after
            if not method_found:
                context_start = max(0, target_line - 6)  # -6 because line numbers start at 1
                context_end = min(
                    len(lines), target_line + 5
                )  # +5 includes 5 lines after target line
                return f"Target line is not inside a method. Showing context:\n" + "".join(
                    lines[context_start:context_end]
                )

            # Search downward for method end (based on indentation)
            method_indent = len(lines[start_line]) - len(lines[start_line].lstrip())
            end_line = target_line

            # Verify target line indentation belongs to this method
            target_line_content = lines[target_line - 1].rstrip()
            if not target_line_content:  # blank line
                context_start = max(0, target_line - 6)
                context_end = min(len(lines), target_line + 5)
                return f"Target line is blank. Showing context:\n" + "".join(
                    lines[context_start:context_end]
                )

            target_indent = len(lines[target_line - 1]) - len(
                lines[target_line - 1].lstrip()
            )
            if target_indent <= method_indent:
                # If target line is not inside the method, return local context
                context_start = max(0, target_line - 6)
                context_end = min(len(lines), target_line + 5)
                return f"Target line is not inside a method. Showing context:\n" + "".join(
                    lines[context_start:context_end]
                )

            while end_line < len(lines):
                # Skip blank lines
                if not lines[end_line].strip():
                    end_line += 1
                    continue
                # Method ends at same-or-lower indentation
                current_indent = len(lines[end_line]) - len(lines[end_line].lstrip())
                if current_indent <= method_indent:
                    break
                end_line += 1

            # Extract method content
            method_content = "".join(lines[start_line:end_line])
            return method_content

        except FileNotFoundError:
            return "File does not exist"
        except Exception as e:
            return f"Error extracting method: {str(e)}"

    def extract_context_content(self, extracted_results, project_name):
        if not extracted_results:
            print("No matches found for context extraction.")
            return ""

        first_result = extracted_results[0]
        file_path = os.path.join(
            self.project_base_path, project_name, first_result["file_path"]
        )
        line_number = first_result["line_number"]

        method_content = self.extract_method_by_line(file_path, line_number)
        if method_content:
            return method_content
        else:
            return ""

        full_target_file = os.path.join(self.project_base_path, target_file.lstrip("/"))

        try:
            # Use extract_method_by_line to fetch full method
            method_content = self.extract_method_by_line(full_target_file, target_line)

            with open(context_output_file, "w") as file:
                file.write(f"File: {full_target_file}, Line: {target_line}\n")
                file.write("Method content:\n")
                file.write(method_content)

            print(f"Method content written to {context_output_file}")
        except Exception as e:
            print(f"Error extracting method content: {e}")

    def count_checked_issues(self, project_name):
        """
        Count already checked issues.
        :param project_name: Project name.
        :return: Number of already checked issues.
        """
        base_dir = os.path.join(self.log_dir, project_name)
        issue_count = 0

        # Check whether target directory exists
        if not os.path.exists(base_dir):
            print(f"Directory {base_dir} does not exist.")
            return issue_count

        # Traverse all folders under the directory
        for item in os.listdir(base_dir):
            item_path = os.path.join(base_dir, item)
            if os.path.isdir(item_path):
                issue_count += 1

        print(f"Number of checked issues: {issue_count}")
        return issue_count

    def is_file_path_checked(self, file_path, project_name):
        """
        Check whether file_path has already been analyzed.
        :param file_path: File path to check.
        :param project_name: Current project name.
        :return: Matching response_output.json path if found; otherwise None.
        """
        base_dir = os.path.join(self.log_dir, project_name)

        issue_checked = self.count_checked_issues(project_name)

        # Traverse all issue folders
        for issue_number in range(1, issue_checked + 1):
            paths_and_lines_file = os.path.join(
                base_dir, str(issue_number), "file_paths_and_lines.json"
            )

            # Check whether file_paths_and_lines.json exists
            if not os.path.exists(paths_and_lines_file):
                continue

            # Read file_paths_and_lines.json
            with open(paths_and_lines_file, "r") as file:
                try:
                    data = json.load(file)
                    if data and data[0]["file_path"] == file_path:
                        # If file_path matches, return corresponding response_output.json path
                        response_file = os.path.join(
                            base_dir, str(issue_number), "response_output.json"
                        )
                        if os.path.exists(response_file):
                            return response_file
                except json.JSONDecodeError as e:
                    print(f"Error parsing {paths_and_lines_file}: {e}")

        # Return None when no matching file_path is found
        return None

    def check_and_merge_duplicate_issues(self, project_name):
        """Check for and merge duplicate issues."""
        base_dir = os.path.join(self.log_dir, project_name)
        issue_count = self.count_checked_issues(project_name)
        issue_info = {}  # Store first/last entry signatures per issue
        duplicates = {}  # Store duplicate issue groups

        # First collect first/last signatures for all issues
        for i in range(1, issue_count + 1):
            paths_file = os.path.join(base_dir, str(i), "file_paths_and_lines.json")
            if not os.path.exists(paths_file):
                continue

            try:
                with open(paths_file, "r") as f:
                    data = json.load(f)
                    if not data:  # Skip empty files
                        continue

                    # Get first and last records
                    first_record = data[0]
                    last_record = data[-1]
                    issue_info[i] = {
                        "first": f"{first_record['file_path']}:{first_record['line_number']}:{first_record['function_name']}",
                        "last": f"{last_record['file_path']}:{last_record['line_number']}:{last_record['function_name']}",
                    }

            except Exception as e:
                print(f"Error processing file {paths_file}: {e}")

        # Compare first/last signatures across issues
        for i in range(1, issue_count + 1):
            if i not in issue_info:
                continue

            for j in range(i + 1, issue_count + 1):
                if j not in issue_info:
                    continue

                # If two issues have identical first/last signatures
                if (
                    issue_info[i]["first"] == issue_info[j]["first"]
                    and issue_info[i]["last"] == issue_info[j]["last"]
                ):
                    # Use first+last signature as a grouping key
                    key = f"{issue_info[i]['first']}|{issue_info[i]['last']}"
                    if key not in duplicates:
                        duplicates[key] = []
                    if i not in duplicates[key]:
                        duplicates[key].append(i)
                    if j not in duplicates[key]:
                        duplicates[key].append(j)

        # Merge duplicate issues
        for key, issue_numbers in duplicates.items():
            if len(issue_numbers) > 1:
                # Keep the smallest issue ID
                keep_issue = min(issue_numbers)
                remove_issues = [i for i in issue_numbers if i != keep_issue]
                print(f"Duplicate issues found {issue_numbers}; keeping smallest ID {keep_issue}")

                # Delete other duplicate issue directories
                for remove_issue in remove_issues:
                    remove_dir = os.path.join(base_dir, str(remove_issue))
                    try:
                        if os.path.exists(remove_dir):
                            import shutil

                            shutil.rmtree(remove_dir)
                            print(f"Deleted duplicate issue directory: {remove_dir}")
                    except Exception as e:
                        print(f"Error deleting directory {remove_dir}: {e}")

        return duplicates

    def interact_with_deepseek(self, issue_number, context, project_name, i):
        try:
            # Build target response file path
            response_file = os.path.join(
                self.log_dir, project_name, str(i), "response_output.json"
            )

            # Skip if target file already exists and is non-empty
            if os.path.exists(response_file) and os.path.getsize(response_file) > 0:
                print(f"File {response_file} already exists with content; skipping.")
                return

            # Read file_paths_and_lines.json and get the first file_path
            paths_and_lines_file = os.path.join(
                self.log_dir, project_name, str(i), "file_paths_and_lines.json"
            )
            with open(paths_and_lines_file, "r") as file:
                file_path_data = json.load(file)
                first_file_path = (
                    file_path_data[0]["file_path"] if file_path_data else None
                )
                first_function_name = (
                    file_path_data[0]["function_name"] if file_path_data else None
                )

                # Check whether the final function location in output.log is valid
                # Read output.log content
                output_log_path = os.path.join(
                    self.log_dir, project_name, str(i), "output.log"
                )
                output_log_content = ""
                if os.path.exists(output_log_path):
                    with open(output_log_path, "r") as f:
                        output_log_content = f.read()

                # Detect invalid terminal function locations in output.log
                # Assume invalid markers like "*:" or "leaf:*" appear near the end.
                # This is a simplified heuristic and may need format-specific tuning.
                if "*:" in output_log_content or "leaf:*" in output_log_content:
                    # More precise validation could parse last-call records explicitly.
                    # For now, this simplified check treats these markers as invalid.
                    print(f"Issue {i}: invalid function location detected in output.log; skipping.")
                    default_response = {
                        "issue_number": i,
                        "is_vulnerability": False,
                        "reason": "The final function location in the call chain is invalid; cannot determine accurately",
                        "triggering_conditions": "",
                    }
                    with open(response_file, "w") as f:
                        json.dump(default_response, f, indent=2, ensure_ascii=False)
                    return

            # Check whether first_file_path has already been analyzed
            if first_file_path:
                checked_response_file = self.is_file_path_checked(
                    first_file_path, project_name
                )
                if checked_response_file:
                    # If already checked, reuse previous response_output.json
                    import shutil

                    shutil.copyfile(checked_response_file, response_file)
                    print(
                        f"File {first_file_path} already checked; copied {checked_response_file} to {response_file}."
                    )
                    return

            # Build payload sent to DeepSeek (using the provided context directly)
            deepseek_input = f"Issue {issue_number}\n{self.system_prompt}\n\ncode snippet:\n {context}\n"

            try:
                response_data = self.llm_client.chat_completion(
                    model="deepseek-ai/DeepSeek-V3",
                    messages=[{"role": "user", "content": deepseek_input}],
                    temperature=0,
                    max_tokens=1024,
                    response_format={"type": "json_object"},
                )

                if "choices" not in response_data or not response_data["choices"]:
                    print("DeepSeek API returned an invalid response format")
                    sys.exit(1)

                # Keep raw JSON text content
                json_content = response_data["choices"][0]["message"]["content"]

                # Write response content to file
                with open(response_file, "w") as file:
                    file.write(json_content)

                print(f"DeepSeek response saved to {response_file}")

            except Exception as api_error:
                error_message = str(api_error)
                print(f"Error while interacting with DeepSeek API: {error_message}")
                if "json.decoder.JSONDecodeError" in error_message:
                    with open(response_file.replace(".json", "_raw.txt"), "w") as f_raw:
                        f_raw.write(str(response_data))
                    print(
                        f"Raw response saved to {response_file.replace('.json', '_raw.txt')}"
                    )
                sys.exit(1)
        except Exception as e:
            print(f"Unknown error while processing issue {issue_number}: {str(e)}")


# if __name__ == "__main__":
#     # Example usage
#     # Assume project_name, test_script_path, test_script_arg1, and test_script_arg2 are external inputs
#     # Example: python your_script.py my_project /path/to/test.sh arg1 1
#     if len(sys.argv) != 5:
#         print("Usage: python ds_llm_source_determine_mul.py <project_name> <test_script_path> <test_script_arg1> <issue_number>")
#         sys.exit(1)

#     project_name = sys.argv[1]
#     test_script_path = sys.argv[2]
#     test_script_arg1 = sys.argv[3]
#     issue_number = int(sys.argv[4])

#     # Create folder
#     output_dir = f"log_zhipu/{project_name}/{issue_number}"
#     create_folder(output_dir)

#     # Run test.sh script
#     run_test_script(test_script_path, test_script_arg1, issue_number, project_name)

#     # Extract file paths and line numbers
#     taint_output_file = f"log_zhipu/{project_name}/{issue_number}/output.log"
#     file_paths_and_lines_file = f"log_zhipu/{project_name}/{issue_number}/file_paths_and_lines.json"
#     results = extract_file_paths_and_lines(taint_output_file, file_paths_and_lines_file)

#     # Extract context around the target line
#     context_output_file = f"log_zhipu/{project_name}/{issue_number}/context_output.txt"
#     extract_context_content(results, project_name, context_output_file)

#     # Interact with DeepSeek
#     interact_with_deepseek(issue_number, context_output_file, taint_output_file, project_name, issue_number)

#     # Check and merge duplicate issues
#     check_and_merge_duplicate_issues(project_name)
