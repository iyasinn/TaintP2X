import json
import os

# from openai import OpenAI
from zhipuai import ZhipuAI
import requests
import sys
import re
from typing import Dict
from Source_Identification.llm_client import LLMClient


class FullyDeterminer:
    def __init__(self, project_base_path, log_dir):
        self.project_base_path = project_base_path
        self.log_dir = log_dir
        self.llm_client = LLMClient(api_key=os.getenv("SILICONFLOW_API_KEY", ""))
        self.system_prompt = """
You are a software security expert specializing in identifying taint propagation paths in code. For accurate analysis, you need strong Python programming skills and taint flow analysis abilities.

Your task is to examine functions in an open-source project (written in Python) for taint propagation. The criteria for determining taints are as follows:

1. Source of Taint:

- Any user-controlled input (e.g., HTTP request parameters, user-uploaded file content, command-line arguments, etc.)

- Sensitive information (e.g., API keys, database credentials, personally identifiable information, etc.)

2. Sink of Taints:

- Code execution functions (e.g., eval(), exec(), os.system(), subprocess.run(), etc.)

- Database operation functions (e.g., SQL queries, ORM operations, etc.)

- File operation functions (e.g., open(), write(), read(), etc.)

- Network request functions (e.g., requests.get(), requests.post(), etc.)

- Template rendering functions (e.g., Jinja2, Django templates, etc.)

- Deserialization functions (e.g., pickle.loads(), yaml.load(), etc.)

3. Taint Propagation Path:

- Tainted data flows from the source to the sink, potentially passing through multiple function calls, variable assignments, and data structure transfers.

- The tainted data has not undergone sufficient cleansing or verification during its propagation.

You need to analyze the given code snippet and call chain to determine if taint propagation exists, and describe the taint source, propagation path, and convergence point.

Please return your analysis in the following JSON format:

{ "issue_number": <issue number>,

"is_vulnerability": <true or false>,

"reason": "<the reason why it is or is not taint propagation>",

"triggering_conditions": "<if it is taint propagation, describe its calling behavior and parameters>"

} The returned "reason" and "triggering_conditions" content must use Chinese characters.

Below is the suspicious code snippet and call chain you need to analyze:
"""

    def process_project(
        self, project_name, taint_output_file, source_determiner_log_dir
    ):
        """
        Process a project's taint-output.json and further analyze full call chains
        based on SourceDeterminer results.
        """
        print(f"--- Starting LLM Full validation: {project_name} ---")

        project_log_dir = os.path.join(self.log_dir, project_name)
        if not os.path.exists(project_log_dir):
            os.makedirs(project_log_dir)

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

        vulnerable_issues = self._get_vulnerable_issues(
            project_name, source_determiner_log_dir
        )
        print(f"Suspicious issues identified by SourceDeterminer: {vulnerable_issues}")

        for issue_num in vulnerable_issues:
            if issue_num < 1 or issue_num > len(issues):
                continue

            issue_data = issues[issue_num - 1]
            issue_dir = os.path.join(project_log_dir, str(issue_num))
            if not os.path.exists(issue_dir):
                os.makedirs(issue_dir)

            trace_chain = self._extract_trace_chain(issue_data)
            self._interact_with_llm(issue_num, trace_chain, project_name, issue_dir)

    def _get_vulnerable_issues(self, project_name, source_log_dir):
        vulnerable_issues = []
        base_dir = os.path.join(source_log_dir, project_name)
        if not os.path.exists(base_dir):
            return []
        for item in os.listdir(base_dir):
            if not os.path.isdir(os.path.join(base_dir, item)):
                continue
            try:
                response_file = os.path.join(base_dir, item, "response_output.json")
                if os.path.exists(response_file):
                    with open(response_file, "r") as f:
                        if json.load(f).get("is_vulnerability", False):
                            vulnerable_issues.append(int(item))
            except:
                pass
        return sorted(vulnerable_issues)

    def _extract_trace_chain(self, issue_data):
        chain = []
        try:
            # Simplified version of Trace extraction
            chain.append(f"Callable: {issue_data.get('data', {}).get('callable')}")
            # Can be expanded to more detailed trace extraction
        except Exception as e:
            chain.append(f"Error extracting trace: {e}")
        return "\n".join(chain)

    def _interact_with_llm(self, issue_number, context, project_name, issue_dir):
        response_file = os.path.join(issue_dir, "response_output.json")
        if os.path.exists(response_file):
            return

        deepseek_input = (
            f"Issue {issue_number}\n{self.system_prompt}\n\nTrace info:\n {context}\n"
        )
        try:
            response_data = self.llm_client.chat_completion(
                model="deepseek-ai/DeepSeek-V3",
                messages=[{"role": "user", "content": deepseek_input}],
                temperature=0,
                max_tokens=1024,
                response_format={"type": "json_object"},
            )
            if "choices" in response_data and response_data["choices"]:
                with open(response_file, "w") as f:
                    f.write(response_data["choices"][0]["message"]["content"])
                print(f"DeepSeek response saved: {response_file}")
        except Exception as e:
            print(f"LLM interaction error: {e}")

    def get_project_names_starting_with_a(self, base_path):
        """
        Get all project names under the given directory that start with 'a'.
        :param base_path: Root path containing project directories.
        :return: Project names that start with 'a'.
        """
        project_names = []
        if not os.path.exists(base_path):
            print(f"Error: path {base_path} does not exist.")
            return project_names

        for item in os.listdir(base_path):
            if os.path.isdir(os.path.join(base_path, item)) and item.lower().startswith(
                "a"
            ):
                project_names.append(item)
        return project_names

    def extract_method_by_line(self, file_path: str, target_line: int) -> str:
        """Extract complete method content by target line number."""
        try:
            with open(file_path, "r") as file:
                lines = file.readlines()

            # Make sure the target line is within the file scope
            if target_line < 1 or target_line > len(lines):
                return "Target line number is out of file range"

            # Check if the target row is an empty row
            if not lines[target_line - 1].strip():
                return "Target line is blank"

            # The upward search method begins
            start_line = target_line - 1
            method_found = False
            while start_line >= 0:
                if lines[start_line].strip().startswith("def "):
                    method_found = True
                    break
                start_line -= 1

            # If no method definition is found, return 5 lines each of the context
            if not method_found:
                context_start = max(
                    0, target_line - 6
                )  # 6 is because line numbers start from 1
                context_end = min(
                    len(lines), target_line + 5
                )  # +5 is to include the 5 lines after the target line
                return f"Target line is not inside any method. Showing context:\n" + "".join(
                    lines[context_start:context_end]
                )

            # The end of the downward search method (judged by indentation)
            method_indent = len(lines[start_line]) - len(lines[start_line].lstrip())
            end_line = target_line

            # Check if the indentation of the target line belongs to the method
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
                # If the target line is not inside the method, return 5 lines each of the context.
                context_start = max(0, target_line - 6)
                context_end = min(len(lines), target_line + 5)
                return f"Target line is not inside any method. Showing context:\n" + "".join(
                    lines[context_start:context_end]
                )

            while end_line < len(lines):
                # Skip empty lines
                if not lines[end_line].strip():
                    end_line += 1
                    continue
                # If an indentation of the same level or lower level is encountered, the method ends.
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

    def extract_vulnerable_issues(self, project_name):
        # Get all issue folders
        base_dir = os.path.join(self.log_dir, project_name)
        vulnerable_issues = []

        # Traverse actual existing folders
        for item in os.listdir(base_dir):
            folder_path = os.path.join(base_dir, item)
            if not os.path.isdir(folder_path):
                continue

            issue_number = int(item)
            response_file = os.path.join(folder_path, "response_output.json")

            # Check if the file exists
            if not os.path.exists(response_file):
                continue

            # Read file contents
            with open(response_file, "r") as file:
                try:
                    data = json.load(file)
                    # Check if is_vulnerability is true
                    if data.get("is_vulnerability", False):
                        vulnerable_issues.append(issue_number)
                except json.JSONDecodeError as e:
                    print(f"Error parsing {response_file}: {e}")

        # Output results
        if vulnerable_issues:
            print("Issues with is_vulnerability=true:")
            for issue in vulnerable_issues:
                print(f"Issue {issue}")
        else:
            print("No issues with is_vulnerability=true were found.")

        return vulnerable_issues

    def parse_trace_chain(self, log_file_path):
        """
        Parse trace_chain.log and extract call-chain information per issue.
        :param log_file_path: Path to trace_chain.log.
        :return: Dictionary containing call-chain info for all issues.
        """
        issues_trace_chains = {}
        current_issue = None
        current_chain = []

        try:
            with open(log_file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("Issue"):
                        if current_issue is not None:
                            issues_trace_chains[current_issue] = current_chain
                        current_issue = int(line.split(" ")[1])
                        current_chain = []
                    elif current_issue is not None and line:
                        current_chain.append(line)
                if current_issue is not None:
                    issues_trace_chains[current_issue] = current_chain
        except FileNotFoundError:
            print(f"Error: file {log_file_path} not found.")
        except Exception as e:
            print(f"Error parsing file {log_file_path}: {e}")

        return issues_trace_chains

    def get_pure_function_name(self, full_function_name):
        """
        Extract plain function name from fully qualified function name.
        Example: 'module.submodule.ClassName.method_name' -> 'method_name'
                 'module.function_name' -> 'function_name'
        """
        return full_function_name.split(".")[-1]

    def find_function_implementation(
        self, function_name: str, project_path: str
    ) -> list:
        """
        Find concrete function implementations in the project.
        """
        results = []

        for root, _, files in os.walk(project_path):
            for file in files:
                if not file.endswith(".py"):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()

                    for i, line in enumerate(lines):
                        if line.strip().startswith(
                            f"def {function_name}"
                        ) or line.strip().startswith(f"async def {function_name}"):
                            method_indent = len(line) - len(line.lstrip())
                            end_line = i + 1

                            while end_line < len(lines):
                                if not lines[end_line].strip():
                                    end_line += 1
                                    continue
                                current_indent = len(lines[end_line]) - len(
                                    lines[end_line].lstrip()
                                )
                                if current_indent <= method_indent:
                                    break
                                end_line += 1

                            results.append(
                                {
                                    "file_path": file_path,
                                    "content": "".join(lines[i:end_line]),
                                    "line_number": i + 1,
                                }
                            )

                except Exception as e:
                    print(f"Error reading file {file_path}: {str(e)}")

        return results

    def get_sanitizer_implementations(
        self, analysis_results, trace_chain, project_name
    ) -> dict:
        """
        Get concrete implementations of sanitizer functions mentioned in analysis
        but not already present in the call chain.

        Args:
            analysis_results: list of analysis results
            trace_chain: call-chain list

        Returns:
            dict: sanitizer function names mapped to implementations
        """
        # Collect all mentioned filter functions but exclude functions already in the call chain
        sanitizer_functions = set()
        existing_functions = {
            self.get_pure_function_name(call["function"]) for call in trace_chain
        }

        for result in analysis_results:
            if result["analysis"].get("has_sanitizer") and result["analysis"].get(
                "sanitizer_functions"
            ):
                sanitizer_functions.update(
                    func
                    for func in result["analysis"]["sanitizer_functions"]
                    if func not in existing_functions
                )

        # Find the specific implementation of the filter function
        sanitizer_implementations = {}
        if sanitizer_functions:
            print(f"\nDetected sanitizer functions: {sanitizer_functions}")
            project_path = os.path.join(self.project_base_path, project_name)

            for func_name in sanitizer_functions:
                impls = self.find_function_implementation(func_name, project_path)
                if impls:
                    # If multiple implementations are found, the first one is used
                    sanitizer_implementations[func_name] = impls[0]["content"]
                    if len(impls) > 1:
                        print(
                            f"Warning: multiple implementations found for {func_name}; using the first one"
                        )
                        for i, impl in enumerate(impls, 1):
                            print(
                                f"Implementation #{i} at: {impl['file_path']}:{impl['line_number']}"
                            )
                else:
                    print(f"No implementation found for function {func_name}")

        return sanitizer_implementations

    def analyze_trace_with_deepseek(
        self, trace_chain: list, log_file: str, project_name
    ) -> dict:
        """
        Analyze call chain with DeepSeek and evaluate taint propagation reliability.

        Args:
            trace_chain: call-chain list
            log_file: path to raw call-chain log file
        """
        # Check if analysis_results.json already exists
        analysis_results_file = os.path.join(
            os.path.dirname(log_file), "analysis_results.json"
        )
        if (
            os.path.exists(analysis_results_file)
            and os.path.getsize(analysis_results_file) > 0
        ):
            print(f"File {analysis_results_file} already exists with content; skipping analysis.")
            try:
                with open(analysis_results_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error reading existing analysis results: {str(e)}")
                # If a read error occurs, continue with a new analysis

        # Read the original call chain log
        with open(log_file, "r") as f:
            output_log_content = f.read()

        analysis_results = []
        print(f"\nStarting call-chain analysis. Total functions: {len(trace_chain)}")

        # Extract vulnerability type
        vuln_type = None
        response_json = os.path.join(os.path.dirname(log_file), "response_output.json")
        if os.path.exists(response_json):
            try:
                with open(response_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "vulnerability_types" in data:
                        vuln_type = data["vulnerability_types"]
            except Exception as e:
                print(f"Error reading vulnerability types: {str(e)}")

        # Add specific tips based on vulnerability type
        type_specific_prompts = {
            "Code_Execution": """
Please pay special attention to the following points:

1. Does it contain command concatenation or `eval`-like execution functions?

2. Are command parameters strictly filtered?

3. Is a safe command execution method used?

4. Is the scope of executable commands restricted?

5. If command execution is implemented via `eval`, are taints restricted to correct JSON format?

6. Can the content controlled by taints affect the execution of commands or code? Some taints, even if they propagate to the sink function, cannot affect the execution of any specific command or code.

7. For sink points like `subprocess.Popen`, ensure the value of `shell` is True.


"SQL_Injection":

Please pay special attention to the following points:

1. Does the SQL statement use parameterized queries?

2. Does it contain direct string concatenation?

3. Are special characters escaped?

4. Are the types of SQL statements restricted?


"File_Operation": 

Please pay special attention to the following points:

1. Are file paths normalized?

2. Is the directory range for file operations restricted?

3. Is path traversal possible?

Then you need to analyze whether the file operation is reading or writing a file; this is crucial.

For sinks that write files:

1. Can the taint control both the file path and the content being written?

2. If the taint can only control one of them (path or content), it does not constitute a valid exploit.

3. Even if other conditions are met, if the condition of simultaneously controlling the path and content is not met, it must be deemed invalid.

For sinks that read files:

1. Can the taint control the file path, leading to arbitrary file reading?

2. Is the file path being read whitelisted?

3. Are the types of files and directories that can be read restricted?

"XSS":  Please pay special attention to the following points:

1. Is the output HTML encoded?

2. Is a secure template engine used?

3. Is the output of large models strictly filtered?

"SSRF": 1. Check whether the target address of these requests is controllable, for example, whether it is obtained from user input, configuration files, or environment variables.

2. Verify for any access to internal network resources (such as internal IP addresses, local files, and internal services).

3. Evaluate for techniques that bypass URL whitelists or blacklists, such as using special protocols (file://, gopher://), redirects, or DNS rebinding.

""",
        }

        # Add a collection of analyzed functions at the beginning of the function
        analyzed_functions = set()

        for i, call in enumerate(trace_chain, 1):
            # Only use function implementation content as a unique identifier
            func_content = call.get("content", "Function implementation unavailable")

            # If the same function implementation has already been analyzed, skip
            if func_content in analyzed_functions:
                print(f"\n[{i}/{len(trace_chain)}] Skipping duplicate function: {call['function']}")
                continue

            print(f"\n[{i}/{len(trace_chain)}] Analyzing function: {call['function']}")
            analyzed_functions.add(func_content)

            # Build basic prompt information
            base_prompt = f"""Analyze whether taint propagation is valid in the following call-chain segment.
The taint source is user-controllable LLM output.
During propagation to sink functions, sanitizer functions may be applied.
Carefully evaluate whether sanitization is effective.
For each taint flow, determine whether data reaching the sink remains controllable from the source,
and whether that control can actually trigger the sink vulnerability.
Only analyze the provided code segment.
"""

            # Add vulnerability type specific hints
            if vuln_type and isinstance(vuln_type, list):
                for vtype in vuln_type:
                    if vtype in type_specific_prompts:
                        base_prompt += "\n" + type_specific_prompts[vtype]

            # Complete prompt information
            prompt = (
                base_prompt
                + f"""

Please provide a detailed analysis of:
1. Functional role and call intent of each function in the taint path
2. How each function processes and forwards tainted data
3. Inter-function call relationships and dataflow transitions
4. Whether validation or sanitization exists

Full call-chain information:
{output_log_content}

Current call-chain segment:

Function name: {call['function']}
Parameter info: {call['params']}
Function implementation:
{call['content'] if 'content' in call else 'Function implementation unavailable'}

Return analysis in JSON format:
{{
    "issue_number": <call chain id>,
    "is_taint_valid": true/false,
    "has_sanitizer": true/false,
    "sanitizer_functions": [<list of sanitizer function names>],
    "function_analysis": [
        {{
            "function_name": <function name>,
            "purpose": <function intent and role (Chinese)>,
            "taint_handling": <taint handling method (Chinese)>
        }}
    ],
    "analysis_reason": <reason the flow is valid/invalid (Chinese)>
}}
"""
            )

            # Call deep seek for analysis
            try:
                messages = [{"role": "user", "content": prompt}]
                response = self.llm_client.chat_completion(
                    messages=messages,
                    temperature=0,
                    max_tokens=1024,
                    response_format={"type": "json_object"},
                )

                # response = requests.request("POST", url, json=payload, headers=headers)
                # response.raise_for_status()
                # response_json = response.json()

                # if response_json and 'choices' in response_json and response_json['choices']:
                #     message_content = response_json['choices'][0].get('message', {}).get('content')
                #     if message_content:
                #         try:
                #             extracted_analysis = json.loads(message_content)
                #             print("---LLM Call Analysis Extracted JSON ---")
                #             print(json.dumps(extracted_analysis, indent=4))
                #             call.update(extracted_analysis)
                #             analysis_results.append(call)
                #         except json.JSONDecodeError:
                #             print("Error: Could not decode nested JSON from LLM response content.")
                #             analysis_results.append({"error": "JSON decode error in LLM content", **call})
                #     else:
                #         print("Warning: 'content' field is missing or empty in LLM response message.")
                #         analysis_results.append({"error": "Empty or missing content in LLM response", **call})
                # else:
                #     print("Warning: Unexpected LLM response structure or empty choices.")
                #     analysis_results.append({"error": "Unexpected LLM response structure", **call})

                if response and "choices" in response and response["choices"]:
                    message_content = (
                        response["choices"][0].get("message", {}).get("content")
                    )
                    if message_content:
                        try:
                            extracted_analysis = json.loads(message_content)
                            print("--- LLM Call Analysis Extracted JSON ---")
                            print(json.dumps(extracted_analysis, indent=4))
                            call.update(extracted_analysis)
                            analysis_results.append(call)
                        except json.JSONDecodeError:
                            print(
                                "Error: Could not decode nested JSON from LLM response content."
                            )
                            analysis_results.append(
                                {"error": "JSON decode error in LLM content", **call}
                            )
                    else:
                        print(
                            "Warning: 'content' field is missing or empty in LLM response message."
                        )
                        analysis_results.append(
                            {
                                "error": "Empty or missing content in LLM response",
                                **call,
                            }
                        )
                else:
                    print(
                        "Warning: Unexpected LLM response structure or empty choices."
                    )
                    analysis_results.append(
                        {"error": "Unexpected LLM response structure", **call}
                    )

            except Exception as e:
                print(f"Error calling DeepSeek API: {str(e)}")
                analysis_results.append(
                    {"error": f"DeepSeek API call error: {str(e)}", **call}
                )

        try:
            final_response = self.llm_client.chat_completion(
                messages=[
                    {
                        "role": "user",
                        "content": chain_prompt
                        + "\nReturn strictly valid JSON only. Do not include extra text or Markdown. Ensure the JSON is parseable.",
                    }
                ],
                temperature=0,
                max_tokens=1024,
                response_format={"type": "json_object"},
            )

            if (
                final_response
                and "choices" in final_response
                and final_response["choices"]
            ):
                json_content = final_response["choices"][0]["message"]["content"]
                try:
                    final_analysis = json.loads(json_content)
                except json.JSONDecodeError as je:
                    print(f"JSON parse error, raw content:\n{json_content}")
                    print(f"Error details: {str(je)}")
                    final_analysis = {
                        "issue_number": os.path.basename(os.path.dirname(log_file)),
                        "is_vulnerability": False,
                        "reason": "JSON parse error, unable to complete analysis",
                        "triggering_conditions": "Undetermined",
                        "poc": "Cannot generate",
                    }
            else:
                print(
                    "Warning: Unexpected LLM response structure or empty choices for final analysis."
                )
                final_analysis = {
                    "issue_number": os.path.basename(os.path.dirname(log_file)),
                    "is_vulnerability": False,
                    "reason": "Unexpected LLM response structure, unable to complete analysis",
                    "triggering_conditions": "Undetermined",
                    "poc": "Cannot generate",
                }
                sys.exit(1)  # Json parsing errors also exit directly

        except Exception as e:
            print(f"Error calling DeepSeek for final analysis: {str(e)}")
            final_analysis = {
                "issue_number": os.path.basename(os.path.dirname(log_file)),
                "is_vulnerability": False,
                "reason": f"DeepSeek API call error: {str(e)}",
                "triggering_conditions": "Undetermined",
                "poc": "Cannot generate",
            }

        # Build output json
        output_json = {
            "issue_id": os.path.basename(
                os.path.dirname(log_file)
            ),  # Extract issue id from log file path
            "trace_chain": trace_chain,
            "analysis": {
                "individual_analysis": analysis_results,
                "chain_analysis": final_analysis,
            },
        }

        # Output json result
        output_file = os.path.join(os.path.dirname(log_file), "analysis_results.json")
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(output_json, f, ensure_ascii=False, indent=2)

        print(f"Analysis results saved to: {output_file}")

        return {
            "individual_analysis": analysis_results,
            "chain_analysis": final_analysis,
        }
