import os
import json
import re
import time
import requests
import ast
import logging
import base64
import urllib.parse
import socket
import ipaddress
import jwt
from jwt import InvalidTokenError
import AVASecret
from datetime import datetime
from typing import Any, Dict, Optional, Type
from pydantic import BaseModel, Field, ConfigDict, field_validator
from crewai.tools import BaseTool

# --- REDIS LOG IMPORTS ---
from app.helpers.redis_logs import PipelineAILogs
from app.core.redis_client import redis_client

# --- Initialize Logger ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# --- Security Constants ---
MAX_POLL_ATTEMPTS = 60   # 60 × 20s = 20 minutes max polling

# --- Pre-compiled Regular Expressions ---
JIRA_ID_REGEX = re.compile(r"^[A-Za-z0-9]+-\d+$")
GITHUB_NAME_REGEX = re.compile(r"^[A-Za-z0-9._-]+$")
BRANCH_REGEX = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
PATH_REGEX = re.compile(r"^[A-Za-z0-9._\-/]+$")

# --- Centralized URL Validator (Hardened SSRF Protection) ---
def validate_secure_url(url: str) -> str:
    """SSRF-safe URL validation with DNS check."""
    logger.info(f"URL_CHECK - {url}")
    if not url:
        raise ValueError("URL cannot be empty.")
    url = url.strip()
    
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            raise ValueError("URL must use HTTP or HTTPS.")
            
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("URL must contain a valid hostname.")

        # Allow internal Kubernetes service only if explicitly required
        if hostname.endswith(".svc.cluster.local"):
            return url

        # Resolve DNS securely
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        if (ip_obj.is_private or ip_obj.is_loopback or 
            ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved):
            raise ValueError("URL resolves to a restricted internal IP.")
            
        return url
    except Exception:
        raise ValueError("Invalid or unsafe URL.")

def get_required_secret(key: str) -> str:
    value = AVASecret.getValue(key)
    logger.info(f"[get_required_secret]: key is {key}")

    if not value or not isinstance(value, str) or not value.strip():
        logger.info(f"[get_required_secret]: NOT_VALID_VALUE {key}")
        raise ValueError(f"{key} is missing or empty")

    logger.info(f"[get_required_secret]: VALID_VALUE {key}")
    return value.strip()



# --- 1. Clean Input Schema ---
class HierarchyOrchestratorInput(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    jira_story_id: str = Field(..., description="The input Jira Story ID to process.")
    github_repo_owner: str = Field(..., description="Owner or organization name")
    github_repo_name: str = Field(..., description="Repository name")
    github_branch: str = Field(default="main", description="Target branch")

    # Validators
    @field_validator("jira_story_id")
    @classmethod
    def validate_jira_id(cls, v: str):
        if not JIRA_ID_REGEX.fullmatch(v):
            raise ValueError("Invalid Jira Story ID format")
        return v

    @field_validator("github_repo_owner", "github_repo_name")
    @classmethod
    def validate_github_names(cls, v: str):
        if not GITHUB_NAME_REGEX.fullmatch(v):
            raise ValueError("Invalid GitHub owner or repo name")
        return v

    @field_validator("github_branch")
    @classmethod
    def validate_branch(cls, v: str):
        if not BRANCH_REGEX.fullmatch(v):
            raise ValueError("Invalid branch name")
        return v

# --- 2. Main Controller Logic ---
class JiraMainOrchestrator:
    def __init__(self):
        # Platform Endpoint Configuration
        raw_pipeline_url = os.environ.get("PIPELINE_URL")
        if not raw_pipeline_url:
            raise ValueError("CRITICAL: PIPELINE_URL environment variable is not set.")

        self.jira_base_url = get_required_secret("JIRA_URL")
        self.github_base_url = get_required_secret("GITHUB_URL")
        self.PIPELINE_URL = validate_secure_url(raw_pipeline_url)
        self.RESULT_URL_TEMPLATE = f"{self.PIPELINE_URL.rstrip('/')}/{{}}/result"
        
        # Token & Strict User Extraction
        self.token = AVASecret.getValue("access_key_hp_stg_user")
        self.EXECUTION_USER = self._extract_user_from_jwt(self.token)
        
        # High-Level Workflow IDs (Encapsulated)
        self.wf_jira_link_fetcher = "472" 
        self.wf_xxx_summary = "473"
        self.wf_aaaa_child = "487"
        self.wf_yyy_final_merge = "480"

    def _extract_user_from_jwt(self, token: str) -> str:
        """Strictly decodes the JWT to find the unique_name. Fails if missing."""
        if not token:
            raise ValueError("Authentication token is missing from AVASecret.")
            
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed JWT format in AVASecret.")
            
        payload_b64 = parts[1]
        # Pad base64 string to handle missing padding
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        
        try:
            payload_json = base64.b64decode(payload_b64).decode("utf-8")
            payload_data = json.loads(payload_json)
        except Exception:
            logger.exception("Failed to decode base64 JWT payload.")
            raise ValueError("Failed to parse token payload.")
            
        unique_name = payload_data.get("unique_name")
        if not unique_name:
            raise ValueError("JWT token does not contain a 'unique_name'. Execution blocked.")
            
        return unique_name

    def _trigger_workflow(self, pipeline_id: str, placeholders: Dict[str, Any]) -> Optional[str]:
        logger.info("Triggering Jira Orchestration Pipeline ID %s", pipeline_id)
        PipelineAILogs().publishLogs(f"Triggering Workflow ID: {pipeline_id}...", "black", redisClient=redis_client)
        
        headers = {"Authorization": f"Bearer {self.token}"}
        payload = {
            "pipelineId": pipeline_id,
            "user": self.EXECUTION_USER,
            "userInputs": json.dumps(placeholders),
            "priority": "1"
        }
        form_data = {k: (None, str(v)) for k, v in payload.items()}
        
        try:
            response = requests.post(self.PIPELINE_URL, headers=headers, files=form_data, timeout=120, verify=True)
            response.raise_for_status()
            data = response.json()
            return data.get("workflowExecutionId") or data.get("data", {}).get("workflowExecutionId")
        except Exception:
            logger.exception("Jira Orchestration ERROR during workflow trigger.")
            PipelineAILogs().publishLogs("Failed to trigger Workflow due to an unexpected error.", "black", redisClient=redis_client)
            raise Exception("Workflow execution failed to trigger.")

    def _poll_execution(self, execution_id: str) -> Dict[str, Any]:
        url = self.RESULT_URL_TEMPLATE.format(execution_id)
        headers = {"Authorization": f"Bearer {self.token}"}
        PipelineAILogs().publishLogs(f"Polling status for execution ID: {execution_id}...", "black", redisClient=redis_client)
        
        attempts = 0

        while attempts < MAX_POLL_ATTEMPTS:
            try:
                response = requests.get(url, headers=headers, timeout=60, verify=True)
                response.raise_for_status()
                result = response.json()
                
                status = result.get("status")
                inner_status = result.get("data", {}).get("status") if isinstance(result.get("data"), dict) else None
                
                if status in ["SUCCESS", "FAILED", "ERROR"] and inner_status not in ["QUEUED", "IN_PROGRESS"]:
                    if status == "SUCCESS":
                        logger.info(f"WF {execution_id} finished: {status}")
                        PipelineAILogs().publishLogs(f"WF {execution_id} completed successfully.", "black", redisClient=redis_client)
                    else:
                        logger.error(f"WF {execution_id} finished with error status: {status}")
                        PipelineAILogs().publishLogs("Workflow failed during execution.", "black", redisClient=redis_client)
                        raise Exception("Workflow failed during execution.")
                    return result
                    
                attempts += 1
                time.sleep(20) 
            except Exception as e:
                if "failed during execution" in str(e):
                    raise e
                logger.warning(f"Polling error encountered (retrying in 20s). Attempt {attempts}/{MAX_POLL_ATTEMPTS}")
                attempts += 1
                time.sleep(20)

        logger.error(f"Polling timeout for execution ID: {execution_id}")
        PipelineAILogs().publishLogs("Workflow polling exceeded maximum retry limit.", "black", redisClient=redis_client)
        raise TimeoutError("Workflow polling exceeded maximum retry limit.")

    def _parse_nested_response(self, result_data: Dict[str, Any]) -> Any:
        try:
            res_content = result_data.get("result") or result_data.get("data", {}).get("result") or result_data.get("data")
            if isinstance(res_content, str):
                try: res_content = json.loads(res_content)
                except: pass
            response_payload = res_content.get("response", "{}") if isinstance(res_content, dict) else res_content
            if isinstance(response_payload, str):
                try: return json.loads(response_payload).get("output", json.loads(response_payload))
                except: return response_payload
            return response_payload
        except Exception: 
            logger.exception("Error parsing AAVA response structure.")
            return "{}"

    def _get_jira_links(self, inputs: HierarchyOrchestratorInput) -> Dict:
        placeholders = {"{{Input_string_true}}": json.dumps({
            "jira_story_id": inputs.jira_story_id, 
            "jira_base_url": self.jira_base_url
        })}
        PipelineAILogs().publishLogs(f"Fetching Jira links and metadata for {inputs.jira_story_id}...", "black", redisClient=redis_client)
        
        exec_id = self._trigger_workflow(self.wf_jira_link_fetcher, placeholders)
        if not exec_id: return {}
        res = self._poll_execution(exec_id)
        raw_out = self._parse_nested_response(res)
        
        if isinstance(raw_out, str):
            out_str = raw_out.replace("```json", "").replace("```", "").strip()
            try:
                return json.loads(out_str) if out_str and out_str != "{}" else {}
            except json.JSONDecodeError:
                return {}
        return raw_out if isinstance(raw_out, dict) else {}

    def run(self, inputs: HierarchyOrchestratorInput) -> Dict:
        logger.info(f"--- STARTING MAIN ORCHESTRATOR FOR: {inputs.jira_story_id} ---")
        PipelineAILogs().publishLogs(f"Starting Main Orchestrator for {inputs.jira_story_id}...", "black", redisClient=redis_client)
        
        timestamp = datetime.now().strftime("%d%m%y_%H%M%S")
        run_folder = f"{inputs.jira_story_id}_{timestamp}"
        
        try:
            # 1. Fetch Links
            links = self._get_jira_links(inputs)
            
            # 2. Determine base folder based on Issue Type
            res_issue_type = links.get("issue_type", "Story")
            base_summary_folder = "epic_summary" if res_issue_type.lower() == "epic" else "story_summary"
            final_merged_path = f"{run_folder}/{base_summary_folder}/final_summary.json"

            # Reusable GitHub Base UI URL construction for the frontend
            #github_ui_url = f"{inputs.github_base_url}/{inputs.github_repo_owner}/{inputs.github_repo_name}/tree/{inputs.github_branch}/{run_folder}"
            github_ui_url = f"{self.github_base_url.rstrip('/')}/{inputs.github_repo_owner}/{inputs.github_repo_name}/tree/{inputs.github_branch}/{run_folder}"
            # 3. Check for attachments 
            attachment_keys = ["PDF_links", "TXT_links", "DOCX_llnks", "XLSX_links", "Image_links"]
            has_attachments = any(len(links.get(k, [])) > 0 for k in attachment_keys)
            jira_summary_write_path = f"{run_folder}/jira_summary.txt" if has_attachments else final_merged_path
            
            # 4. Trigger Base Summary 
            PipelineAILogs().publishLogs(f"Triggering {res_issue_type} summary workflow...", "black", redisClient=redis_client)
            xxx_placeholders = {
                "{{jira-story-id_string_true}}": inputs.jira_story_id,
                "{{jira-base-url_string_true}}": self.jira_base_url,
                "{{file-path-write_string_true}}": jira_summary_write_path,
                "{{github-base-url_string_true}}": self.github_base_url,
                "{{github-repo-owner_string_true}}": inputs.github_repo_owner,
                "{{repo-name_string_true}}": inputs.github_repo_name,
                "{{branch_string_true}}": inputs.github_branch
            }
            exec_id = self._trigger_workflow(self.wf_xxx_summary, xxx_placeholders)
            self._poll_execution(exec_id)

            # If no attachments, we are completely done.
            if not has_attachments:
                logger.info("No attachments found. Process complete.")
                PipelineAILogs().publishLogs("No attachments found. Process complete.", "black", redisClient=redis_client)
                return {
                    "status": "SUCCESS", 
                    "final_summary_path": final_merged_path,
                    "final_github_url": github_ui_url
                }

            # 5. Delegate to Child Workflow AAAAA
            logger.info("Attachments found. Delegating to Child Workflow...")
            PipelineAILogs().publishLogs("Attachments found. Delegating to Child Workflow...", "black", redisClient=redis_client)
            
            child_placeholders = {
                "{{links-payload_string_true}}": json.dumps(links),
                "{{run-folder_string_true}}": run_folder,
                "{{github-base-url_string_true}}": self.github_base_url,
                "{{github-repo-owner_string_true}}": inputs.github_repo_owner,
                "{{repo-name_string_true}}": inputs.github_repo_name,
                "{{branch_string_true}}": inputs.github_branch
            }
            
            child_exec_id = self._trigger_workflow(self.wf_aaaa_child, child_placeholders)
            child_paths = {}
            child_result = self._poll_execution(child_exec_id)
            child_paths_raw = self._parse_nested_response(child_result)
                
            # Robust Parsing Logic
            if isinstance(child_paths_raw, dict):
                if "raw" in child_paths_raw and isinstance(child_paths_raw["raw"], str):
                    child_paths_raw = child_paths_raw["raw"]
                elif "output" in child_paths_raw and isinstance(child_paths_raw["output"], str):
                    child_paths_raw = child_paths_raw["output"]
                
            if isinstance(child_paths_raw, str):
                cleaned_raw = child_paths_raw.replace("```json", "").replace("```", "").replace("```python", "").strip()
                try:
                    child_paths = json.loads(cleaned_raw)
                except json.JSONDecodeError:
                    try:
                        child_paths = ast.literal_eval(cleaned_raw)
                    except (ValueError, SyntaxError):
                        logger.exception("Failed to parse child output.")
                        PipelineAILogs().publishLogs("Failed to parse child output correctly.", "black", redisClient=redis_client)
                        child_paths = {}
            elif isinstance(child_paths_raw, dict):
                child_paths = child_paths_raw
                    
            if not isinstance(child_paths, dict):
                child_paths = {}

            # Extract paths returned by the child
            pdf_text_paths = child_paths.get("pdf_text_paths", [])
            xlsx_jpg_paths = child_paths.get("xlsx_jpg_paths", [])
            doc_png_paths = child_paths.get("doc_png_paths", [])

            # 6. Final Master Merge
            logger.info("Triggering Final Master Merge...")
            PipelineAILogs().publishLogs("All child tasks complete. Triggering Final Master Merge...", "black", redisClient=redis_client)
            
            yyy_placeholders = {
                "{{file-path-pdf-text_string_true}}": ",".join(pdf_text_paths),
                "{{file-path-xslx-jpg_string_true}}": ",".join(xlsx_jpg_paths),
                "{{file-path-doc-png_string_true}}": ",".join(doc_png_paths),
                "{{file-path-issue-summary_string_true}}": jira_summary_write_path, 
                "{{file-path-write_string_true}}": final_merged_path,
                "{{github-base-url_string_true}}": self.github_base_url,
                "{{github-repo-owner_string_true}}": inputs.github_repo_owner,
                "{{repo-name_string_true}}": inputs.github_repo_name,
                "{{branch_string_true}}": inputs.github_branch
            }
            final_exec_id = self._trigger_workflow(self.wf_yyy_final_merge, yyy_placeholders)
            self._poll_execution(final_exec_id)
            
            logger.info("Main Orchestrator finished successfully.")
            PipelineAILogs().publishLogs("Main Orchestrator finished successfully.", "black", redisClient=redis_client)
            return {
                "status": "SUCCESS", 
                "final_summary_path": final_merged_path,
                "final_github_url": github_ui_url
            }
            
        except Exception:
            logger.exception("Main Orchestrator failed unexpectedly.")
            PipelineAILogs().publishLogs("Process aborted due to an unexpected error.", "black", redisClient=redis_client)
            return {"status": "ERROR", "error": "An unexpected error occurred during execution."}

# --- 3. CrewAI Tool Wrapper ---
class JiraMainOrchestratorTool(BaseTool):
    name: str = "Jira Main Orchestrator"
    description: str = "Manages Jira summary execution and delegates attachment processing to child workflows."
    args_schema: Type[BaseModel] = HierarchyOrchestratorInput

    def _run(self, **kwargs: Any) -> Dict:
        return JiraMainOrchestrator().run(HierarchyOrchestratorInput(**kwargs))