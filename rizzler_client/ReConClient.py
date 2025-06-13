# --- START OF FILE ReConClient.py ---

# ReConClient.py
import asyncio
import os
import json
import logging
import urllib.parse
import hashlib
import re
from datetime import datetime
import time
import queue # For gui_update_queue

import httpx
from httpx_sse import aconnect_sse
from cachetools import TTLCache
from dotenv import load_dotenv
from langchain_core.messages import AIMessage, BaseMessage, SystemMessage, HumanMessage, ToolMessage
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from icecream import ic # Ensure icecream is in requirements or remove if not used
from typing import Optional, List, Dict, Any, Set
from urllib.parse import urlparse

# Import from models.py
from models import Models, AVAILABLE_LLM_MODELS, DEFAULT_LLM_MODEL_ID

# Configure logging (remains the same)
logger = logging.getLogger("MCPClientSSE_Google")
logger.setLevel(logging.INFO) 

file_handler = logging.FileHandler("mcp_sse_client.log", mode='w')
file_handler.setLevel(logging.DEBUG) 
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'))

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO) 
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

if logger.hasHandlers():
    logger.handlers.clear()
logger.addHandler(file_handler)
logger.addHandler(console_handler)
logger.propagate = False

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("google.api_core").setLevel(logging.WARNING)
logging.getLogger("google.auth").setLevel(logging.WARNING)

load_dotenv()

# Exception Classes (remains the same)
class ConfigError(Exception): pass
class ConnectionError(Exception): pass 
class ToolExecutionError(Exception): pass
class MaxToolIterationsError(Exception): pass

# Config Class (remains the same)
class Config:
    def __init__(self):
        self.server_base_url = os.getenv("MCP_SERVER_BASE_URL")
        self.google_api_key = os.getenv("GOOGLE_API_KEY")
        self.default_prompt = os.getenv("default_prompt") or """
        You are a helpful assistant. For each query:
        1. Analyze the query to identify required actions.
        2. Use the 'SequentialThinkingPlanner' tool to record each thought step-by-step.
        3. When necessary, call other tools to perform actions.
        4. Continue until the problem is solved, then provide a final answer without calling more tools.
        """
        if not self.server_base_url or not self.google_api_key:
            logger.critical("MCP_SERVER_BASE_URL and GOOGLE_API_KEY must be set in .env")
            raise ConfigError("MCP_SERVER_BASE_URL and GOOGLE_API_KEY must be set in .env")
        if not self.server_base_url.startswith(("http://", "https://")):
            logger.critical(f"MCP_SERVER_BASE_URL '{self.server_base_url}' must start with http:// or https://")
            raise ConfigError("MCP_SERVER_BASE_URL must start with http:// or https://")
        self.server_base_url = self.server_base_url.rstrip('/')
        logger.info(f"Config loaded. Server URL: {self.server_base_url}")

from dataclasses import dataclass, field
@dataclass
class Plan: # (remains the same)
    query: str
    dependencies: List[str] = field(default_factory=list)
    id: str = ""

class MCPClient:
    REFLECTION_THRESHOLD = 3

    def __init__(self, max_tool_iterations=555, cache_size=10000, cache_ttl=36000):
        self.config = Config()
        
        self.current_llm_id = DEFAULT_LLM_MODEL_ID 
        try:
            self.models = Models(model_id=self.current_llm_id)
        except ValueError as e: 
            logger.critical(f"Failed to initialize Models class: {e}")
            raise ConfigError(f"Models class initialization failed: {e}") from e

        self.http_client = httpx.AsyncClient(timeout=None)
        self.tools_schema_for_binding: List[Dict[str, Any]] = []
        self.mcp_tools_map: Dict[str, Any] = {}
        self.system_prompt_template: str = ""
        self.default_prompt = self.config.default_prompt
        self.max_tool_iterations = max_tool_iterations
        self.llm_cache = TTLCache(maxsize=cache_size, ttl=cache_ttl)
        self.tool_cache = TTLCache(maxsize=cache_size, ttl=cache_ttl)
        self.no_cache_tools = {"get_current_time", "fetch_realtime_data"}
        self.no_cache_query_patterns = ["current time", "latest news", "real-time"]

        self.plan_histories: Dict[str, List[BaseMessage]] = {}
        self.plan_counter = 0
        self.ongoing_plans: Dict[str, Dict[str, Any]] = {}

        self.max_history_messages_failsafe = int(os.getenv("MAX_HISTORY_MESSAGES_FAILSAFE", 99999))
        self.max_tokens = int(os.getenv("MAX_TOKENS", 300000)) 

        self.STREAM_INTERVAL_SECONDS = 300 

        self.gui_update_queue: Optional[queue.Queue] = None
        self.client_command_queue: Optional[asyncio.Queue] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None

        logger.info(
            f"Initialized MCPClient with LLM: {self.current_llm_id}. "
            f"Max tokens: {self.max_tokens}. Reflection Threshold: {self.REFLECTION_THRESHOLD}."
        )

    # --- Methods related to plan management, GUI events, caching, history truncation ---
    # (These methods: _extract_target_entity, _send_gui_event, send_gui_plan_update_event,
    #  get_next_plan_id, extract_dependencies, validate_dependencies, add_plan_to_ongoing,
    #  start_executing_plan, check_and_start_dependent_plans, execute_plan_wrapper,
    #  propagate_failure_or_cancellation, run_thought_process, print_plan_status,
    #  _format_tool_result_for_console, _estimate_tokens, _truncate_history,
    #  _prepare_system_prompt, _validate_schema, remove_title_from_schema,
    #  _should_bypass_cache, _generate_cache_key, _format_tool_result
    #  remain UNCHANGED from the previous version unless specified otherwise)

    def _extract_target_entity(self, text: str) -> Optional[str]: # Unchanged
        if not text:
            return None
        text_lower = text.lower()
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text_lower)
        if ip_match:
            return ip_match.group(0)
        try:
            if not text_lower.startswith(('http://', 'https://')) and '//' not in text_lower:
                parsed_url = urlparse(f"http://{text_lower}")
            else:
                parsed_url = urlparse(text_lower)
            if parsed_url.netloc:
                return parsed_url.netloc.split(':')[0]
        except Exception:
            pass
        domain_match = re.search(r'([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', text_lower)
        if domain_match:
            return domain_match.group(0)
        return None

    def _send_gui_event(self, event_data: Dict[str, Any]): # Unchanged
        if self.gui_update_queue:
            try:
                self.gui_update_queue.put_nowait(event_data)
            except queue.Full:
                logger.warning("GUI update queue is full. Discarding event.")
            except Exception as e:
                logger.error(f"Error sending event to GUI queue: {e}")
        else:
            logger.debug(f"GUI update queue not set. Event not sent: {event_data.get('type')}")

    def send_gui_plan_update_event(self, plan_id: str,
                                   event_type: str = "plan_update",
                                   event_description: Optional[str] = None,
                                   stream_content: Optional[Any] = None): # Unchanged
        if plan_id not in self.ongoing_plans and event_type not in ["plan_cleared", "all_plans_cleared", "plan_tab_closed"]:
             if plan_id not in self.plan_histories:
                logger.warning(f"Attempted to send GUI update for non-existent or incomplete plan_id: {plan_id} (Event: {event_type})")
                return
        plan_data_snapshot = self.ongoing_plans.get(plan_id, {}).copy()
        history_snapshot = []
        if plan_id in self.plan_histories:
            for msg in self.plan_histories[plan_id]:
                try:
                    history_snapshot.append(msg.dict())
                except Exception as e:
                    logger.error(f"Could not serialize message for GUI update (Plan {plan_id}): {type(msg)} - {e}")
                    history_snapshot.append({"type": type(msg).__name__, "content": str(msg.content if hasattr(msg, 'content') else 'N/A (serialization error)'), "error": "Serialization failed"})

        payload = {"type": event_type, "plan_id": plan_id}
        if event_type == "plan_stream_event" and stream_content is not None:
            payload["stream_content"] = stream_content
        else:
            payload["plan_data"] = plan_data_snapshot
            payload["full_history"] = history_snapshot
        if event_description:
            payload["event_description"] = event_description
        self._send_gui_event(payload) # Corrected: Was self.send_gui_event
        logger.debug(f"Sent '{event_type}' for plan '{plan_id}' to GUI. Desc: {event_description}")

    def get_next_plan_id(self) -> str: # Unchanged
        self.plan_counter += 1
        return f"plan_{self.plan_counter}"

    def extract_dependencies(self, query: str) -> tuple[str, List[str]]: # Unchanged
        dependencies = []
        task_part = query
        match = re.search(r"(.*)\s+after\s+((?:plan_\d+\s*(?:,|\band\b)?\s*)+)$", query, re.IGNORECASE)
        if match:
            task_part = match.group(1).strip()
            deps_str = match.group(2).strip()
            dependencies = re.findall(r"plan_\d+", deps_str)
            logger.info(f"Extracted task: '{task_part}', dependencies: {dependencies}")
        else:
            logger.debug(f"No dependencies found in query: '{query}'")
        return task_part, dependencies

    def validate_dependencies(self, dependencies: List[str]) -> None: # Unchanged
        for dep_id in dependencies:
            if dep_id not in self.ongoing_plans:
                logger.error(f"Dependency validation failed: Plan '{dep_id}' does not exist.")
                raise ValueError(f"Dependency plan '{dep_id}' does not exist.")
        logger.debug(f"Dependencies {dependencies} validated successfully.")

    async def add_plan_to_ongoing(self, query: str, dependencies: List[str]): # Unchanged
        plan_id = self.get_next_plan_id()
        logger.info(f"Adding new plan '{plan_id}' for query: '{query}' with dependencies: {dependencies}")
        self.plan_histories[plan_id] = [
            SystemMessage(content=self.system_prompt_template),
            HumanMessage(content=query)
        ]
        unfinished_dependencies_count = 0
        for dep_id in dependencies:
            dep_plan_data = self.ongoing_plans.get(dep_id)
            if not dep_plan_data or dep_plan_data.get("status") != "completed":
                unfinished_dependencies_count += 1
        initial_target = self._extract_target_entity(query)
        self.ongoing_plans[plan_id] = {
            "query": query, "status": "queued", "dependencies": dependencies,
            "unfinished_dependencies": unfinished_dependencies_count, "task": None,
            "result": None, "error": None, "thoughts": [], "tool_calls_log": [],
            "current_targets": {initial_target} if initial_target else set(),
            "has_active_tool_calls": False,
            "non_stp_tool_call_counter": 0 
        }
        self.send_gui_plan_update_event(plan_id, event_type="new_plan_created",
                                        event_description=f"Plan '{plan_id}' created and queued.")
        logger.info(f"Plan '{plan_id}' added. Unfinished dependencies: {unfinished_dependencies_count}. Initial target: {initial_target}")
        if unfinished_dependencies_count == 0:
            await self.start_executing_plan(plan_id)
        else:
            logger.info(f"Plan '{plan_id}' is queued, waiting for {unfinished_dependencies_count} dependencies.")

    async def start_executing_plan(self, plan_id: str): # Unchanged
        plan_data = self.ongoing_plans.get(plan_id)
        if not plan_data:
            logger.error(f"Cannot start plan '{plan_id}': Not found.")
            return
        if plan_data["status"] == "queued" and plan_data["unfinished_dependencies"] == 0:
            logger.info(f"Starting execution for plan '{plan_id}'.")
            plan_data["status"] = "running"
            plan_data["task"] = asyncio.create_task(self.execute_plan_wrapper(plan_id), name=f"PlanTask-{plan_id}")
            self.send_gui_plan_update_event(plan_id, event_description=f"Plan '{plan_id}' starting execution.")
        elif plan_data["status"] != "queued":
            logger.warning(f"Plan '{plan_id}' is not queued (status: {plan_data['status']}). Cannot start.")
        elif plan_data["unfinished_dependencies"] > 0:
            logger.warning(f"Plan '{plan_id}' has unmet dependencies ({plan_data['unfinished_dependencies']}). Cannot start.")

    async def check_and_start_dependent_plans(self, completed_plan_id: str): # Unchanged
        logger.info(f"Plan '{completed_plan_id}' completed. Checking for dependent plans.")
        for plan_id, plan_data in self.ongoing_plans.items():
            if plan_data["status"] == "queued" and completed_plan_id in plan_data["dependencies"]:
                plan_data["unfinished_dependencies"] -= 1
                logger.info(f"Plan '{plan_id}' dependency '{completed_plan_id}' met. "
                            f"Remaining unfinished dependencies: {plan_data['unfinished_dependencies']}")
                self.send_gui_plan_update_event(plan_id, event_description=f"Dependency '{completed_plan_id}' met for plan '{plan_id}'.")
                if plan_data["unfinished_dependencies"] == 0:
                    await self.start_executing_plan(plan_id)

    async def execute_plan_wrapper(self, plan_id: str): # Unchanged
        plan_data = self.ongoing_plans.get(plan_id)
        if not plan_data:
            logger.error(f"execute_plan_wrapper: Plan '{plan_id}' not found.")
            return
        logger.info(f"Executing plan wrapper for '{plan_id}'.")
        try:
            if plan_data['status'] != 'running':
                plan_data['status'] = 'running'
                logger.info(f"Plan '{plan_id}' status set to 'running'.")
            result = await self.run_thought_process(plan_id)
            plan_data['status'] = 'completed'
            plan_data['result'] = result
            logger.info(f"Plan '{plan_id}' completed successfully. Result: {str(result)[:200]}...")
            await self.check_and_start_dependent_plans(plan_id)
        except asyncio.CancelledError:
            plan_data = self.ongoing_plans.get(plan_id)
            if plan_data:
                plan_data['status'] = 'cancelled'
                plan_data['error'] = 'Execution was cancelled by user or system.'
                logger.warning(f"Plan '{plan_id}' was cancelled.")
            self.propagate_failure_or_cancellation(plan_id, is_cancellation=True)
        except MaxToolIterationsError as e:
            if plan_id in self.ongoing_plans:
                self.ongoing_plans[plan_id]['status'] = 'failed'
                self.ongoing_plans[plan_id]['error'] = str(e)
            logger.error(f"Plan '{plan_id}' failed due to max tool iterations: {e}", exc_info=True)
            self.propagate_failure_or_cancellation(plan_id)
        except Exception as e:
            if plan_id in self.ongoing_plans:
                self.ongoing_plans[plan_id]['status'] = 'failed'
                self.ongoing_plans[plan_id]['error'] = str(e)
            logger.error(f"Plan '{plan_id}' failed with an unexpected error: {e}", exc_info=True)
            self.propagate_failure_or_cancellation(plan_id)
        finally:
            if plan_id in self.ongoing_plans:
                 self.send_gui_plan_update_event(plan_id, event_description=f"Plan '{plan_id}' execution wrapper finished.")

    def propagate_failure_or_cancellation(self, failed_or_cancelled_plan_id: str, is_cancellation: bool = False): # Unchanged
        status_to_set = "cancelled" if is_cancellation else "failed"
        reason = "dependency cancelled" if is_cancellation else "dependency failed"
        logger.info(f"Propagating '{status_to_set}' status from plan '{failed_or_cancelled_plan_id}'.")
        for plan_id, plan_data in self.ongoing_plans.items():
            if failed_or_cancelled_plan_id in plan_data.get("dependencies", []) and \
               plan_data["status"] in ["queued", "running"]:
                logger.warning(f"Plan '{plan_id}' is being marked as '{status_to_set}' due to '{failed_or_cancelled_plan_id}'.")
                plan_data["status"] = status_to_set
                plan_data["error"] = plan_data.get("error", "") + f"; Upstream {reason}: '{failed_or_cancelled_plan_id}'"
                self.send_gui_plan_update_event(plan_id, event_description=f"Plan '{plan_id}' {status_to_set} due to upstream {failed_or_cancelled_plan_id}.")
                task = plan_data.get("task")
                if task and not task.done():
                    logger.info(f"Cancelling task for dependent plan '{plan_id}'.")
                    task.cancel()
                self.propagate_failure_or_cancellation(plan_id, is_cancellation=(is_cancellation or plan_data["status"] == "cancelled"))

    async def run_thought_process(self, plan_id: str): # Unchanged
        history_ref = self.plan_histories.get(plan_id)
        plan_data = self.ongoing_plans.get(plan_id)

        if not history_ref or not plan_data:
            err_msg = f"Plan data or history missing for '{plan_id}'."
            logger.error(f"Cannot run thought process: {err_msg}")
            if plan_data:
                plan_data['status'] = 'failed'
                plan_data['error'] = err_msg
                self.send_gui_plan_update_event(plan_id, event_description=f"Plan '{plan_id}' failed: {err_msg}")
            raise ValueError(err_msg)

        logger.info(f"Starting thought process for plan '{plan_id}'. Initial history length: {len(history_ref)}")
        self.send_gui_plan_update_event(plan_id, event_description=f"Plan '{plan_id}' starting thought process.")

        if 'non_stp_tool_call_counter' not in plan_data:
            plan_data['non_stp_tool_call_counter'] = 0

        for iteration in range(self.max_tool_iterations):
            logger.debug(f"Plan '{plan_id}', Iteration {iteration + 1}/{self.max_tool_iterations}")

            if plan_data.get('has_active_tool_calls', False):
                logger.info(f"Plan '{plan_id}' has active tool calls. LLM will wait for tools to complete before next thought.")
                await asyncio.sleep(1) 
                continue

            current_history_for_llm_processing = list(history_ref) 
            current_history_for_llm_processing = self._truncate_history(current_history_for_llm_processing)

            try:
                ai_response = await self._invoke_llm(current_history_for_llm_processing)
                history_ref.append(ai_response)
                logger.debug(f"Plan '{plan_id}': LLM response received. Content: {str(ai_response.content)[:100]}..., Tool calls: {ai_response.tool_calls}")
                self.send_gui_plan_update_event(plan_id, event_description="LLM response received.")

                if not ai_response.tool_calls and not (hasattr(ai_response, 'additional_kwargs') and ai_response.additional_kwargs.get('tool_calls')):
                    final_answer = ai_response.content
                    # Check for effectively empty content before declaring completion
                    if not final_answer or final_answer.strip() == "":
                        logger.warning(f"Plan '{plan_id}': LLM returned empty content and no tool calls at iteration {iteration + 1}. This might indicate an issue or premature completion.")
                        # Optionally, add a HumanMessage to history_ref to prompt LLM for clarification and 'continue' the loop
                        # For now, we'll let it complete with the (empty) final_answer.
                    logger.info(f"Plan '{plan_id}' completed with final answer (Content: '{str(final_answer)[:50]}...') after {iteration + 1} iterations.")
                    return final_answer

                tool_calls_to_process = ai_response.tool_calls
                if not tool_calls_to_process and hasattr(ai_response, 'additional_kwargs'):
                    tool_calls_to_process = ai_response.additional_kwargs.get('tool_calls', [])

                if not tool_calls_to_process: # Should be caught by the above check, but defensive
                    logger.warning(f"Plan '{plan_id}': LLM indicated tool use but no tool_calls found. Assuming completion with content: {ai_response.content}")
                    return ai_response.content
                
                for tool_call in tool_calls_to_process:
                    tool_name = tool_call['name']
                    tool_args = ic(tool_call.get('args', {})) 
                    tool_call_id = tool_call['id']
                    logger.info(f"Plan '{plan_id}': Processing tool call '{tool_name}' with ID '{tool_call_id}' and args: {tool_args}")

                    self.send_gui_plan_update_event(plan_id, event_type="plan_stream_event",
                                                    event_description=f"Executing tool: {tool_name}",
                                                    stream_content={"type": "tool_initiation", "tool_name": tool_name, "args": tool_args})

                    if tool_name == "SequentialThinkingPlanner":
                        thought_details = {
                            'thought': tool_args.get('thought', 'No thought provided'),
                            'thoughtNumber': tool_args.get('thoughtNumber', 'N/A'),
                            'totalThoughts': tool_args.get('totalThoughts', 'N/A'),
                            'isRevision': tool_args.get('isRevision', False),
                            'revisesThought': tool_args.get('revisesThought', None),
                            'branchFromThought': tool_args.get('branchFromThought', None),
                            'timestamp': datetime.now().isoformat(),
                            'nextThoughtNeeded': tool_args.get('nextThoughtNeeded', True)
                        }
                        plan_data['thoughts'].append(thought_details)
                        logger.info(f"Plan '{plan_id}': Logged thought: {thought_details['thought']}")
                        
                        tool_message_parts = [
                            f"Thought #{thought_details['thoughtNumber']} ('{thought_details['thought']}') was recorded.",
                            "Based on this thought and previous results (if any), what is the next immediate tool to call or the next thought to plan?",
                            "If a tool is needed, call it directly. If more planning is needed, use SequentialThinkingPlanner.",
                            "If the goal is achieved, provide the final answer without any tool calls."
                        ]
                        if not thought_details['nextThoughtNeeded']:
                            tool_message_parts.append("You indicated no further thoughts are immediately needed. Please either provide the final answer or call a concluding tool.")
                        tool_message_content = " ".join(tool_message_parts)

                        history_ref.append(ToolMessage(content=tool_message_content, tool_call_id=tool_call_id))
                        self.send_gui_plan_update_event(plan_id, event_description="Thought recorded with enhanced guidance.")
                        plan_data['non_stp_tool_call_counter'] = 0
                    else:
                        tool_result_data = await self._execute_mcp_tool(tool_name, tool_args, plan_id)
                        formatted_tool_result_for_llm = self._format_tool_result(tool_result_data, tool_name)
                        history_ref.append(ToolMessage(content=formatted_tool_result_for_llm, tool_call_id=tool_call_id))
                        self.send_gui_plan_update_event(plan_id, event_description=f"Tool '{tool_name}' execution finished and result added to history.")

                        plan_data['non_stp_tool_call_counter'] += 1
                        logger.debug(f"Plan '{plan_id}' non-STP tool call counter: {plan_data['non_stp_tool_call_counter']}")

                        trigger_reflection = False
                        if plan_data['non_stp_tool_call_counter'] >= self.REFLECTION_THRESHOLD:
                            logger.info(f"Plan '{plan_id}' reached reflection threshold ({self.REFLECTION_THRESHOLD}). Triggering plan review.")
                            trigger_reflection = True
                        
                        if trigger_reflection:
                            current_thoughts_summary = [f"Thought {idx+1}: {t.get('thought', 'N/A')}" for idx, t in enumerate(plan_data.get('thoughts', []))]
                            thoughts_str = "\n".join(current_thoughts_summary) if current_thoughts_summary else "No thoughts recorded yet."
                            
                            reflection_prompt_content = (
                                f"PLAN REVIEW:\nYou have executed {plan_data['non_stp_tool_call_counter']} tool calls since the last full plan review (or start).\n"
                                f"The original goal is: '{plan_data.get('query', 'N/A')}'\n"
                                f"Current recorded thoughts are:\n{thoughts_str}\n"
                                "Consider the recent tool outputs and the overall progress.\n"
                                "Based on this, critically assess the current plan:\n"
                                "- Is it still optimal for achieving the original goal?\n"
                                "- Are there any flawed assumptions or outdated thoughts?\n"
                                "- Does the plan need adjustment or revision?\n"
                                "Use 'SequentialThinkingPlanner' to explicitly state your assessment. If revisions are needed, use STP's revision features (e.g., `isRevision=True`, `revisesThought=[number]`, `branchFromThought=[number]`) to modify the plan. Clearly explain your reasoning for any changes. If the plan is sound and no changes are needed, briefly state this using STP and then proceed with the next planned step or use STP for the next thought in your original plan."
                            )
                            history_ref.append(HumanMessage(content=reflection_prompt_content))
                            plan_data['non_stp_tool_call_counter'] = 0 
                            logger.info(f"Plan '{plan_id}': Injected PLAN REVIEW message into history.")
                            self.send_gui_plan_update_event(plan_id, event_description="PLAN REVIEW prompted.")

            except RuntimeError as e: 
                logger.error(f"Runtime error during thought process for plan '{plan_id}': {e}", exc_info=True)
                history_ref.append(AIMessage(content=f"Critical Error: {str(e)} Halting plan."))
                raise 
            except Exception as e: 
                logger.error(f"Unexpected error in thought process for plan '{plan_id}', iteration {iteration + 1}: {e}", exc_info=True)
                history_ref.append(AIMessage(content=f"Error encountered: {str(e)}. Attempting to recover or terminate."))
                raise ToolExecutionError(f"Failed during tool processing or LLM interaction in plan '{plan_id}': {e}") from e

        logger.warning(f"Plan '{plan_id}' reached maximum tool iterations ({self.max_tool_iterations}).")
        raise MaxToolIterationsError(f"Plan '{plan_id}' exceeded {self.max_tool_iterations} tool iterations.")

    def print_plan_status(self) -> None: # Unchanged
        if not self.ongoing_plans:
            print("No ongoing plans.")
            return
        print(f"\n--- Plans Overview (Total: {len(self.ongoing_plans)}) ---")
        for plan_id, info in sorted(self.ongoing_plans.items()):
            status = info.get('status', 'Unknown')
            query_preview = info.get('query', 'N/A')[:50] + "..." if info.get('query') and len(info.get('query', '')) > 50 else info.get('query', 'N/A')
            deps = info.get('dependencies', [])
            unfinished_deps = info.get('unfinished_dependencies', 0)
            active_tools = info.get('has_active_tool_calls', False)
            targets = info.get('current_targets', set())
            non_stp_calls = info.get('non_stp_tool_call_counter', 0)
            details = f"Query: '{query_preview}', Deps: {deps}, Unfinished Deps: {unfinished_deps}, ActiveTools: {active_tools}, Targets: {targets}, NonSTPCalls: {non_stp_calls}"
            if status == 'failed':
                error_msg = str(info.get('error', 'Unknown error'))[:100]
                details += f" - Error: {error_msg}..." if len(str(info.get('error', ''))) > 100 else f" - Error: {error_msg}"
            elif status == 'completed':
                result_preview = str(info.get('result', 'N/A'))[:70]
                details += f" - Result: {result_preview}..." if len(str(info.get('result', ''))) > 70 else f" - Result: {result_preview}"
            print(f"  Plan {plan_id}: {status.upper()} - {details}")
        print("------------------------------------")

    def _format_tool_result_for_console(self, tool_result: Any, tool_name: str) -> str: # Unchanged
        if isinstance(tool_result, dict):
            if "error" in tool_result:
                return f"Error from {tool_name}: {tool_result['error']}"
            try:
                pretty_json = json.dumps(tool_result, indent=2, sort_keys=True)
                if len(pretty_json) > 2000:
                    return pretty_json[:2000] + "\n... (result truncated for console)"
                return pretty_json
            except (TypeError, OverflowError):
                str_repr = str(tool_result)
                if len(str_repr) > 2000:
                    return str_repr[:2000] + "\n... (result truncated for console)"
                return str_repr
        else:
            str_repr = str(tool_result)
            if len(str_repr) > 2000:
                return str_repr[:2000] + "\n... (result truncated for console)"
            return str_repr

    def _estimate_tokens(self, messages: List[BaseMessage]) -> int: # Unchanged
        total_tokens = 0
        for msg_idx, msg in enumerate(messages):
            content_str = ""
            current_message_tokens = 0
            if hasattr(msg, "content"):
                if isinstance(msg.content, str):
                    content_str = msg.content
                elif isinstance(msg.content, list): 
                    for part in msg.content:
                        if isinstance(part, dict) and "text" in part:
                            content_str += part["text"] + " "
            tool_calls_str = ""
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                try: tool_calls_str = json.dumps(msg.tool_calls)
                except TypeError: tool_calls_str = str(msg.tool_calls)
            elif hasattr(msg, 'additional_kwargs') and msg.additional_kwargs.get('tool_calls'):
                try: tool_calls_str = json.dumps(msg.additional_kwargs['tool_calls'])
                except TypeError: tool_calls_str = str(msg.additional_kwargs['tool_calls'])
            
            full_message_text_for_tokenization = content_str
            if tool_calls_str:
                full_message_text_for_tokenization += " " + tool_calls_str
            
            if full_message_text_for_tokenization:
                segments = re.findall(r'\w+|[^\w\s]', full_message_text_for_tokenization, re.UNICODE)
                current_message_tokens = len(segments)
            
            current_message_tokens += 5 
            total_tokens += current_message_tokens
        logger.debug(f"Estimated total tokens for {len(messages)} messages: {total_tokens}")
        return total_tokens

    def _truncate_history(self, history_copy: List[BaseMessage], force_truncate: bool = False) -> List[BaseMessage]: # Unchanged
        current_tokens = self._estimate_tokens(history_copy)
        needs_truncation = force_truncate or \
                           current_tokens > self.max_tokens or \
                           len(history_copy) > self.max_history_messages_failsafe

        if not needs_truncation:
            return history_copy

        logger.warning(f"Truncating history copy. Current tokens: {current_tokens} (Max: {self.max_tokens}), Msgs: {len(history_copy)}. "
                       f"Triggered by: {'force_truncate' if force_truncate else 'token/msg_limit'}.")

        system_messages = [m for m in history_copy if isinstance(m, SystemMessage)]
        other_messages = [m for m in history_copy if not isinstance(m, SystemMessage)]

        while self._estimate_tokens(system_messages + other_messages) > self.max_tokens:
            if len(other_messages) > 0:
                removed_msg_type = type(other_messages[0]).__name__
                removed_msg_tokens = self._estimate_tokens([other_messages[0]])
                logger.debug(f"Token-based truncation on copy: Tokens {self._estimate_tokens(system_messages + other_messages)} > {self.max_tokens}. "
                             f"Removing oldest non-system message ({removed_msg_type}, ~{removed_msg_tokens} tokens).")
                other_messages.pop(0)
            else: 
                logger.error(f"CRITICAL (in _truncate_history on copy): System messages alone ({self._estimate_tokens(system_messages)} tokens) "
                             f"exceed max_tokens ({self.max_tokens}). Cannot truncate further by removing non-system messages.")
                break 

        final_history_for_llm = system_messages + other_messages
        final_tokens = self._estimate_tokens(final_history_for_llm)
        logger.info(f"History copy truncation complete. Final length for LLM: {len(final_history_for_llm)} msgs, Tokens: {final_tokens}.")

        if final_tokens > self.max_tokens: 
            logger.error(f"CRITICAL (in _truncate_history on copy): History copy for LLM still exceeds token limit ({final_tokens}/{self.max_tokens}) after message removal.")
            if not other_messages and system_messages: 
                 logger.error("Truncation of copy resulted in only system messages, which still exceed token limit.")
            elif len(other_messages) == 1: 
                 logger.error("The single remaining non-system message in copy, combined with system messages, exceeds token limit.")
        
        return final_history_for_llm

    async def _prepare_system_prompt(self) -> None: # Unchanged
        prompts_url = f"{self.config.server_base_url}/mcp/prompts"
        tool_descriptions_list = []
        for name, tool_info in self.mcp_tools_map.items():
            description = tool_info.get('description', f"Tool named '{name}' with no detailed description.")
            params_overview = ""
            if tool_info.get('parameters') and tool_info['parameters'].get('properties'):
                param_names = list(tool_info['parameters']['properties'].keys())
                if param_names:
                    params_overview = f" (Params: {', '.join(param_names[:3])}{'...' if len(param_names) > 3 else ''})"
            tool_descriptions_list.append(f"- {name}{params_overview}: {description}")
        
        tool_descriptions_str = "\n".join(tool_descriptions_list)
        if not tool_descriptions_str:
            tool_descriptions_str = "No tools are currently available for use."

        logger.info(f"Attempting to fetch system prompt from: {prompts_url}")
        try:
            if self.http_client.is_closed:
                logger.info("HTTP client was closed. Reinitializing.")
                self.http_client = httpx.AsyncClient(timeout=None)

            async with aconnect_sse(self.http_client, "GET", prompts_url) as event_source:
                async for sse in event_source.aiter_sse():
                    if sse.event == "prompt":
                        data = json.loads(sse.data) if sse.data and sse.data.strip() else {}
                        prompt_template = data.get('prompt', self.default_prompt)
                        self.system_prompt_template = prompt_template.replace('{functions}', tool_descriptions_str)
                        logger.info("System prompt template successfully fetched and prepared.")
                        return
                    elif sse.event == "error":
                        error_msg = sse.data if sse.data and sse.data.strip() else "Unknown server error"
                        logger.warning(f"Server error fetching system prompt: {error_msg}. Using default prompt.")
                        self.system_prompt_template = self.default_prompt.replace('{functions}', tool_descriptions_str)
                        return
            
            logger.warning("No 'prompt' or 'error' event received from SSE for system prompt. Using default prompt.")
            self.system_prompt_template = self.default_prompt.replace('{functions}', tool_descriptions_str)

        except httpx.RequestError as e:
            logger.error(f"HTTP request error fetching system prompt from {prompts_url}: {e}", exc_info=True)
            self.system_prompt_template = self.default_prompt.replace('{functions}', tool_descriptions_str)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error processing system prompt response: {e}", exc_info=True)
            self.system_prompt_template = self.default_prompt.replace('{functions}', tool_descriptions_str)
        except Exception as e:
            logger.error(f"Unexpected error fetching system prompt: {e}", exc_info=True)
            self.system_prompt_template = self.default_prompt.replace('{functions}', tool_descriptions_str)
        finally:
            logger.debug(f"Final system prompt template (first 200 chars): {self.system_prompt_template[:200]}...")

    def _validate_schema(self, params_schema: Dict[str, Any], tool_name: str = "UnknownTool") -> bool: # Unchanged
        if not isinstance(params_schema, dict):
            logger.warning(f"Schema validation failed for '{tool_name}': Schema is not a dictionary. Schema: {params_schema}")
            return False
        required_top_level_fields = ['type', 'properties']
        if not all(field in params_schema for field in required_top_level_fields):
            logger.warning(f"Schema validation failed for '{tool_name}': Missing required fields ('type', 'properties'). Schema: {params_schema}")
            return False
        if params_schema.get('type') != 'object':
            if params_schema.get('properties') is None or params_schema.get('properties') == {}:
                 logger.debug(f"Schema for '{tool_name}' is type '{params_schema.get('type')}' and has no properties. Valid for no-arg tools.")
                 return True
            else:
                 logger.warning(f"Schema validation failed for '{tool_name}': Type is '{params_schema.get('type')}' but 'properties' field is non-empty. Schema: {params_schema}")
                 return False 
        if not isinstance(params_schema.get('properties'), dict):
            logger.warning(f"Schema validation failed for '{tool_name}': 'properties' is not a dictionary for object type. Schema: {params_schema}")
            return False
        return True

    def remove_title_from_schema(self, schema: Any) -> Any: # Unchanged
        if isinstance(schema, dict):
            return {k: self.remove_title_from_schema(v) for k, v in schema.items() if k != 'title'}
        elif isinstance(schema, list):
            return [self.remove_title_from_schema(item) for item in schema]
        else:
            return schema

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(5),
        retry=retry_if_exception_type((httpx.ConnectError, httpx.ReadTimeout, ConnectionError))
    )
    async def initialize_tools(self): # Unchanged
        tools_url = f"{self.config.server_base_url}/mcp/tools"
        logger.info(f"Attempting to initialize tools from: {tools_url}")
        try:
            if self.http_client.is_closed:
                logger.info("HTTP client was closed. Reinitializing for tool initialization.")
                self.http_client = httpx.AsyncClient(timeout=None)

            async with aconnect_sse(self.http_client, "GET", tools_url) as event_source:
                async for sse in event_source.aiter_sse():
                    if sse.event == "tools_list":
                        try: data = json.loads(sse.data)
                        except json.JSONDecodeError as e:
                            logger.error(f"Failed to decode JSON from tools_list SSE event: {e}. Data: {sse.data[:200]}...")
                            raise ConnectionError(f"Invalid JSON received for tools list: {e}") from e
                        
                        server_tools = data.get("available_tools", [])
                        if not server_tools: logger.warning("Received empty 'available_tools' list from server.")
                        
                        self.mcp_tools_map = {tool['name']: tool for tool in server_tools if 'name' in tool}
                        valid_schemas_for_binding = []
                        for tool in server_tools:
                            tool_name = tool.get('name')
                            if not tool_name: 
                                logger.warning(f"Found a tool without a name in server response: {tool}"); continue
                            
                            if 'parameters' in tool and self._validate_schema(tool['parameters'], tool_name):
                                cleaned_params = self.remove_title_from_schema(tool['parameters'])
                                valid_schemas_for_binding.append({
                                    "name": tool_name, 
                                    "description": tool.get('description', f"Tool named {tool_name}"), 
                                    "parameters": cleaned_params
                                })
                                logger.debug(f"Tool '{tool_name}' schema validated and added for LLM binding.")
                            else:
                                logger.warning(f"Tool '{tool_name}' has no valid 'parameters' schema or failed validation. Skipping for LLM binding. Schema: {tool.get('parameters')}")
                        
                        self.tools_schema_for_binding = valid_schemas_for_binding
                        self.models.initializeTools(self.tools_schema_for_binding) 
                        await self._prepare_system_prompt() 
                        
                        logger.info(f"MCPClient tools initialized. {len(self.tools_schema_for_binding)} tools configured for LLM binding. "
                                    f"{len(self.mcp_tools_map) - len(self.tools_schema_for_binding)} tools skipped due to schema issues.")
                        return 
                    
                    elif sse.event == "error":
                        error_msg = sse.data if sse.data and sse.data.strip() else "Unknown server error"
                        logger.error(f"Server error during tool initialization (SSE 'error' event): {error_msg}")
                        raise ConnectionError(f"Server error fetching tools: {error_msg}")
            
            logger.error("No 'tools_list' or 'error' event received from SSE for tools after stream ended.")
            raise ConnectionError("Failed to receive tools list from server (stream ended prematurely).")

        except httpx.ConnectError as e:
            logger.warning(f"HTTP ConnectError fetching tools from {tools_url} (will retry if attempts remain): {e}")
            raise 
        except httpx.ReadTimeout as e:
            logger.warning(f"HTTP ReadTimeout fetching tools from {tools_url} (will retry if attempts remain): {e}")
            raise 
        except ConnectionError as e: 
            logger.warning(f"ConnectionError during tool initialization (will retry if attempts remain): {e}")
            raise 
        except httpx.RequestError as e: 
            logger.error(f"HTTP request error fetching tools from {tools_url}: {e}", exc_info=True)
            raise ConnectionError(f"HTTP request error fetching tools: {e}") from e
        except Exception as e: 
            logger.error(f"Unexpected error initializing tools: {e}", exc_info=True)
            self.models.initializeTools([]) 
            await self._prepare_system_prompt() 
            logger.warning("Initialized with NO TOOLS due to an error during tool fetching. System prompt set to default.")
            raise ConnectionError(f"Unexpected critical error initializing tools: {e}") from e

    def _should_bypass_cache(self, query: str, tool_name: Optional[str] = None) -> bool: # Unchanged
        if tool_name and tool_name in self.no_cache_tools:
            logger.debug(f"Bypassing cache for tool: {tool_name}")
            return True
        if isinstance(query, str) and any(pattern.lower() in query.lower() for pattern in self.no_cache_query_patterns):
            logger.debug(f"Bypassing cache due to query pattern: {query[:50]}...")
            return True
        return False

    def _generate_cache_key(self, *args, **kwargs) -> str: # Unchanged
        key_components = []
        for arg in args:
            if isinstance(arg, list) and all(isinstance(item, BaseMessage) for item in arg):
                key_components.append([m.dict() for m in arg]) 
            elif isinstance(arg, BaseMessage):
                key_components.append(arg.dict())
            else:
                key_components.append(arg)
        
        sorted_kwargs = {}
        for k, v in sorted(kwargs.items()):
            if isinstance(v, list) and all(isinstance(item, BaseMessage) for item in v):
                sorted_kwargs[k] = [m.dict() for m in v]
            elif isinstance(v, BaseMessage):
                sorted_kwargs[k] = v.dict()
            else:
                sorted_kwargs[k] = v
        try:
            key_str = json.dumps(key_components + [sorted_kwargs], sort_keys=True)
        except TypeError as e:
            logger.warning(f"Could not fully serialize args/kwargs for cache key, generating less specific key: {e}. Args: {args}, Kwargs: {kwargs}")
            key_str = f"{str(args)}_{str(kwargs)}" 
        return hashlib.md5(key_str.encode('utf-8')).hexdigest()

    async def _execute_mcp_tool(self, tool_name: str, tool_args: Dict[str, Any], plan_id: str) -> Dict[str, Any]: # Unchanged
        cache_key = None
        if not self._should_bypass_cache("", tool_name): 
            cache_key = self._generate_cache_key("mcp_tool", tool_name, tool_args)
            if cache_key in self.tool_cache:
                cached_data = self.tool_cache[cache_key]
                logger.info(f"Returning cached result for tool '{tool_name}' with args {tool_args}")
                plan_data = self.ongoing_plans.get(plan_id)
                if plan_data:
                    tool_log_entry = {
                        'tool_name': tool_name, 'tool_args': tool_args, 'status': 'completed (cached)',
                        'timestamp_start': datetime.now().isoformat() + "Z",
                        'stream_events': [{'timestamp': datetime.now().isoformat() + "Z",
                                           'status_message': 'Result retrieved from cache.',
                                           'details': {'source': 'cache'}}],
                        'final_event_data': {'status': 'completed', 'result_payload': cached_data, 'tool_name': tool_name, 'timestamp_completion': datetime.now().isoformat() + "Z"},
                        'formatted_result_for_llm': self._format_tool_result(cached_data, tool_name),
                        'error_info': None, 'timestamp_end': datetime.now().isoformat() + "Z"
                    }
                    if 'tool_calls_log' not in plan_data: plan_data['tool_calls_log'] = []
                    plan_data['tool_calls_log'].append(tool_log_entry)
                    self.send_gui_plan_update_event(plan_id, event_description=f"Tool '{tool_name}' result from cache logged.")
                return cached_data

        if tool_name not in self.mcp_tools_map:
            logger.error(f"Tool '{tool_name}' not available in mcp_tools_map. Cannot execute.")
            error_payload_for_log = {"message": f"Tool '{tool_name}' not available or configured.", "type": "ToolNotAvailableError"}
            plan_data = self.ongoing_plans.get(plan_id)
            if plan_data:
                if 'tool_calls_log' not in plan_data: plan_data['tool_calls_log'] = []
                plan_data['tool_calls_log'].append({
                    'tool_name': tool_name, 'tool_args': tool_args, 'status': 'failed',
                    'timestamp_start': datetime.now().isoformat() + "Z", 'stream_events': [],
                    'final_event_data': {'status': 'failed', 'error_payload': error_payload_for_log, 'tool_name': tool_name, 'timestamp_completion': datetime.now().isoformat() + "Z"},
                    'formatted_result_for_llm': self._format_tool_result(error_payload_for_log, tool_name),
                    'error_info': error_payload_for_log, 'timestamp_end': datetime.now().isoformat() + "Z"
                })
                self.send_gui_plan_update_event(plan_id, event_description=f"Tool '{tool_name}' not available.")
            return {"error": error_payload_for_log["message"], "details": error_payload_for_log}

        plan_data = self.ongoing_plans.get(plan_id)
        current_tool_log_entry_index = -1 
        if plan_data:
            plan_data['has_active_tool_calls'] = True
            tool_target = None 
            if 'domain' in tool_args: tool_target = self._extract_target_entity(str(tool_args['domain']))
            elif 'start_url' in tool_args: tool_target = self._extract_target_entity(str(tool_args['start_url']))
            elif 'target_domain' in tool_args: tool_target = self._extract_target_entity(str(tool_args['target_domain']))
            elif 'technology' in tool_args: tool_target = self._extract_target_entity(str(tool_args['technology']))
            elif 'query' in tool_args: tool_target = self._extract_target_entity(str(tool_args['query']))
            
            if tool_target:
                plan_data.setdefault('current_targets', set()).add(tool_target)
                logger.info(f"Plan '{plan_id}' current targets updated with '{tool_target}' for tool '{tool_name}'. All targets: {plan_data['current_targets']}")

            if 'tool_calls_log' not in plan_data: plan_data['tool_calls_log'] = []
            new_log_entry = {
                'tool_name': tool_name, 'tool_args': tool_args, 'status': 'running',
                'timestamp_start': datetime.now().isoformat() + "Z", 'stream_events': [],
                'final_event_data': None, 'formatted_result_for_llm': None,
                'error_info': None, 'timestamp_end': None
            }
            plan_data['tool_calls_log'].append(new_log_entry)
            current_tool_log_entry_index = len(plan_data['tool_calls_log']) - 1 
            self.send_gui_plan_update_event(plan_id, event_description=f"Tool '{tool_name}' initiated. Active calls: True. Targets: {plan_data.get('current_targets')}")

        @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10),
               retry_error_callback=lambda retry_state: { 
                   "status": "failed",
                   "error_payload": {"message": f"Tool '{tool_name}' failed after {retry_state.attempt_number} attempts: {retry_state.outcome.exception()}", "type": "RetryLimitExceededError"},
                    "tool_name": tool_name, "timestamp_completion": datetime.now().isoformat() + "Z"
                })
        async def execute_with_retry_sse():
            if self.http_client.is_closed:
                logger.info("HTTP client was closed. Reinitializing for tool execution.")
                self.http_client = httpx.AsyncClient(timeout=None)
            
            current_tool_args = tool_args if isinstance(tool_args, dict) else {}
            try:
                encoded_args = urllib.parse.quote(json.dumps(current_tool_args))
            except TypeError as e: 
                logger.error(f"Failed to JSON encode arguments for tool '{tool_name}': {e}. Args: {current_tool_args}")
                raise ToolExecutionError(f"Invalid arguments for tool '{tool_name}', could not serialize: {e}") from e

            tool_url = f"{self.config.server_base_url}/mcp/tools/{tool_name}?arguments={encoded_args}"
            logger.info(f"Executing MCP tool (normalized): GET {tool_url} (Plan: {plan_id})")
            
            final_sse_data_payload = None
            try:
                async with aconnect_sse(self.http_client, "GET", tool_url) as event_source:
                    async for sse in event_source.aiter_sse():
                        logger.debug(f"SSE event from tool '{tool_name}' (Plan {plan_id}): {sse.event}, Data (first 100): {sse.data[:100]}...")
                        parsed_sse_data = None
                        try:
                            if sse.data and sse.data.strip(): parsed_sse_data = json.loads(sse.data)
                        except json.JSONDecodeError:
                            logger.warning(f"Non-JSON SSE data from '{tool_name}' (Plan {plan_id}): {sse.data[:200]}...")
                            stream_event_data = {"timestamp": datetime.now().isoformat() + "Z", "status_message": "Received malformed/non-JSON stream data.", "details": {"raw_data": sse.data[:200]}}
                            if plan_data and current_tool_log_entry_index != -1: 
                                plan_data['tool_calls_log'][current_tool_log_entry_index]['stream_events'].append(stream_event_data)
                            self.send_gui_plan_update_event(plan_id, event_type="plan_stream_event", stream_content=stream_event_data)
                            continue 

                        if sse.event == "tool_progress":
                            if plan_data and current_tool_log_entry_index != -1 and parsed_sse_data: 
                                log_entry = plan_data['tool_calls_log'][current_tool_log_entry_index]
                                if log_entry['status'] == 'running': 
                                    log_entry['stream_events'].append(parsed_sse_data)
                                    self.send_gui_plan_update_event(plan_id, event_type="plan_stream_event", stream_content=parsed_sse_data)
                        elif sse.event == "tool_result":
                            final_sse_data_payload = parsed_sse_data
                            logger.info(f"Tool '{tool_name}' (Plan {plan_id}) provided final tool_result via SSE.")
                            break 
                        elif sse.event == "error": 
                            logger.error(f"Received generic 'error' SSE event from tool '{tool_name}': {parsed_sse_data}. Converting to failed tool_result.")
                            final_sse_data_payload = {
                                "status": "failed", 
                                "error_payload": parsed_sse_data if isinstance(parsed_sse_data, dict) else {"message": str(parsed_sse_data)}, 
                                "tool_name": tool_name, 
                                "timestamp_completion": datetime.now().isoformat() + "Z"
                            }
                            break 
                        await asyncio.sleep(0.01) 
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP Status Error connecting to tool '{tool_name}' SSE: {e.response.status_code} - {e.response.text}", exc_info=True)
                raise ConnectionError(f"Tool endpoint error for '{tool_name}': {e.response.status_code}") from e
            except httpx.RequestError as e: 
                logger.error(f"Request Error connecting to tool '{tool_name}' SSE: {e}", exc_info=True)
                raise ConnectionError(f"Network error for tool '{tool_name}': {e}") from e
            
            if final_sse_data_payload is not None:
                return final_sse_data_payload
            else: 
                logger.warning(f"Tool '{tool_name}' (Plan {plan_id}) finished SSE stream without 'tool_result' event.")
                return {
                    "status": "failed", 
                    "error_payload": {"message": "SSE stream ended without a final 'tool_result' event.", "type": "StreamEndedPrematurelyError"}, 
                    "tool_name": tool_name, 
                    "timestamp_completion": datetime.now().isoformat() + "Z"
                }

        final_outcome_data = None
        try:
            final_outcome_data = await execute_with_retry_sse()
            tool_final_status = final_outcome_data.get("status", "failed") 

            if plan_data and current_tool_log_entry_index != -1: 
                log_entry = plan_data['tool_calls_log'][current_tool_log_entry_index]
                log_entry['status'] = tool_final_status
                log_entry['timestamp_end'] = final_outcome_data.get("timestamp_completion", datetime.now().isoformat() + "Z")
                log_entry['final_event_data'] = final_outcome_data

                if tool_final_status == 'completed':
                    result_payload = final_outcome_data.get('result_payload', {})
                    log_entry['formatted_result_for_llm'] = self._format_tool_result(result_payload, tool_name)
                    if cache_key: self.tool_cache[cache_key] = result_payload 
                    self.send_gui_plan_update_event(plan_id, event_description=f"Tool '{tool_name}' completed.")
                    return result_payload
                else: 
                    error_payload = final_outcome_data.get('error_payload', {'message': 'Unknown error from tool.'})
                    log_entry['error_info'] = error_payload
                    log_entry['formatted_result_for_llm'] = self._format_tool_result(error_payload, tool_name)
                    self.send_gui_plan_update_event(plan_id, event_description=f"Tool '{tool_name}' failed.")
                    return {"error": error_payload.get("message", "Tool failed"), "details": error_payload}
            
            if tool_final_status == 'completed':
                return final_outcome_data.get('result_payload', {})
            else:
                return {"error": final_outcome_data.get('error_payload', {}).get("message", "Tool failed")}

        except (ConnectionError, ToolExecutionError) as e: 
            logger.error(f"Tool '{tool_name}' (Plan {plan_id}) failed after retries (outer): {e}", exc_info=False) 
            error_payload_for_log = {"message": str(e), "type": type(e).__name__}
            if plan_data and current_tool_log_entry_index != -1:
                entry = plan_data['tool_calls_log'][current_tool_log_entry_index]
                entry['status'] = 'failed'; entry['error_info'] = error_payload_for_log
                entry['timestamp_end'] = datetime.now().isoformat() + "Z"
                entry['final_event_data'] = {'status': 'failed', 'error_payload': error_payload_for_log, 'tool_name': tool_name, 'timestamp_completion': datetime.now().isoformat() + "Z"}
                entry['formatted_result_for_llm'] = self._format_tool_result(error_payload_for_log, tool_name)
                self.send_gui_plan_update_event(plan_id, event_description=f"Tool '{tool_name}' failed (outer exception).")
            return {"error": str(e), "details": error_payload_for_log}
        except Exception as e: 
            logger.error(f"Unhandled error during _execute_mcp_tool for '{tool_name}' (Plan {plan_id}): {e}", exc_info=True)
            error_payload_for_log = {"message": f"Unexpected tool execution error: {str(e)}", "type": type(e).__name__}
            if plan_data and current_tool_log_entry_index != -1:
                entry = plan_data['tool_calls_log'][current_tool_log_entry_index]
                entry['status'] = 'failed'; entry['error_info'] = error_payload_for_log
                entry['timestamp_end'] = datetime.now().isoformat() + "Z"
                entry['final_event_data'] = {'status': 'failed', 'error_payload': error_payload_for_log, 'tool_name': tool_name, 'timestamp_completion': datetime.now().isoformat() + "Z"}
                entry['formatted_result_for_llm'] = self._format_tool_result(error_payload_for_log, tool_name)
                self.send_gui_plan_update_event(plan_id, event_description=f"Tool '{tool_name}' unexpected failure (outer).")
            return {"error": f"Unexpected failure executing tool '{tool_name}': {str(e)}", "details": error_payload_for_log}
        finally:
            if plan_data: 
                plan_data['has_active_tool_calls'] = False
                logger.info(f"Plan '{plan_id}' tool '{tool_name}' processing finished. has_active_tool_calls set to False.")
                self.send_gui_plan_update_event(plan_id, event_description=f"Tool '{tool_name}' finished, active calls ended.")

    async def _invoke_llm(self, messages_for_llm: List[BaseMessage]) -> AIMessage: # Unchanged
        if not self.models.executor_llm:
            logger.critical("Executor LLM not initialized. Cannot invoke LLM.")
            raise RuntimeError("Executor LLM not initialized. Call initialize_tools first.")

        processed_messages_for_api: List[BaseMessage] = []
        for i, msg in enumerate(messages_for_llm):
            if isinstance(msg, AIMessage):
                has_tools = bool(getattr(msg, 'tool_calls', [])) or \
                            bool(getattr(msg, 'invalid_tool_calls', [])) or \
                            (hasattr(msg, 'additional_kwargs') and bool(msg.additional_kwargs.get("tool_calls", [])))
                content_is_empty_str = isinstance(msg.content, str) and msg.content == ""
                content_is_none = msg.content is None

                if (content_is_empty_str or content_is_none) and has_tools:
                    logger.info(f"AIMessage at index {i} has empty/None content and tool_calls. Modifying content to a single space.")
                    tool_calls_list = getattr(msg, 'tool_calls', [])
                    if not tool_calls_list and hasattr(msg, 'additional_kwargs') and isinstance(msg.additional_kwargs.get("tool_calls"), list):
                        tool_calls_list = msg.additional_kwargs["tool_calls"]
                    
                    invalid_tool_calls_list = getattr(msg, 'invalid_tool_calls', [])
                    if not invalid_tool_calls_list and hasattr(msg, 'additional_kwargs') and isinstance(msg.additional_kwargs.get("invalid_tool_calls"), list):
                        invalid_tool_calls_list = msg.additional_kwargs["invalid_tool_calls"]

                    new_msg_additional_kwargs = msg.additional_kwargs.copy() if hasattr(msg, 'additional_kwargs') and msg.additional_kwargs else {}
                    if "tool_calls" in new_msg_additional_kwargs and tool_calls_list: del new_msg_additional_kwargs["tool_calls"]
                    if "invalid_tool_calls" in new_msg_additional_kwargs and invalid_tool_calls_list: del new_msg_additional_kwargs["invalid_tool_calls"]

                    new_msg = AIMessage(content=" ", 
                                        tool_calls=tool_calls_list, 
                                        invalid_tool_calls=invalid_tool_calls_list,
                                        usage_metadata=getattr(msg, 'usage_metadata', None), 
                                        id=getattr(msg, 'id', None),
                                        name=getattr(msg, 'name', None), 
                                        additional_kwargs=new_msg_additional_kwargs,
                                        response_metadata=getattr(msg, 'response_metadata', {}))
                    processed_messages_for_api.append(new_msg)
                else:
                    processed_messages_for_api.append(msg)
            else:
                processed_messages_for_api.append(msg)

        current_tokens_for_llm = self._estimate_tokens(processed_messages_for_api)
        if current_tokens_for_llm > self.max_tokens:
            logger.warning(f"History for LLM (after message-level truncation) still has {current_tokens_for_llm} tokens (Max: {self.max_tokens}). "
                           "This indicates an oversized single message. Replacing its content with a placeholder.")
            
            temp_final_messages_for_llm = []
            system_msgs_preserved = [m for m in processed_messages_for_api if isinstance(m, SystemMessage)]
            other_msgs_to_check = [m for m in processed_messages_for_api if not isinstance(m, SystemMessage)]

            temp_final_messages_for_llm.extend(system_msgs_preserved)

            if len(other_msgs_to_check) == 1: 
                original_oversized_msg = other_msgs_to_check[0]
                original_content_tokens = self._estimate_tokens([original_oversized_msg])
                placeholder_text = (f"Critical Error: The content of the previous step "
                                    f"({type(original_oversized_msg).__name__}, "
                                    f"tool_call_id: {original_oversized_msg.tool_call_id if isinstance(original_oversized_msg, ToolMessage) else 'N/A'}) "
                                    f"was too large to include (estimated {original_content_tokens} tokens, exceeding limit of {self.max_tokens}). "
                                    "The raw output was not sent. Please proceed based on the context or ask for a summary if possible.")
                
                modified_msg = None
                if isinstance(original_oversized_msg, ToolMessage):
                    modified_msg = ToolMessage(content=placeholder_text, tool_call_id=original_oversized_msg.tool_call_id)
                elif isinstance(original_oversized_msg, AIMessage): 
                    modified_msg = AIMessage(content=placeholder_text, tool_calls=original_oversized_msg.tool_calls, invalid_tool_calls=original_oversized_msg.invalid_tool_calls, additional_kwargs=original_oversized_msg.additional_kwargs)
                elif isinstance(original_oversized_msg, HumanMessage):
                     modified_msg = HumanMessage(content=placeholder_text)
                
                if modified_msg:
                    temp_final_messages_for_llm.append(modified_msg)
                    logger.info(f"Replaced content of oversized message with placeholder. New token count for LLM: {self._estimate_tokens(temp_final_messages_for_llm)}")
                else: 
                    logger.error(f"Oversized message was of unexpected type {type(original_oversized_msg)}. Appending generic error message.")
                    temp_final_messages_for_llm.append(HumanMessage(content="Error: A message was too large and its content was replaced with this error."))

            elif not other_msgs_to_check and system_msgs_preserved: 
                 logger.error(f"System messages alone ({current_tokens_for_llm} tokens) exceed max_tokens ({self.max_tokens}). Cannot reduce further. This will likely fail.")
                 temp_final_messages_for_llm = list(processed_messages_for_api) 
            
            else: 
                logger.error(f"Unexpected state: {len(other_msgs_to_check)} non-system messages remain after truncation but still exceed token limit ({current_tokens_for_llm} > {self.max_tokens}). "
                               "Proceeding with this potentially oversized context. This may indicate an issue with _truncate_history or token estimation.")
                temp_final_messages_for_llm = list(processed_messages_for_api)
            
            processed_messages_for_api = temp_final_messages_for_llm

        if not processed_messages_for_api:
            logger.error("No messages to send to LLM after processing and potential oversized message handling. Aborting LLM call.")
            raise RuntimeError("Cannot invoke LLM with an empty message list after all processing.")
        if all(isinstance(msg, SystemMessage) for msg in processed_messages_for_api):
            logger.warning("Processed messages list for LLM contains only SystemMessage(s). This might lead to API errors if not handled by LangChain adapter.")

        @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
        async def invoke_with_retry_llm_internal():
            logger.debug(f"Invoking executor_llm (Model: {self.models.current_model_id}) with {len(processed_messages_for_api)} final messages. Estimated tokens: {self._estimate_tokens(processed_messages_for_api)}. First msg type: {type(processed_messages_for_api[0]) if processed_messages_for_api else 'N/A'}")
            return await self.models.executor_llm.ainvoke(processed_messages_for_api)

        query_for_cache_check = ""
        if processed_messages_for_api:
            for msg in reversed(processed_messages_for_api):
                if isinstance(msg, HumanMessage) and isinstance(msg.content, str):
                    query_for_cache_check = msg.content; break
            if not query_for_cache_check and hasattr(processed_messages_for_api[-1], 'content') and isinstance(processed_messages_for_api[-1].content, str):
                 query_for_cache_check = processed_messages_for_api[-1].content 

        cache_key = None
        if not self._should_bypass_cache(query_for_cache_check):
            cache_key = self._generate_cache_key("llm_invoke", self.current_llm_id, processed_messages_for_api)
            if cache_key in self.llm_cache:
                logger.info(f"Returning cached LLM response for query: {query_for_cache_check[:50]}... (Model: {self.current_llm_id})")
                return self.llm_cache[cache_key]
        try:
            result_ai_message = await invoke_with_retry_llm_internal()
            if cache_key and not self._should_bypass_cache(query_for_cache_check) and \
               not (getattr(result_ai_message, "tool_calls", []) or \
                    (hasattr(result_ai_message, 'additional_kwargs') and \
                     result_ai_message.additional_kwargs.get('tool_calls'))):
                self.llm_cache[cache_key] = result_ai_message
            return result_ai_message
        except Exception as e:
            logger.error(f"Error invoking executor_llm (Model: {self.models.current_model_id}) after retries: {e}", exc_info=True)
            error_str = str(e).lower()
            recoverable_error_keywords = [
                "token limit", "size limit", "request payload size", "context length",
                "resource has been exhausted", 
                "candidate.finish_reason is safety" 
            ]
            if any(keyword in error_str for keyword in recoverable_error_keywords):
                logger.warning(f"LLM invocation failed with potentially context-related or safety error: '{error_str}'.")
                if "candidate.finish_reason is safety" in error_str:
                     raise RuntimeError(f"LLM call blocked due to safety reasons. Content may need review. Original error: {str(e)}") from e
                if "contents is not specified" in error_str: 
                    raise RuntimeError(f"LLM call failed with '{error_str}' even after attempting to handle oversized messages. Original error: {str(e)}") from e
                raise RuntimeError(f"LLM call failed, possibly due to context size or content issues, after history processing: {str(e)}") from e
            raise 

    def _format_tool_result(self, tool_result: Any, tool_name: str) -> str: # Unchanged
        prefix = f"Full result from {tool_name}:\n"
        result_str = ""

        if isinstance(tool_result, dict) and 'error' in tool_result and 'details' in tool_result:
            error_message = tool_result.get('error', 'Unknown error')
            details = tool_result.get('details', {})
            error_obj_for_llm = {"error": error_message}
            if details: 
                error_obj_for_llm["details"] = details if isinstance(details, dict) else {"info": str(details)}
            
            try:
                result_str = json.dumps(error_obj_for_llm, indent=2, sort_keys=True)
                logger.warning(f"Error reported from tool '{tool_name}': {result_str[:500]}...")
            except (TypeError, OverflowError) as e:
                logger.error(f"Could not serialize error object for tool {tool_name}: {e}. Error: {error_obj_for_llm}")
                result_str = f'{{"error": "Error from tool {tool_name}: {str(error_message)} (Details could not be serialized)"}}'
        
        elif isinstance(tool_result, (dict, list)):
            try:
                result_str = json.dumps(tool_result, indent=2, sort_keys=True)
            except (TypeError, OverflowError) as e:
                logger.error(f"Could not serialize tool result for {tool_name} to JSON: {e}. Falling back to str(). Result snippet: {str(tool_result)[:500]}")
                result_str = str(tool_result)
        else:
            result_str = str(tool_result)

        final_output = prefix + result_str
        logger.debug(f"Formatted tool result for LLM (tool: {tool_name}, length: {len(final_output)}): {final_output[:300]}...")
        return final_output

    async def set_active_model(self, new_model_id: str):
        """
        Handles the logic to switch the active LLM model used by the client.
        """
        if new_model_id == self.current_llm_id:
            logger.info(f"Model '{new_model_id}' is already active.")
            self._send_gui_event({"type": "status_update", "message": f"Model {new_model_id} is already active."}) # Corrected
            return

        if new_model_id not in AVAILABLE_LLM_MODELS.values():
            logger.error(f"Attempted to switch to invalid model ID: {new_model_id}")
            self._send_gui_event({"type": "status_update", "message": f"Error: Invalid model ID {new_model_id}."}) # Corrected
            return

        logger.info(f"Attempting to switch LLM from '{self.current_llm_id}' to '{new_model_id}'.")
        
        success = self.models.switch_model(new_model_id)

        if success:
            self.current_llm_id = new_model_id 
            
            await self._prepare_system_prompt() 
            
            logger.info(f"Successfully switched LLM to {self.current_llm_id}. System prompt re-prepared.")
            self._send_gui_event({ # Corrected
                "type": "status_update",
                "message": f"LLM successfully switched to {self.current_llm_id}."
            })
            
            self.llm_cache.clear()
            logger.info("LLM cache cleared due to model switch.")
        else:
            logger.error(f"Failed to switch LLM to {new_model_id}. Client remains on {self.current_llm_id}.")
            self._send_gui_event({ # Corrected
                "type": "status_update",
                "message": f"Error: Failed to switch LLM to {new_model_id}. Current model: {self.current_llm_id}."
            })

    async def process_gui_query(self, query_text: str): # Unchanged
        if not query_text:
            self._send_gui_event({"type": "status_update", "message": "Query cannot be empty."}) # Corrected
            return
        self._send_gui_event({"type": "status_update", "message": f"Processing query: {query_text[:50]}..."}) # Corrected

        extracted_target_from_new_query = self._extract_target_entity(query_text)
        query_queued_to_plan_id = None

        if extracted_target_from_new_query:
            for plan_id_loop, pd_loop in self.ongoing_plans.items():
                if pd_loop.get('status') == 'running' and \
                   pd_loop.get('has_active_tool_calls', False) and \
                   extracted_target_from_new_query in pd_loop.get('current_targets', set()):
                    logger.info(f"New query targets active entity '{extracted_target_from_new_query}' in plan '{plan_id_loop}'. Queuing message.")
                    if plan_id_loop in self.plan_histories:
                        self.plan_histories[plan_id_loop].append(HumanMessage(content=query_text))
                        self._send_gui_event({"type": "status_update", "message": f"Query for '{extracted_target_from_new_query}' queued to active plan '{plan_id_loop}'."}) # Corrected
                        self.send_gui_plan_update_event(plan_id_loop, event_description="User message queued to history.")
                        query_queued_to_plan_id = plan_id_loop
                        break
                    else:
                        logger.warning(f"History not found for plan '{plan_id_loop}' while trying to queue message.")
        
        if query_queued_to_plan_id:
            logger.info(f"Query handled by queuing to plan '{query_queued_to_plan_id}'.")
            return

        try:
            task_query, dependencies = self.extract_dependencies(query_text)
            if dependencies: self.validate_dependencies(dependencies)
            await self.add_plan_to_ongoing(task_query, dependencies)
            self._send_gui_event({"type": "status_update", "message": f"New Plan 'plan_{self.plan_counter}' for query '{task_query}' added."}) # Corrected
        except ValueError as e: 
            logger.error(f"Dependency validation failed for GUI query '{query_text}': {e}")
            self._send_gui_event({"type": "status_update", "message": f"Error: {e}"}) # Corrected
        except Exception as e:
            logger.error(f"Unexpected error processing GUI query '{query_text}': {e}", exc_info=True)
            self._send_gui_event({"type": "status_update", "message": f"Unexpected error: {e}"}) # Corrected

    async def clear_all_plans_from_gui(self): # Unchanged
        logger.info("User requested to clear all plans and histories via GUI.")
        for plan_id, plan_data_val in list(self.ongoing_plans.items()): 
            task = plan_data_val.get("task")
            if task and not task.done():
                logger.info(f"Cancelling task for plan '{plan_id}' due to 'clear' command.")
                task.cancel()
                try: await task 
                except asyncio.CancelledError: logger.info(f"Task for plan '{plan_id}' successfully cancelled.")
                except Exception as e_task_cancel: logger.error(f"Error during task cancellation for plan '{plan_id}': {e_task_cancel}")
        
        for plan_id_key in list(self.ongoing_plans.keys()): 
             self._send_gui_event({"type": "plan_cleared", "plan_id": plan_id_key}) # Corrected
        
        self.plan_histories.clear(); self.ongoing_plans.clear(); self.plan_counter = 0
        logger.info("All plans, tasks, and histories cleared by user via GUI.")
        self._send_gui_event({"type": "status_update", "message": "All plans cleared."}) # Corrected
        self._send_gui_event({"type": "all_plans_cleared"}) # Corrected

    async def handle_gui_command(self, command_data: Dict[str, Any]):
        command_type = command_data.get("command")
        payload = command_data.get("payload", {})
        logger.info(f"Received GUI command: {command_type} with payload: {payload}")

        if command_type == "submit_query":
            query_text = payload.get("query_text")
            if query_text: await self.process_gui_query(query_text)
            else: self._send_gui_event({"type": "status_update", "message": "Empty query received from GUI."}) # Corrected
        
        elif command_type == "switch_llm_model": 
            model_id_to_switch = payload.get("model_id")
            if model_id_to_switch:
                await self.set_active_model(model_id_to_switch)
            else:
                logger.warning("Switch LLM command received without 'model_id'.")
                self._send_gui_event({"type": "status_update", "message": "Error: Model ID missing for switch."}) # Corrected

        elif command_type == "clear_all_plans": await self.clear_all_plans_from_gui()
        
        elif command_type == "get_full_plan_status":
            if not self.ongoing_plans: self._send_gui_event({"type": "status_update", "message": "No active plans to display."}) # Corrected
            else:
                for plan_id_key in self.ongoing_plans.keys(): self.send_gui_plan_update_event(plan_id_key)
        
        elif command_type == "cancel_plan":
            plan_id = payload.get("plan_id")
            if not plan_id:
                logger.error("Cancel_plan command received without plan_id.")
                self._send_gui_event({"type": "status_update", "message": "Error: Plan ID missing for cancellation."}) # Corrected
                return
            
            logger.info(f"Attempting to cancel plan '{plan_id}' via GUI command.")
            plan_info = self.ongoing_plans.get(plan_id)
            if not plan_info:
                logger.warning(f"Cannot cancel plan '{plan_id}': Plan not found in ongoing_plans.")
                self._send_gui_event({"type": "status_update", "message": f"Error: Plan {plan_id} not found for cancellation."}) # Corrected
                return

            task = plan_info.get("task")
            if task and not task.done():
                logger.info(f"Cancelling task for plan '{plan_id}'.")
                task.cancel(); plan_info["status"] = "cancelling" 
                self.send_gui_plan_update_event(plan_id, event_description=f"Plan '{plan_id}' cancellation initiated.")
            elif task and task.done():
                logger.info(f"Plan '{plan_id}' task already done. Current status: {plan_info.get('status')}")
                self._send_gui_event({"type": "status_update", "message": f"Plan {plan_id} already completed or failed."}) # Corrected
            else: 
                logger.warning(f"No active task found for plan '{plan_id}' to cancel. Status: {plan_info.get('status')}")
                if plan_info.get('status') == "queued": 
                    plan_info["status"] = "cancelled"; plan_info["error"] = "Cancelled by user while queued."
                    self.send_gui_plan_update_event(plan_id, event_description=f"Queued plan '{plan_id}' cancelled by user.")
                    self.propagate_failure_or_cancellation(plan_id, is_cancellation=True) 
                else:
                    self._send_gui_event({"type": "status_update", "message": f"Plan {plan_id} (status: {plan_info.get('status')}) has no active task to cancel."}) # Corrected

        elif command_type == "close_plan_tab": 
            plan_id = payload.get("plan_id")
            if not plan_id:
                logger.error("Close_plan_tab command received without plan_id.")
                self._send_gui_event({"type": "status_update", "message": "Error: Plan ID missing for closing tab."}) # Corrected
                return
            
            if plan_id in self.ongoing_plans:
                plan_status = self.ongoing_plans[plan_id].get("status")
                if plan_status in ["completed", "failed", "cancelled"]:
                    logger.info(f"Closing plan tab for '{plan_id}' (status: {plan_status}) as requested by GUI.")
                    task = self.ongoing_plans[plan_id].get("task")
                    if task and not task.done(): 
                        logger.warning(f"Plan '{plan_id}' was in terminal state '{plan_status}' but task was not done. Cancelling.")
                        task.cancel()
                        try: await task
                        except asyncio.CancelledError: logger.info(f"Task for plan '{plan_id}' (during close_plan_tab) successfully cancelled.")
                        except Exception as e_task_close_cancel: logger.error(f"Error during task cancellation for plan '{plan_id}' (during close_plan_tab): {e_task_close_cancel}")
                    
                    del self.ongoing_plans[plan_id]
                    if plan_id in self.plan_histories: del self.plan_histories[plan_id]
                    self._send_gui_event({"type": "plan_tab_closed", "plan_id": plan_id, "message": f"Plan '{plan_id}' tab closed."}) # Corrected
                else:
                    logger.warning(f"Attempt to close active/queued plan '{plan_id}' (status: {plan_status}). Disallowing direct close.")
                    self._send_gui_event({"type": "status_update", "message": f"Cannot close plan '{plan_id}' (status: {plan_status}). Cancel it first if running/queued."}) # Corrected
            else:
                logger.warning(f"Attempt to close non-existent plan tab '{plan_id}'.")
                self._send_gui_event({"type": "status_update", "message": f"Plan '{plan_id}' not found for closing."}) # Corrected
        else:
            logger.warning(f"Unknown GUI command type: {command_type}")
            self._send_gui_event({"type": "status_update", "message": f"Unknown command: {command_type}"}) # Corrected

    async def chat_loop(self) -> None: # Unchanged
        if not self.system_prompt_template:
            try:
                logger.warning("System prompt template was not prepared. Attempting to prepare now.")
                await self.initialize_tools() 
                if not self.system_prompt_template: 
                    logger.critical("System prompt template could not be prepared. Aborting chat loop.")
                    print("FATAL ERROR: System prompt could not be initialized. Exiting.")
                    return
            except ConnectionError as e: 
                logger.critical(f"Failed to initialize tools/system prompt: {e}. Aborting chat loop.")
                print(f"ERROR: Could not connect to initialize: {e}. Exiting.")
                return
            except Exception as e: 
                logger.critical(f"Unexpected error during fallback system prompt prep: {e}. Aborting.")
                print(f"FATAL ERROR: Unexpected issue initializing: {e}. Exiting.")
                return

        print("\nMCP Client Ready (Console Mode). System prompt loaded.")
        print(f"Current LLM: {self.current_llm_id}")
        print(f"Max tokens for LLM context: {self.max_tokens}")
        print("Enter your query. Type 'quit' to exit, 'clear' to reset all plans, 'status' for overview.")
        print("To switch model (console only): 'model model_id' (e.g., 'model gemini-1.5-pro-latest')")
        print("To create dependencies, use '... after plan_ID1, plan_ID2 ...' in your query.")

        while True:
            try:
                self.print_plan_status()
                raw_query = await asyncio.to_thread(input, f"\nQuery (LLM: {self.current_llm_id}): ")
                query = raw_query.strip()

                if query.lower() == 'quit':
                    print("Exiting chat loop...")
                    break
                if query.lower() == 'clear':
                    await self.handle_gui_command({"command": "clear_all_plans"}) 
                    continue
                if query.lower() == 'status':
                    continue 
                if query.startswith("model "): 
                    parts = query.split(" ", 1)
                    if len(parts) == 2 and parts[1]:
                        await self.set_active_model(parts[1])
                    else:
                        print("Invalid model command. Usage: model <model_id>")
                        print("Available model IDs:", ", ".join(AVAILABLE_LLM_MODELS.values()))
                    continue
                if not query:
                    continue

                await self.handle_gui_command({"command": "submit_query", "payload": {"query_text": query}})

            except RuntimeError as e:
                logger.error(f"Runtime error in chat loop: {e}", exc_info=True)
                print(f"\nRUNTIME ERROR: {str(e)}")
            except ConnectionError as e:
                logger.error(f"Connection error in chat loop: {e}", exc_info=True)
                print(f"\nCONNECTION ERROR: {str(e)}. Please check server connection.")
            except MaxToolIterationsError as e:
                logger.error(f"Plan failed due to max iterations: {e}", exc_info=False) 
                print(f"\nPLAN FAILED: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error in chat loop: {e}", exc_info=True)
                print(f"\nUNEXPECTED ERROR: {str(e)}")
            
            await asyncio.sleep(0.1) 

    async def command_listener_loop(self): # Unchanged
        if not self.client_command_queue:
            logger.warning("Client command queue not initialized. Command listener loop cannot start.")
            return

        logger.info("Starting GUI command listener loop.")
        while True:
            try:
                command_data = await self.client_command_queue.get()
                logger.info(f"Command listener received: {command_data}")
                if command_data is None: 
                    logger.info("Command listener received shutdown signal.")
                    break
                await self.handle_gui_command(command_data)
                self.client_command_queue.task_done()
            except asyncio.CancelledError:
                logger.info("Command listener loop cancelled.")
                break
            except Exception as e:
                logger.error(f"Error in command listener loop: {e}", exc_info=True)
        logger.info("Command listener loop stopped.")

    async def cleanup(self): # Unchanged
        logger.info("Initiating MCPClient cleanup...")
        if self.client_command_queue:
            await self.client_command_queue.put(None) 

        active_tasks = []
        for plan_id, plan_data in self.ongoing_plans.items():
            task = plan_data.get("task")
            if task and not task.done():
                logger.info(f"Cancelling task for plan '{plan_id}' during cleanup.")
                task.cancel()
                active_tasks.append(task)

        if active_tasks:
            results = await asyncio.gather(*active_tasks, return_exceptions=True)
            for i, result in enumerate(results):
                task_name = active_tasks[i].get_name() if hasattr(active_tasks[i], 'get_name') else f"Task-{i}"
                if isinstance(result, asyncio.CancelledError):
                    logger.info(f"Task '{task_name}' successfully cancelled during cleanup.")
                elif isinstance(result, Exception):
                    logger.error(f"Error during task '{task_name}' cancellation/cleanup: {result}", exc_info=result)
        
        if self.http_client and not self.http_client.is_closed:
            await self.http_client.aclose()
            logger.info("HTTP client closed.")

        self.llm_cache.clear(); logger.info("LLM cache cleared.")
        self.tool_cache.clear(); logger.info("Tool cache cleared.")
        self.plan_histories.clear(); self.ongoing_plans.clear()
        logger.info("Plan histories and ongoing plans cleared.")
        logger.info("MCPClient cleanup complete.")

async def main_async_with_gui_queues(gui_q: queue.Queue, cmd_q: asyncio.Queue): # Unchanged
    client = None
    try:
        client = MCPClient()
        client.gui_update_queue = gui_q
        client.client_command_queue = cmd_q 
        client.loop = asyncio.get_running_loop()

        await client.initialize_tools() 

        command_listener_task = asyncio.create_task(client.command_listener_loop(), name="GUICommandListener")

        logger.info("MCPClient initialized with GUI queues and command listener started.")
        await command_listener_task 

    except ConfigError as e:
        logger.critical(f"Configuration error: {e}")
        if gui_q: gui_q.put({"type": "critical_error", "message": f"Configuration Error: {e}"})
    except ConnectionError as e: 
        logger.critical(f"Connection error during startup: {e}")
        if gui_q: gui_q.put({"type": "critical_error", "message": f"Connection Error: {e}"})
    except Exception as e:
        logger.critical(f"Critical unhandled error: {e}", exc_info=True)
        if gui_q: gui_q.put({"type": "critical_error", "message": f"Critical Error: {e}"})
    finally:
        if client:
            logger.info("Shutting down MCPClient (from main_async_with_gui_queues)...")
            await client.cleanup() 
        logger.info("Application shutdown sequence finished.")

async def main_async_console_only(): # Unchanged
    client = None
    try:
        client = MCPClient()
        await client.initialize_tools()
        await client.chat_loop()
    except ConfigError as e:
        logger.critical(f"Configuration error: {e}")
        print(f"\nCONFIGURATION ERROR: {e}. Please check .env. Exiting.")
    except ConnectionError as e: 
        logger.critical(f"Connection error during startup: {e}")
        print(f"\nCONNECTION ERROR: {e}. Could not connect. Exiting.")
    except Exception as e:
        logger.critical(f"Critical unhandled error: {e}", exc_info=True)
        print(f"\nCRITICAL ERROR: {e}. Exiting.")
    finally:
        if client:
            logger.info("Shutting down MCPClient (from main_async_console_only)...")
            await client.cleanup()
        logger.info("Application shutdown sequence finished.")

if __name__ == "__main__": # Unchanged
    try:
        asyncio.run(main_async_console_only())
    except KeyboardInterrupt:
        logger.info("Application terminated by user (KeyboardInterrupt).")
        print("\nApplication terminated by user. Shutting down...")
    finally:
        handlers = list(logging.getLogger("MCPClientSSE_Google").handlers) + \
                   list(logging.getLogger().handlers) 
        for handler in handlers:
            try:
                if hasattr(handler, 'close'):
                    handler.close()
            except Exception as e:
                print(f"Error closing log handler during final cleanup: {e}")