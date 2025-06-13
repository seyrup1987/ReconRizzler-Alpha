import json
import glob
import re
import threading
import time
import os
import logging
import queue
import random
from urllib.parse import urljoin, urlparse, parse_qs 
from concurrent.futures import ThreadPoolExecutor
import asyncio
import concurrent.futures
from datetime import datetime
import multiprocessing
from typing import Dict, Any, AsyncGenerator, List, Tuple, Optional, Set
import inspect 

import sys 
import aiohttp

import requests as rq # type: ignore
from bs4 import BeautifulSoup # type: ignore
from selenium import webdriver # type: ignore
from selenium.webdriver.chrome.options import Options as ChromeOptions # type: ignore
from selenium.webdriver.chrome.service import Service as ChromeService # type: ignore
from selenium.webdriver.support.ui import WebDriverWait # type: ignore
from selenium.webdriver.support import expected_conditions as EC # type: ignore
from selenium.webdriver.common.by import By # type: ignore
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException, StaleElementReferenceException # type: ignore

from .ActiveVulnerabilityCheck import ActiveVulnerabilityCheck
from .VulnerabilityChecks.DirectoryBrowsingScanRule import DirectoryBrowsingScanRule, Alert 

logger = logging.getLogger(__name__)

class StartUrlCriticalFailure(Exception):
    """Custom exception for critical failures related to the start URL."""
    pass

COMMON_USER_AGENTS_CRAWLER = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

# --- Passive Scan Template Scanner ---
class PassiveTemplateScanner:
    def __init__(self, template_dir_path: str, parent_logger: Optional[logging.Logger] = None):
        self.templates: List[Dict[str, Any]] = []
        self.logger = parent_logger or logging.getLogger(__name__)
        self._load_and_compile_templates(template_dir_path)
        self.logger.info(f"PassiveTemplateScanner initialized with {len(self.templates)} compiled templates from {template_dir_path}.")

    def _validate_template_structure(self, template_def: Dict[str, Any], file_path: str) -> bool:
        required_top_level_keys = {
            "id": str, "name": str, "passive_hint_type": str,
            "match_conditions": list, "match_condition_logic": str, "evidence_format": str
        }
        optional_top_level_keys = {
            "severity": str, "description": str, "confidence": str,
            "remediation_suggestion": str, "tags": list
        }

        for key, expected_type in required_top_level_keys.items():
            if key not in template_def:
                self.logger.warning(f"Template file {file_path} (ID: {template_def.get('id', 'N/A')}) missing required key '{key}'. Skipping.")
                return False
            if not isinstance(template_def[key], expected_type):
                self.logger.warning(f"Template file {file_path} (ID: {template_def.get('id', 'N/A')}) key '{key}' has incorrect type (expected {expected_type.__name__}, got {type(template_def[key]).__name__}). Skipping.")
                return False

        for key, expected_type in optional_top_level_keys.items():
            if key in template_def and not isinstance(template_def[key], expected_type):
                self.logger.warning(f"Template file {file_path} (ID: {template_def.get('id', 'N/A')}) optional key '{key}' has incorrect type (expected {expected_type.__name__}, got {type(template_def[key]).__name__}). Treating as missing.")
                template_def.pop(key) 

        if not template_def["match_conditions"]: 
            self.logger.warning(f"Template file {file_path} (ID: {template_def.get('id', 'N/A')}) 'match_conditions' is empty. Skipping.")
            return False

        for i, cond_block in enumerate(template_def["match_conditions"]):
            if not isinstance(cond_block, dict):
                self.logger.warning(f"Template file {file_path} (ID: {template_def.get('id', 'N/A')}) 'match_conditions' block at index {i} is not a dictionary. Skipping template.")
                return False
            
            # Part validation (can be url_param_name, url_param_value, url_path, header_value, cookie_value, body_content, status_code, header_name)
            valid_parts = ["url_param_name", "url_param_value", "url_path", "header_value", "cookie_value", "body_content", "status_code", "header_name", "url_param_value_reflected_in_body_unencoded"]
            if "part" not in cond_block or not isinstance(cond_block["part"], str) or cond_block["part"] not in valid_parts:
                self.logger.warning(f"Template file {file_path} (ID: {template_def.get('id', 'N/A')}) 'match_conditions' block at index {i} missing or invalid 'part' (must be one of {valid_parts}). Skipping template.")
                return False
            
            if "condition" not in cond_block or not isinstance(cond_block["condition"], str) or cond_block["condition"].lower() not in ["or", "and"]:
                self.logger.warning(f"Template file {file_path} (ID: {template_def.get('id', 'N/A')}) 'match_conditions' block at index {i} missing or invalid 'condition'. Skipping template.")
                return False
            
            # Keywords or Regexes must exist if part is not status_code
            if cond_block["part"] != "status_code" and not (cond_block.get("keywords") or cond_block.get("regexes")):
                 self.logger.warning(f"Template file {file_path} (ID: {template_def.get('id', 'N/A')}) 'match_conditions' block at index {i} for part '{cond_block['part']}' must have 'keywords' or 'regexes'. Skipping template.")
                 return False
            if cond_block["part"] == "status_code" and not cond_block.get("keywords"): # status_code uses keywords for status codes
                 self.logger.warning(f"Template file {file_path} (ID: {template_def.get('id', 'N/A')}) 'match_conditions' block at index {i} for part 'status_code' must have 'keywords'. Skipping template.")
                 return False


            for opt_key, opt_type in [("keywords", list), ("regexes", list), ("note", str), ("specific_passive_hint_type", str), ("header_name_filter", str), ("cookie_name_filter", str)]:
                 if opt_key in cond_block and not isinstance(cond_block[opt_key], opt_type):
                    self.logger.warning(f"Template file {file_path} (ID: {template_def.get('id', 'N/A')}) 'match_conditions' block at index {i} has invalid type for '{opt_key}'. Ignoring field in block.")
                    cond_block.pop(opt_key)

        if template_def["match_condition_logic"].lower() not in ["or", "and"]:
            self.logger.warning(f"Template file {file_path} (ID: {template_def.get('id', 'N/A')}) 'match_condition_logic' is invalid. Skipping.")
            return False
        return True


    def _load_and_compile_templates(self, template_dir_path: str):
        if not os.path.isdir(template_dir_path):
            self.logger.error(f"Passive scan template directory not found: {template_dir_path}")
            return

        json_files = glob.glob(os.path.join(template_dir_path, '*.json'))
        if not json_files:
            self.logger.warning(f"No JSON template files found in {template_dir_path}")
            return

        for file_path in json_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    template_def = json.load(f)

                if not self._validate_template_structure(template_def, file_path):
                    continue 

                compiled_template = self._compile_single_template_regexes(template_def, file_path)
                if compiled_template:
                    self.templates.append(compiled_template)
            except json.JSONDecodeError as e:
                self.logger.error(f"Invalid JSON in template file {file_path}: {e}")
            except Exception as e:
                self.logger.error(f"Error loading or compiling template file {file_path}: {e}", exc_info=True)

    def _compile_single_template_regexes(self, template_def: Dict[str, Any], file_path: str) -> Optional[Dict[str, Any]]:
        try:
            for cond_block in template_def.get("match_conditions", []): 
                if "regexes" in cond_block and isinstance(cond_block["regexes"], list):
                    compiled_regex_list = []
                    for r_pattern_str in cond_block["regexes"]:
                        if not isinstance(r_pattern_str, str):
                            self.logger.warning(f"Non-string regex pattern found in template {template_def.get('id')} file {file_path}. Skipping pattern: {r_pattern_str}")
                            continue
                        try:
                            compiled_regex_list.append(re.compile(r_pattern_str, re.IGNORECASE))
                        except re.error as re_e:
                            self.logger.error(f"Invalid regex in template ID '{template_def.get('id')}' file {file_path}: '{r_pattern_str}'. Error: {re_e}. Skipping pattern.")
                    cond_block["regexes_compiled"] = compiled_regex_list 
            return template_def
        except Exception as e:
            self.logger.error(f"Failed to compile regexes for passive template ID '{template_def.get('id', 'N/A')}' file {file_path}: {e}", exc_info=True)
            return None

    def scan_page(self, url: str, html_content_raw: Optional[str], headers: Dict[str, str],
                  cookies: Dict[str, str], 
                  query_params: Dict[str, List[str]], 
                  status_code_int: Optional[int], # Added status_code
                  worker_ident: str) -> List[Dict[str, Any]]:

        findings = []
        parsed_url = urlparse(url)

        for template in self.templates:
            template_match_overall = False
            top_level_condition_block_results: List[bool] = []
            first_contributing_match_details: Optional[Dict[str, Any]] = None

            for cond_block_idx, cond_block in enumerate(template.get("match_conditions", [])):
                block_match_internal = False
                part = cond_block.get("part")
                if not part: continue

                block_level_logic = cond_block.get("condition", "and").lower()
                items_to_check_in_block: List[Tuple[str, str, str, Optional[str]]] = []

                if part == "url_param_name":
                    items_to_check_in_block = [(name, "url_param_name", name, None) for name in query_params.keys()]
                elif part == "url_param_value":
                    items_to_check_in_block = [(val, "url_param_value", name, None) for name, vals in query_params.items() for val in vals]
                elif part == "url_path":
                    items_to_check_in_block = [(parsed_url.path, "url_path", parsed_url.path, None)]
                elif part == "header_name": # New part
                    items_to_check_in_block = [(h_name, "header_name", h_name, None) for h_name in headers.keys()]
                elif part == "header_value":
                    header_name_filter = cond_block.get("header_name_filter")
                    for h_name, h_val in headers.items():
                        if header_name_filter and header_name_filter.lower() != h_name.lower():
                            continue
                        items_to_check_in_block.append((h_val, "header_value", h_name, None))
                elif part == "cookie_value":
                    cookie_name_filter = cond_block.get("cookie_name_filter")
                    for c_name, c_val_str in cookies.items(): # cookies is {name: value_string}
                        if cookie_name_filter and cookie_name_filter.lower() != c_name.lower():
                            continue
                        items_to_check_in_block.append((c_val_str, "cookie_value", c_name, None))
                elif part == "body_content" and html_content_raw:
                    items_to_check_in_block = [(html_content_raw, "body_content", "N/A", None)]
                elif part == "status_code" and status_code_int is not None: # New part
                    items_to_check_in_block = [(str(status_code_int), "status_code", "N/A", None)]
                elif part == "url_param_value_reflected_in_body_unencoded" and html_content_raw:
                    for name, vals in query_params.items():
                        for val in vals:
                            if val and len(val) > 2 and val in html_content_raw: 
                                items_to_check_in_block.append((val, "url_param_value_reflected_in_body_unencoded", name, val))
                                if block_level_logic == "or": break 
                        if block_level_logic == "or" and items_to_check_in_block and items_to_check_in_block[-1][1] == "url_param_value_reflected_in_body_unencoded": break
                
                current_block_match_details_list: List[Dict[str, Any]] = []

                for item_value_str, item_location_str, item_name_or_path_str, actual_reflected_val_str in items_to_check_in_block:
                    item_value_str_for_match = str(item_value_str) 
                    
                    regex_matches_for_item = []
                    for r_pattern_compiled in cond_block.get("regexes_compiled", []): 
                        if r_pattern_compiled.search(item_value_str_for_match):
                            regex_matches_for_item.append(r_pattern_compiled.pattern) 
                            if block_level_logic == "or": break 
                    
                    keyword_matches_for_item = []
                    if not (block_level_logic == "or" and regex_matches_for_item): 
                        for keyword_str in cond_block.get("keywords", []):
                            # For status_code, exact match; for others, case-insensitive substring
                            if part == "status_code":
                                if keyword_str == item_value_str_for_match:
                                    keyword_matches_for_item.append(keyword_str)
                                    if block_level_logic == "or": break
                            elif keyword_str.lower() in item_value_str_for_match.lower():
                                keyword_matches_for_item.append(keyword_str)
                                if block_level_logic == "or": break
                    
                    item_caused_block_match = False
                    matched_pattern_for_item = None

                    if block_level_logic == "or":
                        if regex_matches_for_item:
                            item_caused_block_match = True
                            matched_pattern_for_item = regex_matches_for_item[0]
                        elif keyword_matches_for_item:
                            item_caused_block_match = True
                            matched_pattern_for_item = keyword_matches_for_item[0]
                    elif block_level_logic == "and":
                        all_regexes_defined = bool(cond_block.get("regexes_compiled"))
                        all_keywords_defined = bool(cond_block.get("keywords"))
                        
                        regex_condition_met = (not all_regexes_defined) or bool(regex_matches_for_item)
                        keyword_condition_met = (not all_keywords_defined) or bool(keyword_matches_for_item)

                        if regex_condition_met and keyword_condition_met:
                            item_caused_block_match = True
                            if regex_matches_for_item: matched_pattern_for_item = regex_matches_for_item[0]
                            elif keyword_matches_for_item: matched_pattern_for_item = keyword_matches_for_item[0]
                            else: matched_pattern_for_item = "N/A (logic AND with no patterns)"


                    if item_caused_block_match and matched_pattern_for_item is not None:
                        current_block_match_details_list.append({
                            "value": matched_pattern_for_item, 
                            "location": item_location_str,
                            "name_or_path": item_name_or_path_str,
                            "note": cond_block.get("note", ""), 
                            "specific_passive_hint_type": cond_block.get("specific_passive_hint_type", template.get("passive_hint_type")),
                            "reflected_actual_value": actual_reflected_val_str if part == "url_param_value_reflected_in_body_unencoded" else None
                        })
                        if block_level_logic == "or": 
                            break 
                
                if current_block_match_details_list: 
                    block_match_internal = True
                    if not first_contributing_match_details: 
                        first_contributing_match_details = current_block_match_details_list[0]
                
                top_level_condition_block_results.append(block_match_internal)

            if not top_level_condition_block_results: 
                template_match_overall = False
            elif template.get("match_condition_logic", "and").lower() == "and":
                template_match_overall = all(top_level_condition_block_results)
            elif template.get("match_condition_logic", "and").lower() == "or":
                template_match_overall = any(top_level_condition_block_results)
            
            if template_match_overall and first_contributing_match_details:
                evidence_str = template.get("evidence_format", "Pattern matched.")
                
                evidence_str = evidence_str.replace("{matched_value}", str(first_contributing_match_details.get("value", "N/A"))[:100])
                evidence_str = evidence_str.replace("{match_location}", str(first_contributing_match_details.get("location", "N/A")))
                evidence_str = evidence_str.replace("{param_name_or_path}", str(first_contributing_match_details.get("name_or_path", "N/A"))[:100])
                evidence_str = evidence_str.replace("{note}", str(first_contributing_match_details.get("note", "")))
                
                current_passive_hint_type = first_contributing_match_details.get("specific_passive_hint_type", template.get("passive_hint_type"))
                evidence_str = evidence_str.replace("{specific_passive_hint_type}", str(current_passive_hint_type))
                
                reflected_val = first_contributing_match_details.get("reflected_actual_value")
                evidence_str = evidence_str.replace("{reflected_actual_value}", str(reflected_val)[:100] if reflected_val else "N/A")
                evidence_str = evidence_str.replace("{url_tested}", url) # Added placeholder for URL

                finding = {
                    "type": "passive_scan_hint", 
                    "template_id": template["id"],
                    "name": template["name"],
                    "severity": template.get("severity", "Informational"),
                    "confidence": template.get("confidence", "Tentative"),
                    "description": template.get("description", ""),
                    "passive_hint_type": template.get("passive_hint_type"), # The main hint type for grouping
                    "specific_passive_hint_type": current_passive_hint_type, # The more specific hint
                    "url_tested": url,
                    "evidence": evidence_str,
                    "remediation_suggestion": template.get("remediation_suggestion", ""),
                    "tags": template.get("tags", []),
                    "affected_parameter_name": first_contributing_match_details.get("name_or_path") if "param" in first_contributing_match_details.get("location","").lower() or "cookie" in first_contributing_match_details.get("location","").lower() or "header" in first_contributing_match_details.get("location","").lower() else None,
                    "affected_parameter_location": first_contributing_match_details.get("location")
                }
                findings.append(finding)
                self.logger.info(f"[{worker_ident}] Passive template '{template['id']}' matched for {url}. Hint: {current_passive_hint_type}")
        return findings


class Crawler:
    def __init__(self, start_url: str, max_depth: int = 2, num_threads: int = 5,
                 wappalyzer_dir_path: str = "../config/CrawlerConfig/TechFingerprints/",
                 passive_template_dir_path: str = "../config/CrawlerConfig/PassiceScanTemplates", # Corrected typo
                 headless_selenium: bool = True,
                 min_request_delay_seconds: float = 2.0,
                 max_request_delay_seconds: float = 5.0,
                 active_scanning_enabled: bool = False,
                 active_scan_timeout: float = 10.0,
                 oob_listener_domain: Optional[str] = None,
                 process_event_loop: Optional[asyncio.AbstractEventLoop] = None,
                 active_scan_async_q: Optional[asyncio.Queue] = None 
                ):

        self.base_domain = urlparse(start_url).netloc
        instance_logger_name = f"{__name__}.CrawlerInstance.{self.base_domain.replace('.', '_').replace(':', '_')}"
        self.logger = logging.getLogger(instance_logger_name)
        self.logger.debug(f"Crawler instance logger initialized for {self.base_domain}")

        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.wappalyzer_data_path = os.path.normpath(os.path.join(base_dir, wappalyzer_dir_path))
        self.passive_template_dir_path = os.path.normpath(os.path.join(base_dir, passive_template_dir_path))

        self.start_url = start_url
        self.original_max_depth = max_depth
        CRAWL_DEPTH_CAP = 10
        current_max_depth = int(float(max_depth))
        if current_max_depth > CRAWL_DEPTH_CAP:
            self.logger.warning(f"Requested max_depth {current_max_depth} for {start_url} is very high. Capping at {CRAWL_DEPTH_CAP}.")
            self.max_depth = CRAWL_DEPTH_CAP
        else:
            self.max_depth = current_max_depth

        self.num_threads = num_threads
        self.headless_selenium = headless_selenium
        self.min_request_delay_seconds = min_request_delay_seconds
        self.max_request_delay_seconds = max_request_delay_seconds
        self.user_agents = COMMON_USER_AGENTS_CRAWLER

        self.visited_links: set[str] = set()
        self.page_details_accumulator: List[Dict[str, Any]] = []
        self.bad_urls_accumulator: List[Dict[str, Any]] = []
        self.domain_technologies: Set[str] = set() 
        self.url_based_scans_performed: Set[str] = set()
        self.lock = threading.Lock()
        self._critical_failure_event = threading.Event()
        self.process_event_loop = process_event_loop
        self.active_scan_async_q = active_scan_async_q 

        self.url_queue: queue.Queue[Optional[Tuple[str, int]]] = queue.Queue()
        self.requests_session = rq.Session()
        self.aiohttp_session: Optional[aiohttp.ClientSession] = None

        self.directory_browsing_scanner = DirectoryBrowsingScanRule(
            scope_technologies=["Apache", "IIS"], parent_logger=self.logger
        )

        self.passive_template_scanner = PassiveTemplateScanner(
            template_dir_path=self.passive_template_dir_path, parent_logger=self.logger
        )

        self.wappalyzer_data = self._load_wappalyzer_data()

        self._dummy_resolutions = [(1920, 1080), (1366, 768)]
        self._dummy_hardware_concurrency = [4, 8]
        self._dummy_device_memory = [4, 8]
        self._dummy_languages = ["en-US", "en-GB"]
        self._dummy_timezones = ["UTC", "America/New_York"]
        self._dummy_color_depth = [24]
        self._dummy_plugin_mime_sets_js = [{"plugins_array_js": "[]", "mimeTypes_array_js": "[]"}] 
        self._dummy_webgl_info = [{"vendor": "Google Inc.", "renderer": "Google Inc. (NVIDIA)"}] 


        self.active_scanning_enabled = active_scanning_enabled
        self.active_scan_timeout_config = active_scan_timeout
        self.oob_listener_domain_config = oob_listener_domain
        self.active_checker: Optional[ActiveVulnerabilityCheck] = None
        self._base_chrome_options = ChromeOptions()

        if self.headless_selenium: self._base_chrome_options.add_argument("--headless")
        self._base_chrome_options.add_argument("--disable-gpu")
        self._base_chrome_options.add_argument("--no-sandbox")
        self._base_chrome_options.add_argument("--disable-dev-shm-usage")
        self._base_chrome_options.add_argument("--log-level=3") 
        self._base_chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
        self._base_chrome_options.add_argument("--disable-extensions")
        self._base_chrome_options.add_argument("--disable-application-cache")
        self._base_chrome_options.add_argument("--disk-cache-size=1024") 
        self._base_chrome_options.add_argument("--media-cache-size=1024") 
        self._base_chrome_options.add_argument('--aggressive-cache-discard')
        self._base_chrome_options.add_argument('--disable-offline-load-stale-cache')
        self._base_chrome_options.add_argument('--disable-background-networking')
        self._base_chrome_options.add_argument('--disable-component-update')
        self._base_chrome_options.add_argument('--disable-breakpad') 
        self._base_chrome_options.add_argument('--disable-domain-reliability')
        self._base_chrome_options.add_argument('--disable-renderer-backgrounding')
        self._base_chrome_options.add_argument('--enable-automation') 
        self._base_chrome_options.add_argument("--disable-webrtc-udp-multicast")
        self._base_chrome_options.add_argument("--disable-webrtc-multiple-routes")
        self._base_chrome_options.add_argument("--disable-webrtc-stun-origin")
        self._base_chrome_options.add_experimental_option("prefs", {
            "webrtc.ip_handling_policy": "disable_non_proxied_udp",
            "webrtc.multiple_routes_enabled": False,
            "webrtc.nonproxied_udp_enabled": False
        })

        self.chrome_driver_path: Optional[str] = None
        try:
            from webdriver_manager.chrome import ChromeDriverManager # type: ignore
            logging.getLogger('webdriver_manager').setLevel(logging.WARNING)
            self.chrome_driver_path = ChromeDriverManager().install()
            self.logger.info(f"ChromeDriver path set by WebDriverManager: {self.chrome_driver_path}")
        except Exception as e:
            self.logger.warning(f"Failed to pre-install ChromeDriver via WebDriverManager: {e}. Will attempt fallback.")
            self.chrome_driver_path = "chromedriver"

    def _compile_regex_dict(self, rules: Dict[str, Any]) -> Dict[str, Any]:
        compiled_rules = {}
        regex_keys_string_pattern = {"url", "html", "scriptSrc"} 
        regex_keys_list_of_string_patterns = {"html", "scriptSrc"}
        regex_keys_dict_val_string_patterns = {"headers", "cookies", "meta", "js"}

        for key, value in rules.items():
            original_value_for_fallback = value 
            try:
                if key in regex_keys_string_pattern and isinstance(value, str):
                    pattern_str = value.split("\\;")[0]
                    compiled_rules[key] = re.compile(pattern_str, re.IGNORECASE)
                elif key in regex_keys_list_of_string_patterns and isinstance(value, list):
                    compiled_list = []
                    for item in value:
                        if isinstance(item, str):
                            pattern_str = item.split("\\;")[0]
                            compiled_list.append(re.compile(pattern_str, re.IGNORECASE))
                        else:
                            compiled_list.append(item) 
                    compiled_rules[key] = compiled_list
                elif key in regex_keys_dict_val_string_patterns and isinstance(value, dict):
                    compiled_dict = {}
                    for subkey, subvalue in value.items():
                        if isinstance(subvalue, str):
                            pattern_str = subvalue.split("\\;")[0]
                            compiled_dict[subkey] = re.compile(pattern_str, re.IGNORECASE) if pattern_str else None 
                        else:
                            compiled_dict[subkey] = subvalue 
                    compiled_rules[key] = compiled_dict
                else:
                    compiled_rules[key] = original_value_for_fallback
            except re.error as e_re:
                self.logger.debug(f"Invalid regex pattern for {key} (or subkey): {value}. Error: {e_re}. Storing original value.")
                compiled_rules[key] = original_value_for_fallback 
            except Exception as e_comp: 
                self.logger.error(f"Unexpected error compiling rule for {key}: {value}. Error: {e_comp}. Storing original value.", exc_info=True)
                compiled_rules[key] = original_value_for_fallback
        return compiled_rules

    def _load_wappalyzer_data(self) -> Dict[str, Any]:
        wappalyzer_dir_path = self.wappalyzer_data_path
        if not os.path.isdir(wappalyzer_dir_path):
            self.logger.error(f"Wappalyzer data directory not found: {wappalyzer_dir_path}")
            return {}

        wapp_data: Dict[str, Any] = {}
        json_files = glob.glob(os.path.join(wappalyzer_dir_path, '*.json'))
        if not json_files:
            self.logger.warning(f"No JSON files found in {wappalyzer_dir_path}")
            return wapp_data

        technologies_loaded_count = 0
        for file_path in json_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data_from_file = json.load(f)

                if not isinstance(data_from_file, dict):
                    self.logger.warning(f"Skipping file {file_path} as its content is not a dictionary of technologies.")
                    continue

                for tech_key, tech_definition in data_from_file.items():
                    if not isinstance(tech_definition, dict):
                        self.logger.warning(f"Skipping technology entry '{tech_key}' in {file_path} as its definition is not a dictionary.")
                        continue
                    
                    canonical_tech_name = tech_key
                    patterns_and_meta_dict = tech_definition
                    inner_name_field = tech_definition.get("name")
                    if inner_name_field and inner_name_field != canonical_tech_name:
                        self.logger.debug(f"Tech key '{canonical_tech_name}' differs from inner name field '{inner_name_field}' in {file_path} for tech '{canonical_tech_name}'. Using key as canonical name.")
                    elif not inner_name_field:
                        self.logger.debug(f"Tech key '{canonical_tech_name}' in {file_path} does not have an inner 'name' field. Using key as canonical name.")
                    
                    compiled_rules_and_meta = self._compile_regex_dict(patterns_and_meta_dict)
                    
                    if canonical_tech_name in wapp_data:
                        self.logger.warning(f"Duplicate technology key '{canonical_tech_name}' found. Overwriting with definition from {file_path}. Previous source was an earlier file or another key in the same/previous file.")
                    wapp_data[canonical_tech_name] = compiled_rules_and_meta
                    technologies_loaded_count +=1
                        
            except json.JSONDecodeError as e:
                self.logger.error(f"Invalid JSON in {file_path}: {e}")
            except Exception as e:
                self.logger.error(f"Error loading or processing file {file_path}: {e}", exc_info=True)

        self.logger.info(f"Loaded {technologies_loaded_count} technology definitions from {len(json_files)} files into Wappalyzer data store ({len(wapp_data)} unique tech names).")
        return wapp_data

    def _create_driver(self, user_agent_string: Optional[str] = None) -> webdriver.Chrome:
        from webdriver_manager.chrome import ChromeDriverManager # type: ignore
        logging.getLogger('webdriver_manager').setLevel(logging.WARNING)

        current_options = ChromeOptions()
        for arg in self._base_chrome_options.arguments: current_options.add_argument(arg)
        for cap_name, cap_value in self._base_chrome_options.experimental_options.items():
            current_options.add_experimental_option(cap_name, cap_value)
        
        selected_ua = user_agent_string or random.choice(self.user_agents)
        current_options.add_argument(f"user-agent={selected_ua}")
        self.logger.debug(f"[{threading.get_ident()}] Creating WebDriver with User-Agent: {selected_ua.split(' ')[0]}...")

        selected_resolution = random.choice(self._dummy_resolutions)
        selected_hw_concurrency = random.choice(self._dummy_hardware_concurrency)
        selected_device_memory = random.choice(self._dummy_device_memory)
        selected_language = random.choice(self._dummy_languages)
        selected_timezone = random.choice(self._dummy_timezones)
        selected_color_depth = random.choice(self._dummy_color_depth)
        selected_plugin_mime_set = random.choice(self._dummy_plugin_mime_sets_js)
        selected_webgl_info = random.choice(self._dummy_webgl_info)

        self.logger.debug(f"[{threading.get_ident()}] Using rotated values: Resolution={selected_resolution}, HW={selected_hw_concurrency}, Mem={selected_device_memory}GiB, Lang={selected_language}, TZ={selected_timezone}, ColorDepth={selected_color_depth}, Plugins={selected_plugin_mime_set.get('plugins_array_js', '[]')[:20]}..., WebGL={selected_webgl_info}")
        current_options.add_argument(f"--window-size={selected_resolution[0]},{selected_resolution[1]}")
        current_options.add_argument(f"--lang={selected_language}")

        driver_path_to_try = self.chrome_driver_path if self.chrome_driver_path else "chromedriver"
        driver = None
        try:
            service = ChromeService(executable_path=driver_path_to_try)
            driver = webdriver.Chrome(service=service, options=current_options)
            self.logger.debug(f"[{threading.get_ident()}] WebDriver created with path: {driver_path_to_try}")
        except Exception as e_initial:
            self.logger.warning(f"[{threading.get_ident()}] Initial driver creation with path '{driver_path_to_try}' failed: {e_initial}. Retrying with fresh ChromeDriverManager().install().")
            try:
                new_driver_path = ChromeDriverManager().install()
                self.chrome_driver_path = new_driver_path 
                service = ChromeService(executable_path=new_driver_path)
                driver = webdriver.Chrome(service=service, options=current_options)
                self.logger.info(f"[{threading.get_ident()}] WebDriver created successfully with new path: {new_driver_path}")
            except Exception as e_inner:
                self.logger.error(f"[{threading.get_ident()}] Failed to initialize Selenium WebDriver on retry: {e_inner}", exc_info=True)
                self._critical_failure_event.set() 
                raise StartUrlCriticalFailure(f"WebDriver creation failed: {e_inner}") from e_inner
        
        driver.set_page_load_timeout(45) 
        driver.set_script_timeout(30)

        try:
            driver.execute_cdp_cmd("Emulation.setTimezoneOverride", {"timezoneId": selected_timezone})
            self.logger.debug(f"[{threading.get_ident()}] Successfully set timezone override to {selected_timezone}.")
            
            dynamic_js_snippet = f"""
                try {{ Object.defineProperty(navigator, 'webdriver', {{ get: () => undefined }}); }} catch (e) {{ console.warn('AF: Failed to spoof navigator.webdriver:', e.message); }}
                try {{
                    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
                    HTMLCanvasElement.prototype.toDataURL = function(type, encoderOptions) {{
                        if (type === 'image/png') {{ return 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII='; }}
                        return originalToDataURL.call(this, type, encoderOptions);
                    }};
                    const originalGetContext = HTMLCanvasElement.prototype.getContext;
                    HTMLCanvasElement.prototype.getContext = function(contextType, contextAttributes) {{
                        const context = originalGetContext.call(this, contextType, contextAttributes);
                        if (context && (contextType === 'webgl' || contextType === 'webgl2')) {{
                            try {{
                                const originalGetParameter = context.getParameter;
                                context.getParameter = function(parameter) {{
                                    const extension = context.getExtension('WEBGL_debug_renderer_info');
                                    if (extension) {{
                                        if (parameter === extension.UNMASKED_RENDERER_WEBGL) {{ return '{selected_webgl_info["renderer"]}'; }}
                                        if (parameter === extension.UNMASKED_VENDOR_WEBGL) {{ return '{selected_webgl_info["vendor"]}'; }}
                                    }}
                                    return originalGetParameter.call(this, parameter);
                                }};
                            }} catch (e) {{ console.warn('AF: Failed to spoof WebGL getParameter:', e.message); }}
                        }}
                        return context;
                    }};
                }} catch (e) {{ console.warn('AF: Failed to spoof Canvas/WebGL:', e.message); }}
                try {{
                    const spoofedPlugins = {selected_plugin_mime_set.get("plugins_array_js", "[]")};
                    Object.defineProperty(navigator, 'plugins', {{ get: () => spoofedPlugins }});
                    const spoofedMimeTypes = {selected_plugin_mime_set.get("mimeTypes_array_js", "[]")};
                    Object.defineProperty(navigator, 'mimeTypes', {{ get: () => spoofedMimeTypes }});
                }} catch (e) {{ console.warn('AF: Failed to spoof plugins/mimeTypes:', e.message); }}
                try {{
                    Object.defineProperty(navigator, 'hardwareConcurrency', {{ get: () => {selected_hw_concurrency} }});
                    Object.defineProperty(navigator, 'deviceMemory', {{ get: () => {selected_device_memory} }});
                }} catch (e) {{ console.warn('AF: Failed to spoof hardware info:', e.message); }}
                try {{
                    Object.defineProperty(screen, 'width', {{ get: () => {selected_resolution[0]} }});
                    Object.defineProperty(screen, 'height', {{ get: () => {selected_resolution[1]} }});
                    Object.defineProperty(screen, 'availWidth', {{ get: () => {selected_resolution[0]} }});
                    Object.defineProperty(screen, 'availHeight', {{ get: () => {selected_resolution[1]} }}); 
                    Object.defineProperty(screen, 'colorDepth', {{ get: () => {selected_color_depth} }});
                    Object.defineProperty(screen, 'pixelDepth', {{ get: () => {selected_color_depth} }});
                }} catch (e) {{ console.warn('AF: Failed to spoof screen properties:', e.message); }}
                try {{
                    const originalPermissionsQuery = navigator.permissions.query;
                    navigator.permissions.query = async (permissionDesc) => {{ return {{ state: 'denied', onchange: null }}; }};
                    Object.defineProperty(navigator, 'getBattery', {{
                        get: () => async () => ({{
                            charging: true, level: 1.0, chargingTime: 0, dischargingTime: Infinity,
                            addEventListener: () => {{}}, removeEventListener: () => {{}}
                        }})
                    }});
                }} catch (e) {{ console.warn('AF: Failed to spoof permissions/battery:', e.message); }}
            """
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": dynamic_js_snippet})
            self.logger.debug(f"[{threading.get_ident()}] Successfully injected dynamic anti-fingerprinting script.")
        except Exception as cdp_err:
            self.logger.warning(f"[{threading.get_ident()}] Failed to execute CDP command for anti-fingerprinting: {cdp_err}")
        return driver

    def _fetch_headers_via_requests(self, url: str) -> Optional[rq.Response]:
        self.logger.debug(f"Fetching headers for {url} via direct request.")
        try:
            headers = {"User-Agent": random.choice(self.user_agents)}
            response = self.requests_session.get(url, headers=headers, timeout=15, allow_redirects=True, stream=True)
            response.raise_for_status() 
            try: 
                response.iter_content(chunk_size=128).__next__()
            except StopIteration: 
                pass 
            except Exception: 
                pass
            return response
        except rq.RequestException as e:
            self.logger.error(f"Direct request for {url} (for headers) failed: {e}")
            if url == self.start_url and ("Errno -2" in str(e) or "Errno -3" in str(e) or "Name or service not known" in str(e).lower() or "dns" in str(e).lower()):
                 self.logger.critical(f"DNS-like error in requests for start URL {url} (headers). Signaling critical failure.")
                 self._critical_failure_event.set()
            return None


    def _get_selenium_page_content(self, url: str, driver: webdriver.Chrome, worker_ident: str) -> Tuple[Optional[str], Dict[str, str], Dict[str, Any], Optional[int]]:
        html_content: Optional[str] = None
        headers: Dict[str, str] = {}
        cookies_selenium_fmt: Dict[str, Any] = {} # For Wappalyzer: {name: {'value': '...', 'domain': '...'}}
        status_code: Optional[int] = None
        
        self.logger.debug(f"[{worker_ident}] Attempting to fetch content for {url} using Selenium.")
        try:
            self.logger.debug(f"[{worker_ident}] Executing driver.get({url})...")
            driver.get(url)
            self.logger.info(f"[{worker_ident}] driver.get({url}) completed. Current URL: {driver.current_url}. Waiting for body presence.")
            
            WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            html_content = driver.page_source
            self.logger.debug(f"[{worker_ident}] Page source obtained for {url} (length: {len(html_content) if html_content else 0}).")

            selenium_cookies_raw = driver.get_cookies() # List of dicts from Selenium
            cookies_selenium_fmt = {cookie['name']: cookie for cookie in selenium_cookies_raw} 
            self.logger.debug(f"[{worker_ident}] Obtained {len(cookies_selenium_fmt)} cookies for {url}.")

            response_for_headers = self._fetch_headers_via_requests(driver.current_url)
            if response_for_headers:
                headers = dict(response_for_headers.headers)
                status_code = response_for_headers.status_code
                response_for_headers.close() 
                self.logger.debug(f"[{worker_ident}] Obtained headers and status {status_code} for {driver.current_url} via requests.")
            else:
                self.logger.warning(f"[{worker_ident}] Failed to obtain headers/status via requests for {driver.current_url}. Status code will be N/A.")
                status_code = None 
            
            self.logger.info(f"[{worker_ident}] Successfully fetched content for {url} (final URL: {driver.current_url}).")

        except TimeoutException as te:
            self.logger.warning(f"[{worker_ident}] Selenium timeout during page load for {url}: {te}")
        except WebDriverException as wde:
            self.logger.error(f"[{worker_ident}] Selenium WebDriverException during page load for {url}: {type(wde).__name__}: {wde}", exc_info=False) 
            error_type = "selenium_webdriver_error"
            is_critical_start_url_error = False
            if url == self.start_url: 
                err_str = str(wde).lower()
                critical_keywords = [
                    "net::err_name_not_resolved", "net::err_connection_refused",
                    "dns_probe_finished_nxdomain", "tab crashed", "target crashed",
                    "chrome not reachable" 
                ]
                if any(keyword in err_str for keyword in critical_keywords):
                    is_critical_start_url_error = True
                    error_type = "selenium_start_url_critical_error"
            
            if is_critical_start_url_error:
                self.logger.critical(f"[{worker_ident}] Critical Selenium error for start URL {url}. Signaling critical failure event.")
                self._critical_failure_event.set()
                raise StartUrlCriticalFailure(f"Critical Selenium error for start URL {url}: {wde}") from wde
            else:
                raise 
        except Exception as e: 
            self.logger.error(f"[{worker_ident}] Unexpected error during Selenium page load for {url}: {type(e).__name__}: {e}", exc_info=True)
        return html_content, headers, cookies_selenium_fmt, status_code

    def _run_passive_scans_templated(self, url: str, html_content_raw: Optional[str], headers: Dict[str, str], 
                                     page_cookies_selenium_fmt: Dict[str, Any], # From Selenium: {name: {'value': ..., ...}}
                                     status_code_int: Optional[int], # Added status_code
                                     worker_ident: str,
                                     detected_technologies: List[str]) -> List[Dict[str, Any]]:
        self.logger.debug(f"[{worker_ident}] Starting TEMPLATED passive vulnerability checks for {url}.")
        all_passive_findings = []

        if html_content_raw:
            try:
                directory_browsing_alert_obj = self.directory_browsing_scanner.scan(url, html_content_raw, headers)
                if directory_browsing_alert_obj:
                    db_finding = {
                        "type": "passive_scan_alert", 
                        "template_id": "directory-browsing-rule", 
                        "name": directory_browsing_alert_obj.name,
                        "severity": {1: "Info", 2: "Low", 3: "Medium", 4: "High"}.get(directory_browsing_alert_obj.risk, "Unknown"),
                        "description": directory_browsing_alert_obj.description,
                        "passive_hint_type": "DIRECTORY_BROWSING", # Main type
                        "specific_passive_hint_type": "DIRECTORY_BROWSING_DETECTED", # Specific type
                        "url_tested": url,
                        "evidence": directory_browsing_alert_obj.evidence,
                        "solution": directory_browsing_alert_obj.solution,
                        "reference": directory_browsing_alert_obj.reference,
                        "cwe_id": directory_browsing_alert_obj.cwe_id,
                        "wasc_id": directory_browsing_alert_obj.wasc_id,
                    }
                    self.logger.info(f"[{worker_ident}] Directory browsing vulnerability found by class rule: {db_finding['name']}")
                    all_passive_findings.append(db_finding)
            except Exception as e_db_scan:
                self.logger.error(f"[{worker_ident}] Error during DirectoryBrowsingScanRule for {url}: {e_db_scan}", exc_info=True)

        parsed_url_obj = urlparse(url)
        query_params_dict = parse_qs(parsed_url_obj.query, keep_blank_values=True)
        # Convert Selenium cookie format to simple {name: value_string} for PassiveTemplateScanner
        simple_cookies_for_templates = {name: data.get('value', '') for name, data in page_cookies_selenium_fmt.items()}

        try:
            template_based_findings = self.passive_template_scanner.scan_page(
                url, html_content_raw, headers, simple_cookies_for_templates, 
                query_params_dict, status_code_int, # Pass status_code_int
                worker_ident
            )
            if template_based_findings:
                all_passive_findings.extend(template_based_findings)
            self.logger.info(f"[{worker_ident}] Templated passive checks for {url} completed. Found {len(template_based_findings)} hints/findings from templates.")
        except Exception as e_template_scan:
            self.logger.error(f"[{worker_ident}] Error during PassiveTemplateScanner.scan_page for {url}: {e_template_scan}", exc_info=True)
            
        return all_passive_findings


    def _fingerprint_technologies(self, url: str, html_content: str, headers: dict, page_cookies_selenium_fmt: dict, worker_ident: str) -> List[Dict[str, Any]]:
        # page_cookies_selenium_fmt is {name: {'value': ..., 'domain': ...}}
        self.logger.debug(f"[{worker_ident}] Starting technology fingerprinting for {url}.")
        detected_techs_details: Dict[str, Dict[str, Any]] = {} 

        if not html_content and not headers and not page_cookies_selenium_fmt: 
            self.logger.debug(f"[{worker_ident}] Skipping tech fingerprinting for {url} - no content, headers, or cookies.")
            return []

        soup: Optional[BeautifulSoup] = None 

        for tech_name, rules in self.wappalyzer_data.items(): 
            if self._critical_failure_event.is_set(): break
            if tech_name in detected_techs_details: continue 

            def add_tech(name: str, version: Optional[str] = None, confidence: Optional[int] = None) -> None:
                nonlocal detected_techs_details
                if name not in detected_techs_details:
                    detected_techs_details[name] = {"name": name, "versions": set(), "confidence_scores": []}
                if version: 
                    if isinstance(version, list) and version: version = str(version[0])
                    elif isinstance(version, str): version = version.strip("'\"")
                    if version: detected_techs_details[name]["versions"].add(str(version))

                if confidence: detected_techs_details[name]["confidence_scores"].append(int(confidence))
                with self.lock: 
                    self.domain_technologies.add(name)

            def _extract_version_from_match(match_obj: Optional[re.Match], pattern_str_original: Optional[str] = None) -> Optional[str]:
                if match_obj and match_obj.groups():
                    return str(match_obj.group(1))
                if pattern_str_original: 
                    version_match = re.search(r"\\;version:([^\\;\s]+)", pattern_str_original, re.IGNORECASE)
                    if version_match: return version_match.group(1)
                return None

            url_rule = rules.get("url") 
            if url_rule:
                if isinstance(url_rule, re.Pattern):
                    match = url_rule.search(url)
                    if match:
                        add_tech(tech_name, version=_extract_version_from_match(match))
                        continue
                elif isinstance(url_rule, str): 
                    actual_pattern_str = url_rule.split("\\;")[0]
                    if re.search(actual_pattern_str, url, re.IGNORECASE):
                        add_tech(tech_name, version=_extract_version_from_match(None, url_rule))
                        continue
            
            header_rules = rules.get("headers") 
            if header_rules and isinstance(header_rules, dict):
                for header_name_pattern_str, value_pattern_re_or_none in header_rules.items():
                    actual_header_value = next((v for k, v in headers.items() if k.lower() == header_name_pattern_str.lower()), None)
                    if actual_header_value is not None:
                        if value_pattern_re_or_none is None: 
                            add_tech(tech_name)
                            break 
                        elif isinstance(value_pattern_re_or_none, re.Pattern):
                            match = value_pattern_re_or_none.search(actual_header_value)
                            if match:
                                add_tech(tech_name, version=_extract_version_from_match(match))
                                break 
                        elif isinstance(value_pattern_re_or_none, str): 
                            if re.search(value_pattern_re_or_none.split("\\;")[0], actual_header_value, re.IGNORECASE):
                                add_tech(tech_name, version=_extract_version_from_match(None, value_pattern_re_or_none))
                                break
                if tech_name in detected_techs_details: continue
            
            cookie_rules = rules.get("cookies") 
            if cookie_rules and isinstance(cookie_rules, dict) and page_cookies_selenium_fmt:
                for cookie_name_pattern_str, value_pattern_re_or_none in cookie_rules.items():
                    for actual_cookie_name, cookie_data_dict in page_cookies_selenium_fmt.items(): # Iterate Selenium cookie dict
                        try:
                            if re.fullmatch(str(cookie_name_pattern_str), actual_cookie_name, re.IGNORECASE):
                                cookie_value = cookie_data_dict.get('value', '') # Get value from Selenium cookie dict
                                if value_pattern_re_or_none is None: 
                                    add_tech(tech_name)
                                    break 
                                elif isinstance(value_pattern_re_or_none, re.Pattern):
                                    match = value_pattern_re_or_none.search(cookie_value)
                                    if match:
                                        add_tech(tech_name, version=_extract_version_from_match(match))
                                        break
                                elif isinstance(value_pattern_re_or_none, str): 
                                     if re.search(value_pattern_re_or_none.split("\\;")[0], cookie_value, re.IGNORECASE):
                                        add_tech(tech_name, version=_extract_version_from_match(None, value_pattern_re_or_none))
                                        break
                        except re.error: 
                            if str(cookie_name_pattern_str).lower() == actual_cookie_name.lower():
                                cookie_value = cookie_data_dict.get('value', '')
                                if value_pattern_re_or_none is None: add_tech(tech_name); break
                                elif isinstance(value_pattern_re_or_none, re.Pattern):
                                     match = value_pattern_re_or_none.search(cookie_value)
                                     if match: add_tech(tech_name, version=_extract_version_from_match(match)); break
                                elif isinstance(value_pattern_re_or_none, str):
                                     if re.search(value_pattern_re_or_none.split("\\;")[0], cookie_value, re.IGNORECASE):
                                        add_tech(tech_name, version=_extract_version_from_match(None, value_pattern_re_or_none)); break
                    if tech_name in detected_techs_details: break
                if tech_name in detected_techs_details: continue

            if html_content:
                if soup is None: 
                    soup = BeautifulSoup(html_content, 'html.parser')

                html_rules_val = rules.get("html") 
                if html_rules_val:
                    patterns_to_check = html_rules_val if isinstance(html_rules_val, list) else [html_rules_val]
                    for p_re_or_str in patterns_to_check:
                        p_re = p_re_or_str if isinstance(p_re_or_str, re.Pattern) else re.compile(str(p_re_or_str).split("\\;")[0], re.IGNORECASE)
                        match = p_re.search(html_content)
                        if match:
                            add_tech(tech_name, version=_extract_version_from_match(match, str(p_re_or_str) if isinstance(p_re_or_str, str) else None))
                            break
                    if tech_name in detected_techs_details: continue
                
                script_src_rules = rules.get("scriptSrc") 
                if script_src_rules:
                    patterns_to_check = script_src_rules if isinstance(script_src_rules, list) else [script_src_rules]
                    for p_re_or_str in patterns_to_check:
                        p_re = p_re_or_str if isinstance(p_re_or_str, re.Pattern) else re.compile(str(p_re_or_str).split("\\;")[0], re.IGNORECASE)
                        for script_tag in soup.find_all('script', src=True):
                            match = p_re.search(script_tag['src'])
                            if match:
                                add_tech(tech_name, version=_extract_version_from_match(match, str(p_re_or_str) if isinstance(p_re_or_str, str) else None))
                                break
                        if tech_name in detected_techs_details: break 
                    if tech_name in detected_techs_details: continue

                meta_rules = rules.get("meta") 
                if meta_rules and isinstance(meta_rules, dict):
                    for meta_name_str, content_pattern_re_or_none in meta_rules.items():
                        p_re_meta_content: Optional[re.Pattern] = None
                        original_content_pattern_str: Optional[str] = None

                        if isinstance(content_pattern_re_or_none, re.Pattern):
                            p_re_meta_content = content_pattern_re_or_none
                        elif content_pattern_re_or_none is None: 
                            pass 
                        elif isinstance(content_pattern_re_or_none, str): 
                            original_content_pattern_str = content_pattern_re_or_none
                            p_re_meta_content = re.compile(original_content_pattern_str.split("\\;")[0], re.IGNORECASE)
                        
                        for attr_type in ['name', 'property']: 
                            for meta_tag in soup.find_all('meta', attrs={attr_type: meta_name_str, 'content': True}):
                                if p_re_meta_content is None and content_pattern_re_or_none is None: 
                                    add_tech(tech_name)
                                    break
                                elif p_re_meta_content:
                                    match = p_re_meta_content.search(meta_tag['content'])
                                    if match:
                                        add_tech(tech_name, version=_extract_version_from_match(match, original_content_pattern_str))
                                        break
                            if tech_name in detected_techs_details: break
                        if tech_name in detected_techs_details: break
                    if tech_name in detected_techs_details: continue
                
                js_rules = rules.get("js") 
                if js_rules and isinstance(js_rules, dict):
                    for js_prop_path, js_val_pattern_re_or_none in js_rules.items():
                        prop_existence_pattern = re.compile(re.escape(js_prop_path)) 
                        for script_tag in soup.find_all('script'):
                            script_code = script_tag.string or ""
                            if prop_existence_pattern.search(script_code):
                                if js_val_pattern_re_or_none is None: 
                                    add_tech(tech_name) 
                                    break
                                elif isinstance(js_val_pattern_re_or_none, re.Pattern):
                                    add_tech(tech_name) 
                                    break
                        if tech_name in detected_techs_details: break
                    if tech_name in detected_techs_details: continue

                dom_rules = rules.get("dom") 
                if dom_rules:
                    dom_patterns_to_check = []
                    if isinstance(dom_rules, str): dom_patterns_to_check.append(dom_rules)
                    elif isinstance(dom_rules, list): dom_patterns_to_check = dom_rules
                    elif isinstance(dom_rules, dict): 
                        self.logger.debug(f"[{worker_ident}] DOM rules for '{tech_name}' is a dict, complex DOM checks not fully supported yet. Processing simple selectors if any.")
                        if "selector" in dom_rules and isinstance(dom_rules["selector"], str) : 
                             dom_patterns_to_check.append(dom_rules) 

                    for selector_item in dom_patterns_to_check:
                        selector_str: Optional[str] = None
                        if isinstance(selector_item, str):
                            selector_str = selector_item
                        elif isinstance(selector_item, dict) and "selector" in selector_item and isinstance(selector_item["selector"], str): 
                            selector_str = selector_item["selector"]
                        
                        if selector_str:
                            try:
                                if soup.select_one(selector_str):
                                    add_tech(tech_name)
                                    break 
                            except Exception as e_dom: 
                                self.logger.debug(f"[{worker_ident}] DOM select error for selector '{selector_str}' (tech '{tech_name}'): {e_dom}")
                    if tech_name in detected_techs_details: continue
        
        final_detected_list = []
        for name, details in detected_techs_details.items():
            tech_entry: Dict[str, Any] = {"name": name}
            if details["versions"]:
                tech_entry["versions"] = sorted(list(details["versions"]))
            final_detected_list.append(tech_entry)

        if final_detected_list:
            self.logger.info(f"[{worker_ident}] Technology fingerprinting for {url} completed. Detected: {final_detected_list}")
        else:
            self.logger.debug(f"[{worker_ident}] Technology fingerprinting for {url} completed. No technologies detected on this page.")
        return final_detected_list


    def _process_single_page(self, current_url: str, depth: int, driver: webdriver.Chrome, worker_ident: str) -> Tuple[Optional[Dict[str, Any]], List[Tuple[str, int]], List[Dict[str, Any]]]:
        if self._critical_failure_event.is_set():
            self.logger.warning(f"[{worker_ident}] Critical failure signaled. Aborting processing for {current_url}.")
            return None, [], [] 

        self.logger.info(f"[{worker_ident}] Processing page {current_url} (Depth: {depth})...")
        page_info: Dict[str, Any] = {"url": current_url, "status_code": "N/A", "title": "N/A", "depth": depth, "passive_findings_and_hints": []}
        new_links_to_queue: List[Tuple[str, int]] = []
        html_content: Optional[str] = None
        headers: Dict[str, str] = {}
        page_cookies_selenium_fmt: Dict[str, Any] = {} # For Wappalyzer and passive scans
        status_code_int: Optional[int] = None # For passive scans
        detected_tech_list_of_dicts: List[Dict[str, Any]] = []
        final_url_after_redirects = current_url 
        
        try:
            html_content, headers, page_cookies_selenium_fmt, status_code_int = self._get_selenium_page_content(current_url, driver, worker_ident)
            page_info["status_code"] = status_code_int if status_code_int is not None else "N/A (Selenium)"
            final_url_after_redirects = driver.current_url 
            page_info["final_url_after_redirects"] = final_url_after_redirects
            self.logger.debug(f"[{worker_ident}] Content fetched for {current_url}. Final URL: {final_url_after_redirects}. Status: {page_info['status_code']}.")
        except StartUrlCriticalFailure: 
            self.logger.error(f"[{worker_ident}] Start URL {current_url} failed critically.")
            with self.lock: self.bad_urls_accumulator.append({"url": current_url, "error": "StartUrlCriticalFailure", "type": "selenium_start_url_critical_error"})
            page_info["error"] = "StartUrlCriticalFailure"
            return page_info, [], [] 
        except WebDriverException as wde_outer: 
            self.logger.warning(f"[{worker_ident}] WebDriverException for {current_url} during content fetch: {type(wde_outer).__name__}. Will be handled by worker loop.")
            raise 
        except Exception as e: 
            self.logger.error(f"[{worker_ident}] Non-WebDriver error getting content for {current_url}: {e}", exc_info=True)
            with self.lock:
                if not any(b['url'] == current_url for b in self.bad_urls_accumulator):
                     self.bad_urls_accumulator.append({"url": current_url, "error": str(e), "type": "content_fetch_other_error"})
            page_info["error"] = str(e)
            return page_info, [], [] 

        if not html_content: 
            self.logger.warning(f"[{worker_ident}] Failed to get HTML for {current_url}.")
            page_info["error"] = page_info.get("error", "Failed to retrieve HTML content.")
            with self.lock:
                if not any(b['url'] == current_url for b in self.bad_urls_accumulator):
                     self.bad_urls_accumulator.append({"url": current_url, "error": page_info["error"], "type": "no_html_content"})
            return page_info, [], [] 

        try:
            soup_title = BeautifulSoup(html_content, "html.parser")
            page_info["title"] = soup_title.title.string.strip() if soup_title.title else "N/A"
        except Exception as e_title: 
            page_info["title"] = f"Error extracting title: {e_title}"
            self.logger.warning(f"[{worker_ident}] Error extracting title for {current_url}: {e_title}")

        detected_tech_list_of_dicts = self._fingerprint_technologies(driver.current_url, html_content, headers, page_cookies_selenium_fmt, worker_ident)
        if detected_tech_list_of_dicts:
            page_info["technologies_detected"] = detected_tech_list_of_dicts
        
        page_specific_technologies_names = [tech_dict["name"] for tech_dict in detected_tech_list_of_dicts if "name" in tech_dict]
        
        # Convert Selenium cookie format to simple {name: value_string} for active scans
        simple_cookies_for_active_scan = {name: data.get('value', '') for name, data in page_cookies_selenium_fmt.items()}

        passive_findings_and_hints = self._run_passive_scans_templated(
            driver.current_url, html_content, headers, page_cookies_selenium_fmt, status_code_int, # Pass status_code_int
            worker_ident, page_specific_technologies_names
        )
        if passive_findings_and_hints:
            page_info["passive_findings_and_hints"] = passive_findings_and_hints

        if self.active_scanning_enabled and self.active_checker and self.process_event_loop and self.process_event_loop.is_running():
            needs_url_scan = False
            with self.lock: 
                if final_url_after_redirects not in self.url_based_scans_performed:
                    self.url_based_scans_performed.add(final_url_after_redirects)
                    needs_url_scan = True
            
            if needs_url_scan:
                self.logger.info(f"[{worker_ident}] Scheduling URL-based active scans for {final_url_after_redirects} (Tech: {page_specific_technologies_names})")
                url_based_coro = self.active_checker.perform_url_based_active_scans(
                    original_url=final_url_after_redirects, 
                    headers=headers, 
                    cookies=simple_cookies_for_active_scan, # Use simple cookies
                    worker_ident=worker_ident,
                    page_specific_technologies=page_specific_technologies_names,
                    html_content=html_content,
                    passive_scan_hints=passive_findings_and_hints # Pass hints for URL-based rules too
                )
                asyncio.run_coroutine_threadsafe(url_based_coro, self.process_event_loop)


            self.logger.info(f"[{worker_ident}] Scheduling PARAMETER-based active scans for {final_url_after_redirects} (Tech: {page_specific_technologies_names})")
            param_based_coro = self.active_checker.perform_active_scan_for_page(
                original_url=final_url_after_redirects, 
                html_content=html_content,
                headers=headers,
                cookies=simple_cookies_for_active_scan, # Use simple cookies
                worker_ident=worker_ident,
                page_specific_technologies=page_specific_technologies_names,
                passive_scan_hints=passive_findings_and_hints 
            )
            asyncio.run_coroutine_threadsafe(param_based_coro, self.process_event_loop)

        elif self.active_scanning_enabled and not (self.active_checker and self.process_event_loop and self.process_event_loop.is_running()):
             self.logger.warning(f"[{worker_ident}] Active scanning is enabled, but ActiveVulnerabilityCheck instance, event loop, or async queue is not available. Skipping active scan for {driver.current_url}.")
        else: 
            self.logger.debug(f"[{worker_ident}] Active scanning disabled. Skipping for {driver.current_url}.")

        if depth < self.max_depth and not self._critical_failure_event.is_set():
            soup_links = BeautifulSoup(html_content, "html.parser")
            links_found_on_page = 0
            for link_tag in soup_links.find_all("a", href=True):
                href = link_tag["href"]
                if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")): continue
                
                absolute_url = urljoin(final_url_after_redirects, href)
                parsed_absolute_url = urlparse(absolute_url)

                if parsed_absolute_url.netloc == self.base_domain and \
                   parsed_absolute_url.scheme in ["http", "https"]:
                    normalized_url = parsed_absolute_url._replace(fragment="").geturl()
                    new_links_to_queue.append((normalized_url, depth + 1))
                    links_found_on_page +=1
            page_info["links_extracted_on_page"] = links_found_on_page
            self.logger.debug(f"[{worker_ident}] Extracted {links_found_on_page} in-domain links from {driver.current_url}.")

        elif self._critical_failure_event.is_set():
            self.logger.info(f"[{worker_ident}] Critical failure: Not extracting links from {driver.current_url}.")
        else: 
            self.logger.info(f"[{worker_ident}] Max depth reached for {driver.current_url}. Not extracting further links.")
        
        self.logger.info(f"[{worker_ident}] Finished processing page {driver.current_url}.")
        return page_info, new_links_to_queue, [] 

    def _worker_loop(self, worker_id: int, output_queue: queue.Queue[Dict[str, Any]]):
        driver: Optional[webdriver.Chrome] = None
        worker_ident = f"Worker-{worker_id}-{threading.get_ident()}"
        pages_processed_by_this_driver = 0
        MAX_PAGES_PER_DRIVER_INSTANCE = 20 

        def _recreate_driver_and_log(reason: str) -> bool:
            nonlocal driver, pages_processed_by_this_driver
            selected_ua = random.choice(self.user_agents) 
            self.logger.info(f"[{worker_ident}] Attempting to recreate WebDriver (UA: {selected_ua.split(' ')[0]}...) due to: {reason}.")
            if driver:
                try:
                    self.logger.debug(f"[{worker_ident}] Quitting old WebDriver instance..."); driver.quit()
                except Exception as e_q: self.logger.warning(f"[{worker_ident}] Error quitting old WebDriver: {e_q}")
                finally: driver = None 
            try:
                self.logger.debug(f"[{worker_ident}] Creating new WebDriver instance...")
                driver = self._create_driver(user_agent_string=selected_ua)
                pages_processed_by_this_driver = 0 
                self.logger.info(f"[{worker_ident}] Successfully recreated WebDriver.")
                return True
            except StartUrlCriticalFailure: 
                self.logger.critical(f"[{worker_ident}] Critically failed to create WebDriver during recreation. Signaling failure and exiting worker.")
                self._critical_failure_event.set() 
                output_queue.put({"type": "worker_critical_error", "worker_id": worker_id, "message": "WebDriver recreation failed critically"})
                return False
            except Exception as e_create: 
                self.logger.error(f"[{worker_ident}] Unexpected error creating WebDriver during recreation: {e_create}", exc_info=True)
                self._critical_failure_event.set() 
                output_queue.put({"type": "worker_critical_error", "worker_id": worker_id, "message": f"Unexpected WebDriver recreation failed: {e_create}"})
                return False

        try:
            if self._critical_failure_event.is_set(): 
                self.logger.warning(f"[{worker_ident}] Detected critical failure before initial driver creation. Exiting.")
                return
            
            if not _recreate_driver_and_log("initial worker startup"):
                self.logger.error(f"[{worker_ident}] Worker could not initialize WebDriver. Exiting.")
                return 

            while not self._critical_failure_event.is_set():
                current_url_item: Optional[Tuple[str, int]] = None
                try:
                    current_url_item = self.url_queue.get(timeout=0.5) 
                except queue.Empty:
                    continue 
                
                if current_url_item is None: 
                    self.logger.info(f"[{worker_ident}] Received sentinel. Shutting down worker.")
                    self.url_queue.task_done() 
                    break 
                
                current_url, depth = current_url_item
                self.logger.info(f"[{worker_ident}] Picked up {current_url} (Depth: {depth}) from queue.")
                
                page_info_dict: Optional[Dict[str, Any]] = None
                new_links_list: List[Tuple[str, int]] = []

                try:
                    if self.min_request_delay_seconds > 0: 
                        delay = random.uniform(self.min_request_delay_seconds, self.max_request_delay_seconds)
                        self.logger.debug(f"[{worker_ident}] Delaying for {delay:.2f}s before processing {current_url}")
                        time.sleep(delay)
                    
                    if driver is None: 
                        self.logger.error(f"[{worker_ident}] CRITICAL: WebDriver instance is None before processing {current_url}. Attempting recovery.");
                        if not _recreate_driver_and_log("driver was None unexpectedly"):
                             self.logger.error(f"[{worker_ident}] CRITICAL: Failed to recover WebDriver. Worker exiting."); break
                    
                    processing_event = {"type": "page_processing", "url": current_url, "depth": depth, "worker_id": worker_id}
                    self.logger.debug(f"[{worker_ident}] Worker putting 'page_processing' event to output_queue: {processing_event}")
                    output_queue.put(processing_event)

                    self.logger.debug(f"[{worker_ident}] Calling _process_single_page for {current_url}.")
                    page_info_dict, new_links_list, _ = self._process_single_page(current_url, depth, driver, worker_ident) 
                    self.logger.debug(f"[{worker_ident}] _process_single_page returned for {current_url}.")
                    
                    page_result_event = {"type": "page_result", "page_info": page_info_dict, "new_links": new_links_list, "worker_id": worker_id}
                    self.logger.debug(f"[{worker_ident}] Worker putting 'page_result' event to output_queue: {page_result_event}")
                    output_queue.put(page_result_event)

                    if page_info_dict and page_info_dict.get("error"): 
                         with self.lock:
                             if not any(b['url'] == current_url and b.get('error') == page_info_dict.get("error") for b in self.bad_urls_accumulator):
                                 self.bad_urls_accumulator.append({"url": current_url, "error": page_info_dict["error"], "type": "page_processing_error_in_worker"})
                    
                    pages_processed_by_this_driver += 1
                    if pages_processed_by_this_driver >= MAX_PAGES_PER_DRIVER_INSTANCE:
                        self.logger.info(f"[{worker_ident}] Processed {pages_processed_by_this_driver} pages. Restarting WebDriver.")
                        if not _recreate_driver_and_log(f"max pages ({MAX_PAGES_PER_DRIVER_INSTANCE}) reached"):
                            self.logger.error(f"[{worker_ident}] Failed to restart WebDriver after max pages. Worker exiting."); break
                    else:
                         self.logger.debug(f"[{worker_ident}] Processed {pages_processed_by_this_driver}/{MAX_PAGES_PER_DRIVER_INSTANCE} pages for current driver instance.")

                except StartUrlCriticalFailure: 
                    self.logger.critical(f"[{worker_ident}] Caught StartUrlCriticalFailure for {current_url}. Stopping work and signaling.")
                    self._critical_failure_event.set() 
                    self.url_queue.task_done() 
                    break 
                
                except WebDriverException as wd_e: 
                    err_str = str(wd_e).lower()
                    crash_keywords = ["tab crashed", "session deleted", "target crashed", "chrome not reachable", "unable to connect to renderer"]
                    error_type = "selenium_webdriver_crash" if any(kw in err_str for kw in crash_keywords) else "selenium_webdriver_other"
                    self.logger.error(f"[{worker_ident}] WebDriverException ({error_type}) processing {current_url}: {wd_e}. Attempting driver restart.")
                    with self.lock: self.bad_urls_accumulator.append({"url": current_url, "error": f"{error_type}: {str(wd_e)}", "type": error_type})
                    
                    page_result_event = {"type": "page_result", "page_info": {"url": current_url, "depth": depth, "error": f"{error_type}: {str(wd_e)}"}, "new_links": [], "worker_id": worker_id}
                    self.logger.debug(f"[{worker_ident}] Worker putting error 'page_result' event to output_queue: {page_result_event}")
                    output_queue.put(page_result_event)

                    if not _recreate_driver_and_log(f"WebDriverException: {error_type}"):
                        self.logger.error(f"[{worker_ident}] Failed to recover WebDriver after {error_type}. Worker exiting."); break
                
                except Exception as e_inner_loop: 
                    self.logger.exception(f"[{worker_ident}] Unhandled error processing {current_url} in worker's inner loop: {e_inner_loop}")
                    with self.lock: self.bad_urls_accumulator.append({"url": current_url, "error": f"Worker unhandled: {str(e_inner_loop)}", "type": "worker_unhandled_exception"})
                    page_result_event = {"type": "page_result", "page_info": {"url": current_url, "depth": depth, "error": f"Unhandled worker error: {str(e_inner_loop)}"}, "new_links": [], "worker_id": worker_id}
                    self.logger.debug(f"[{worker_ident}] Worker putting error 'page_result' event to output_queue: {page_result_event}")
                    output_queue.put(page_result_event)
                
                finally: 
                    if current_url_item is not None: 
                        try: 
                            self.url_queue.task_done()
                            self.logger.debug(f"[{worker_ident}] url_queue.task_done() called for {current_url}. Remaining tasks: {self.url_queue.unfinished_tasks}")
                        except ValueError: 
                            self.logger.warning(f"[{worker_ident}] ValueError on task_done for {current_url}, possibly already done.")
            
            if self._critical_failure_event.is_set():
                self.logger.info(f"[{worker_ident}] Acknowledging critical failure and exiting worker loop.")
        
        except Exception as e_outer_worker: 
            self.logger.exception(f"[{worker_ident}] CRITICAL error in worker's outer logic or setup: {e_outer_worker}")
            self._critical_failure_event.set() 
            output_queue.put({"type": "worker_critical_error", "worker_id": worker_id, "message": f"Outer worker loop critical error: {e_outer_worker}"})
        
        finally: 
            if driver:
                try:
                    self.logger.debug(f"[{worker_ident}] Worker finishing. Quitting final WebDriver instance.")
                    driver.quit()
                except Exception as e_q_f: self.logger.warning(f"[{worker_ident}] Error quitting driver in final worker cleanup: {e_q_f}")
            self.logger.info(f"[{worker_ident}] Worker loop finished.")
            output_queue.put({"type": "worker_done", "worker_id": worker_id})
            self.logger.info(f"[{worker_ident}] Worker put 'worker_done' event to output_queue.")


    async def close(self):
        if self.aiohttp_session and not self.aiohttp_session.closed: 
            await self.aiohttp_session.close()
            self.logger.info("Aiohttp client session closed.")
        if self.requests_session:
            self.requests_session.close()
            self.logger.info("Requests session closed.")

    async def crawl(self) -> AsyncGenerator[Dict[str, Any], None]:
        if not self.aiohttp_session or self.aiohttp_session.closed:
            connector = aiohttp.TCPConnector(limit_per_host=10, limit=50, ssl=False) 
            self.aiohttp_session = aiohttp.ClientSession(connector=connector)
            self.logger.info("Aiohttp client session created/recreated for crawl.")

        if self.active_scanning_enabled and not self.active_checker:
            if not self.process_event_loop or not self.active_scan_async_q or not self.aiohttp_session:
                 self.logger.error("Active scanning enabled, but process event loop, async queue, or aiohttp session not properly provided. Active scanning will be skipped.")
                 self.active_scanning_enabled = False 
            else:
                self.active_checker = ActiveVulnerabilityCheck(
                    active_scan_timeout=self.active_scan_timeout_config,
                    oast_base_url=self.oob_listener_domain_config,
                    aiohttp_session=self.aiohttp_session, 
                    parent_logger=self.logger,
                    active_scan_async_q=self.active_scan_async_q 
                )
                self.logger.info("ActiveVulnerabilityCheck instance created.")


        self.logger.info(f"Starting crawl for {self.start_url} (depth {self.max_depth}) with {self.num_threads} threads. Streaming progress.")
        self._scan_start_time = datetime.utcnow()
        self._critical_failure_event.clear() 
        self.page_details_accumulator = [] 
        self.bad_urls_accumulator = []
        self.domain_technologies.clear() 
        self.url_based_scans_performed.clear()
        with self.lock: self.visited_links.clear(); self.visited_links.add(self.start_url) 
        
        initial_event = {
            "type": "crawl_start", "target_url": self.start_url, "max_depth": self.original_max_depth,
            "threads": self.num_threads, "active_scanning_enabled": self.active_scanning_enabled,
            "timestamp": self._scan_start_time.isoformat() + "Z"
        }
        self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Yielding initial crawl_start event: {initial_event}")
        yield initial_event 
        
        self.url_queue.put((self.start_url, 0))
        self.logger.info(f"Initial URL {self.start_url} added to queue. URL Queue size: {self.url_queue.qsize()}, Unfinished: {self.url_queue.unfinished_tasks}")
        
        worker_output_queue: queue.Queue[Dict[str, Any]] = queue.Queue() 
        worker_futures: List[concurrent.futures.Future] = [] 
        
        active_workers_tracking = set(range(self.num_threads))
        async_processor_reported_done = False

        try:
            with ThreadPoolExecutor(max_workers=self.num_threads, thread_name_prefix="CrawlerSeleniumWorker") as executor:
                for i in range(self.num_threads):
                    future = executor.submit(self._worker_loop, i, worker_output_queue)
                    worker_futures.append(future)
                self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Launched {self.num_threads} worker threads.")
                self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Entering main processing loop.")

                sentinels_sent_to_workers = False 

                while True: 
                    if self._critical_failure_event.is_set():
                        self.logger.warning(f"[{threading.get_ident()}] CRAWLER.CRAWL: Critical failure event set. Breaking main processing loop.")
                        if not sentinels_sent_to_workers: 
                            self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Critical failure - sending sentinels to url_queue.")
                            for _ in range(self.num_threads):
                                try: self.url_queue.put_nowait(None)
                                except queue.Full: self.logger.warning(f"[{threading.get_ident()}] CRAWLER.CRAWL: URL queue full on critical fail sentinel send.")
                            sentinels_sent_to_workers = True
                        break 

                    item_from_worker: Optional[Dict[str, Any]] = None
                    try:
                        item_from_worker = worker_output_queue.get(timeout=0.2) 
                        worker_output_queue.task_done()

                        self.logger.debug(f"[{threading.get_ident()}] CRAWLER.CRAWL: Main loop YIELDING item (type: {item_from_worker.get('type')}) from worker_output_queue.")
                        yield item_from_worker 

                        item_type = item_from_worker.get("type")
                        if item_type == "page_result":
                            page_info = item_from_worker.get("page_info")
                            new_links_from_page = item_from_worker.get("new_links", [])
                            if page_info:
                                with self.lock: self.page_details_accumulator.append(page_info)
                            if new_links_from_page:
                                with self.lock:
                                    links_added_count = 0
                                    for next_url_normalized, next_depth in new_links_from_page:
                                        if next_depth <= self.max_depth and next_url_normalized not in self.visited_links:
                                            self.visited_links.add(next_url_normalized)
                                            self.url_queue.put((next_url_normalized, next_depth))
                                            links_added_count += 1
                                    if links_added_count > 0:
                                        self.logger.debug(f"[{threading.get_ident()}] CRAWLER.CRAWL: Added {links_added_count} new unique links to URL queue. New URL_Q_Size={self.url_queue.qsize()}, Unfinished: {self.url_queue.unfinished_tasks}")

                        elif item_type == "worker_done":
                            worker_id_done = item_from_worker.get("worker_id")
                            if worker_id_done is not None and worker_id_done in active_workers_tracking:
                                active_workers_tracking.remove(worker_id_done)
                                self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Worker {worker_id_done} reported done. Active workers remaining (tracking): {len(active_workers_tracking)}")

                        elif item_type == "critical_failure" or item_type == "worker_critical_error":
                            self.logger.critical(f"[{threading.get_ident()}] CRAWLER.CRAWL: CRITICAL ERROR reported: {item_from_worker.get('message', 'Unknown critical error')}")
                            self._critical_failure_event.set() 
                            
                    except queue.Empty:
                        pass
                    except Exception as e_main_loop_inner:
                        self.logger.exception(f"[{threading.get_ident()}] CRAWLER.CRAWL: Unexpected error in main processing loop's item handling: {e_main_loop_inner}")
                        self._critical_failure_event.set()
                        yield {"type": "critical_failure", "message": f"Main loop item processing error: {str(e_main_loop_inner)}"}
                        
                    url_queue_is_empty = self.url_queue.empty()
                    url_queue_all_tasks_done = self.url_queue.unfinished_tasks == 0

                    if url_queue_is_empty and url_queue_all_tasks_done and not sentinels_sent_to_workers:
                        self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: URL queue is empty and all tasks processed. Sending shutdown sentinels to workers.")
                        for _ in range(self.num_threads):
                            try:
                                self.url_queue.put_nowait(None) 
                            except queue.Full:
                                self.logger.warning(f"[{threading.get_ident()}] CRAWLER.CRAWL: URL queue full when trying to send worker shutdown sentinel.")
                        sentinels_sent_to_workers = True

                    all_workers_reported_done_tracking = len(active_workers_tracking) == 0

                    if sentinels_sent_to_workers and all_workers_reported_done_tracking and worker_output_queue.empty():
                        self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: All completion conditions met. Breaking main processing loop.")
                        break
                
                self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Main processing loop exited. CriticalFailure={self._critical_failure_event.is_set()}.")

                try:
                    join_timeout_seconds = 20.0
                    self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Attempting to join URL queue (timeout: {join_timeout_seconds}s). Unfinished tasks: {self.url_queue.unfinished_tasks}")
                    self.url_queue.join() 
                    self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: URL queue joined successfully.")
                except Exception as e_join: 
                    self.logger.error(f"[{threading.get_ident()}] CRAWLER.CRAWL: Error or timeout during URL queue join: {e_join}", exc_info=True)
                    self._critical_failure_event.set() 


                self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Waiting for worker threads to complete (futures.result).")
                for i, future in enumerate(worker_futures):
                     try:
                         future.result(timeout=15) 
                         self.logger.debug(f"[{threading.get_ident()}] CRAWLER.CRAWL: Worker future {i} completed successfully.")
                     except TimeoutError:
                         self.logger.warning(f"[{threading.get_ident()}] CRAWLER.CRAWL: Worker future {i} did not complete within timeout after sentinel and join. It might be stuck.")
                     except Exception as e_f: 
                         self.logger.error(f"[{threading.get_ident()}] CRAWLER.CRAWL: Worker future {i} raised an exception during its execution: {e_f}", exc_info=True)
                self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: All worker threads futures processed (or timed out).")
                
                while not worker_output_queue.empty():
                    try:
                        final_item = worker_output_queue.get_nowait()
                        worker_output_queue.task_done()
                        item_type = final_item.get("type")
                        if item_type == "__async_queue_processor_done__" and not async_processor_reported_done:
                            async_processor_reported_done = True 
                            self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Drained __async_queue_processor_done__ sentinel post-loop.")
                        elif item_type not in ["worker_done", "__async_queue_processor_done__"]: 
                            self.logger.debug(f"[{threading.get_ident()}] CRAWLER.CRAWL: Draining final item from worker_output_queue: {final_item.get('type')}")
                            yield final_item
                    except queue.Empty:
                        break
                    except Exception as e_drain:
                        self.logger.error(f"[{threading.get_ident()}] CRAWLER.CRAWL: Error draining worker_output_queue: {e_drain}", exc_info=True)
                        break
                
                if not async_processor_reported_done and self.active_scanning_enabled:
                    self.logger.warning(f"[{threading.get_ident()}] CRAWLER.CRAWL: Async queue processor did not report done. Active scan results might be incomplete if crawl ended prematurely.")


                self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Preparing final summary report. CriticalFailure={self._critical_failure_event.is_set()}")
                scan_duration_seconds = (datetime.utcnow() - self._scan_start_time).total_seconds()
                summary_report = {
                    "target_url": self.start_url, "base_domain": self.base_domain,
                    "max_depth_requested": self.original_max_depth, "max_depth_applied": self.max_depth,
                    "threads_configured": self.num_threads,
                    "request_delay_range_seconds": f"{self.min_request_delay_seconds}-{self.max_request_delay_seconds}",
                    "active_scanning_enabled": self.active_scanning_enabled,
                    "active_scan_timeout_seconds": self.active_scan_timeout_config if self.active_scanning_enabled else None,
                    "oob_listener_domain_configured": self.oob_listener_domain_config if self.active_scanning_enabled else None,
                    "total_pages_processed_with_details": len(self.page_details_accumulator),
                    "total_pages_with_errors_or_unreachable": len(self.bad_urls_accumulator),
                    "scan_start_time_utc": self._scan_start_time.isoformat() + "Z",
                    "scan_end_time_utc": datetime.utcnow().isoformat() + "Z",
                    "scan_duration_seconds": round(scan_duration_seconds, 2),
                    "detected_domain_technologies": sorted(list(self.domain_technologies)) 
                }
                
                if self._critical_failure_event.is_set():
                    crit_err_details_list = [b for b in self.bad_urls_accumulator if "critical_error" in b.get('type','').lower() or "starturlcriticalfailure" in b.get('error','').lower()]
                    crit_msg = crit_err_details_list[0]['error'] if crit_err_details_list and 'error' in crit_err_details_list[0] else "Unknown critical failure"
                    summary_report["status_message"] = f"Crawl ABORTED due to critical error: {crit_msg}"
                    self.logger.critical(f"Crawl for {self.start_url} aborted. Final status: {summary_report['status_message']}")
                elif not self.page_details_accumulator and any(b['url'] == self.start_url for b in self.bad_urls_accumulator):
                     start_url_error_info = next((b for b in self.bad_urls_accumulator if b['url'] == self.start_url), {"error": "Unknown start URL error"})
                     summary_report["status_message"] = f"Start URL ({self.start_url}) was not reachable or failed to load ({start_url_error_info['error']}). No pages scanned."
                     self.logger.warning(f"Crawl for {self.start_url} completed but start URL failed.")
                else: 
                    summary_report["status_message"] = "Crawl completed."
                    self.logger.info(f"Crawl for {self.start_url} completed.")

                final_data_to_yield = {"__final_result__": True, "data": {
                    "summary": summary_report,
                    "scanned_pages_details": self.page_details_accumulator,
                    "unreachable_or_error_urls_summary": self.bad_urls_accumulator,
                    "active_scan_vulnerabilities_found": [] # This will be populated by the main.py from streamed active_scan_alert events
                }}
                self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Yielding THE INTENDED FINAL result for {self.start_url}. Content snippet: {str(final_data_to_yield)[:300]}...")
                yield final_data_to_yield

        except asyncio.CancelledError: 
           self.logger.warning(f"[{threading.get_ident()}] CRAWLER.CRAWL: Task for {self.start_url} was CANCELLED. Signalling critical failure event to stop workers.")
           self._critical_failure_event.set() 
           for _ in range(self.num_threads): 
               try: self.url_queue.put_nowait(None)
               except queue.Full: pass
        except Exception as e_outer_crawl_block: 
            self.logger.critical(f"[{threading.get_ident()}] CRAWLER.CRAWL: CRITICAL unhandled error in main crawl logic for {self.start_url}: {e_outer_crawl_block}", exc_info=True)
            self._critical_failure_event.set() 
            try:
                yield {"type": "critical_failure", "__final_result__": True, "data": {"error": f"Outer crawl logic critical error: {str(e_outer_crawl_block)}", "summary": {"status_message": f"Crawl ABORTED due to critical error: {str(e_outer_crawl_block)}"}}}
            except Exception: pass 
        finally:
           self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Entering 'finally' block for {self.start_url}. critical_failure_event={self._critical_failure_event.is_set()}")
           
           if not self.url_queue.empty() or self.url_queue.unfinished_tasks > 0 or len(active_workers_tracking) > 0 :
               self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: 'finally' - Sending/Re-sending shutdown sentinels to url_queue. Unfinished: {self.url_queue.unfinished_tasks}, Active Workers Tracking: {len(active_workers_tracking)}")
               for _ in range(self.num_threads): 
                   try: self.url_queue.put_nowait(None)
                   except queue.Full: self.logger.warning(f"[{threading.get_ident()}] CRAWLER.CRAWL: 'finally' - URL queue full when trying to send sentinel.")
           
           await asyncio.sleep(0.5) 

           self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: 'finally' - Waiting for worker threads to complete (futures).")
           for i, future in enumerate(worker_futures):
                if future and not future.done():
                    try:
                        future.result(timeout=10.0) 
                        self.logger.debug(f"[{threading.get_ident()}] CRAWLER.CRAWL: 'finally' - Worker future {i} completed.")
                    except TimeoutError:
                        self.logger.warning(f"[{threading.get_ident()}] CRAWLER.CRAWL: 'finally' - Worker future {i} did not complete within timeout. It might be stuck or already exited due to critical failure.")
                    except Exception as e_f_fin:
                        self.logger.error(f"[{threading.get_ident()}] CRAWLER.CRAWL: 'finally' - Worker future {i} raised exception: {e_f_fin}", exc_info=True)

           await self.close() 
           
           self.logger.info(f"[{threading.get_ident()}] CRAWLER.CRAWL: Finished execution for {self.start_url}.")


def _run_crawler_process_streaming(
    start_url: str, max_depth: int, num_threads: int,
    wappalyzer_dir: str,
    passive_template_dir_path: str,
    headless: bool,
    min_request_delay_seconds: float, max_request_delay_seconds: float,
    active_scanning_enabled: bool,
    active_scan_timeout: float,
    oob_listener_domain: Optional[str],
    output_mproc_queue: multiprocessing.Queue, 
    log_level_str: str
):
    process_pid = os.getpid() 
    process_logger_name = f"{__name__}._run_crawler_process.{process_pid}"
    process_logger = logging.getLogger(process_logger_name)

    if process_logger.hasHandlers(): 
        process_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout) 
    formatter = logging.Formatter(f'%(asctime)s - PID {process_pid} - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
    handler.setFormatter(formatter)
    process_logger.addHandler(handler)
    process_logger.propagate = False 

    try:
        log_level_int = getattr(logging, log_level_str.upper(), logging.INFO)
        process_logger.setLevel(log_level_int)
    except AttributeError:
        process_logger.setLevel(logging.INFO) 
        process_logger.warning(f"Invalid log_level_str '{log_level_str}', defaulting to INFO for process logger.")

    main_crawler_module_logger = logging.getLogger(__name__) 
    if not main_crawler_module_logger.hasHandlers() or not any(isinstance(h, logging.StreamHandler) for h in main_crawler_module_logger.handlers):
        for h_rem in main_crawler_module_logger.handlers[:]: main_crawler_module_logger.removeHandler(h_rem)
        main_crawler_module_logger.addHandler(handler) 
    main_crawler_module_logger.setLevel(log_level_int)
    main_crawler_module_logger.propagate = False 

    logging.getLogger("selenium.webdriver.remote.remote_connection").setLevel(logging.WARNING)
    logging.getLogger("selenium.webdriver.common.service").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    logging.getLogger("webdriver_manager").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("itsdangerous").setLevel(logging.WARNING) 

    process_logger.info(f"CRAWLER_PROCESS (PID: {process_pid}) started for {start_url}. Log level: {log_level_str.upper()}")

    animation_stop_event = threading.Event()
    animation_thread = None
    animation_message_prefix = f"Crawler process (PID: {process_pid}) actively crawling {start_url}"
    max_animation_line_len = len(animation_message_prefix) + 15 

    def _animate_cli(stop_event: threading.Event):
        chars = "|/-\\"
        idx = 0
        try:
            while not stop_event.wait(0.15): 
                char = chars[idx % len(chars)]
                line_to_print = f"\r{animation_message_prefix} {char} "
                padding_needed = max(0, max_animation_line_len - len(line_to_print))
                sys.stdout.write(line_to_print + " " * padding_needed)
                sys.stdout.flush() 
                idx += 1
        except Exception as e_anim: 
            process_logger.debug(f"CLI animation thread encountered an error: {e_anim}")
        finally: 
            sys.stdout.write("\r" + " " * max_animation_line_len + "\r")
            sys.stdout.flush()

    if sys.stdout.isatty(): 
        animation_thread = threading.Thread(target=_animate_cli, args=(animation_stop_event,), daemon=True)
        animation_thread.start()
    
    async def _queue_async_to_mproc(async_q: asyncio.Queue, mproc_q: multiprocessing.Queue):
        process_logger.debug(f"CRAWLER_PROCESS (PID {process_pid}) _queue_async_to_mproc task started.")
        try:
            while True:
                item = await async_q.get()
                
                if item is None: 
                    process_logger.info(f"CRAWLER_PROCESS (PID {process_pid}) _queue_async_to_mproc received sentinel. Exiting loop.")
                    async_q.task_done()
                    break

                try:
                    mproc_q.put_nowait(item)
                    process_logger.debug(f"CRAWLER_PROCESS (PID {process_pid}) _queue_async_to_mproc put item (type: {item.get('type')}) onto mproc queue.")
                except queue.Full:
                    process_logger.warning(f"CRAWLER_PROCESS (PID {process_pid}) _queue_async_to_mproc: Multiprocessing queue is full. Dropping item (type: {item.get('type')}).")
                except (BrokenPipeError, EOFError, ConnectionResetError) as q_comm_err_put:
                    process_logger.error(f"CRAWLER_PROCESS (PID {process_pid}) _queue_async_to_mproc: Multiprocessing queue broken during put: {q_comm_err_put}. Terminating processor.", exc_info=False)
                    break 
                except Exception as e_put:
                    process_logger.error(f"CRAWLER_PROCESS (PID {process_pid}) _queue_async_to_mproc: Unexpected error putting item onto mproc queue: {e_put}", exc_info=True)
                    break 

                async_q.task_done()
                await asyncio.sleep(0.001) 
        except Exception as e_processor:
            process_logger.critical(f"CRAWLER_PROCESS (PID {process_pid}) _queue_async_to_mproc task critical error: {e_processor}", exc_info=True)
        finally:
            process_logger.info(f"CRAWLER_PROCESS (PID {process_pid}) _queue_async_to_mproc task finished.")
            try:
                if not isinstance(output_mproc_queue, type(None)) and hasattr(output_mproc_queue, 'put_nowait'): # type: ignore
                    output_mproc_queue.put_nowait({"type": "__async_queue_processor_done__"}) # type: ignore
                    process_logger.debug(f"CRAWLER_PROCESS (PID {process_pid}) _queue_async_to_mproc put done sentinel.")
            except Exception as e_sentinel:
                process_logger.error(f"CRAWLER_PROCESS (PID {process_pid}) _queue_async_to_mproc failed to put done sentinel: {e_sentinel}")


    async def main_in_process():
        process_logger.debug(f"CRAWLER_PROCESS (PID {process_pid}) entering main_in_process async function.")
        current_loop = asyncio.get_running_loop() 
        
        local_active_scan_async_q: asyncio.Queue = asyncio.Queue()
        process_logger.debug(f"CRAWLER_PROCESS (PID {process_pid}) local_active_scan_async_q created.")

        async_to_mproc_task = asyncio.create_task(_queue_async_to_mproc(local_active_scan_async_q, output_mproc_queue))
        process_logger.debug(f"CRAWLER_PROCESS (PID {process_pid}) _queue_async_to_mproc task scheduled.")

        crawler_instance = None 
        try:
            crawler_instance = Crawler( 
                    start_url=start_url, max_depth=max_depth, num_threads=num_threads,
                    wappalyzer_dir_path=wappalyzer_dir,
                    passive_template_dir_path=passive_template_dir_path,
                    headless_selenium=headless,
                    min_request_delay_seconds=min_request_delay_seconds,
                    max_request_delay_seconds=max_request_delay_seconds,
                    active_scanning_enabled=active_scanning_enabled,
                    active_scan_timeout=active_scan_timeout,
                    oob_listener_domain=oob_listener_domain,
                    process_event_loop=current_loop, 
                    active_scan_async_q=local_active_scan_async_q 
                )
            process_logger.debug(f"CRAWLER_PROCESS (PID {process_pid}) Crawler instance created.")

            process_logger.debug(f"CRAWLER_PROCESS (PID {process_pid}) starting crawler_instance.crawl().")
            async for update_item in crawler_instance.crawl():
                is_final = isinstance(update_item, dict) and update_item.get("__final_result__", False)
                try:
                    if is_final:
                        output_mproc_queue.put(update_item, timeout=30.0) 
                        process_logger.info(f"CRAWLER_PROCESS (PID {process_pid}) Successfully put FINAL RESULT to mproc_queue.")
                    else:
                        output_mproc_queue.put_nowait(update_item) 
                except queue.Full:
                    process_logger.warning(f"CRAWLER_PROCESS (PID {process_pid}) main_in_process: Multiprocessing output queue is full. Dropping item: {update_item.get('type')}")
                except (BrokenPipeError, EOFError, ConnectionResetError) as q_err:
                    process_logger.error(f"CRAWLER_PROCESS (PID {process_pid}) main_in_process: Mproc queue broken: {q_err}. Terminating.", exc_info=False)
                    if local_active_scan_async_q: await local_active_scan_async_q.put(None)
                    if crawler_instance and hasattr(crawler_instance, '_critical_failure_event'): crawler_instance._critical_failure_event.set()
                    break 
                except Exception as e_put_main:
                    process_logger.error(f"CRAWLER_PROCESS (PID {process_pid}) main_in_process: Error putting to mproc_queue: {e_put_main}", exc_info=True)
                    break
            process_logger.info(f"CRAWLER_PROCESS (PID {process_pid}) crawler_instance.crawl() generator finished normally.")
        
        except asyncio.CancelledError: 
            process_logger.warning(f"CRAWLER_PROCESS (PID {process_pid}) main_in_process() or crawler_instance.crawl() was cancelled.")
            if crawler_instance and hasattr(crawler_instance, '_critical_failure_event'): crawler_instance._critical_failure_event.set()
        
        except Exception as e_crawl_or_init: 
            process_logger.critical(f"CRAWLER_PROCESS (PID {process_pid}) CRITICAL error in main_in_process (init or crawl): {e_crawl_or_init}", exc_info=True)
            try:
                err_data = {"type": "critical_failure", "__final_result__": True, "data": {"error": f"Crawler process (PID: {process_pid}) critical error: {str(e_crawl_or_init)}", "summary": {"status_message": f"Crawl ABORTED due to process error: {str(e_crawl_or_init)}"}}}
                output_mproc_queue.put_nowait(err_data)
            except Exception: pass 

        finally:
            process_logger.info(f"CRAWLER_PROCESS (PID {process_pid}) main_in_process finally block. Signaling async_to_mproc_task to stop.")
            if local_active_scan_async_q:
                await local_active_scan_async_q.put(None) 
            
            if async_to_mproc_task and not async_to_mproc_task.done():
                try:
                    process_logger.debug(f"CRAWLER_PROCESS (PID {process_pid}) Waiting for async_to_mproc_task to complete.")
                    await asyncio.wait_for(async_to_mproc_task, timeout=5.0)
                    process_logger.debug(f"CRAWLER_PROCESS (PID {process_pid}) async_to_mproc_task completed.")
                except asyncio.TimeoutError:
                    process_logger.warning(f"CRAWLER_PROCESS (PID {process_pid}) Timeout waiting for async_to_mproc_task. Cancelling.")
                    async_to_mproc_task.cancel()
                except Exception as e_wait_async_task:
                    process_logger.error(f"CRAWLER_PROCESS (PID {process_pid}) Error waiting for async_to_mproc_task: {e_wait_async_task}")
            
            if crawler_instance and hasattr(crawler_instance, 'close') and inspect.iscoroutinefunction(crawler_instance.close):
                process_logger.debug(f"CRAWLER_PROCESS (PID {process_pid}) Closing crawler_instance resources.")
                await crawler_instance.close()

    try:
        asyncio.run(main_in_process())
    except Exception as e_outer_run:
        process_logger.critical(f"CRAWLER_PROCESS (PID: {process_pid}) Top-level asyncio.run error: {e_outer_run}", exc_info=True)
        try:
            err_data = {"type": "critical_failure", "__final_result__": True, "data": {"error": f"Crawler process (PID: {process_pid}) critical outer error: {str(e_outer_run)}", "summary": {"status_message": f"Crawl ABORTED due to process outer error: {str(e_outer_run)}"}}}
            output_mproc_queue.put_nowait(err_data)
        except Exception: pass
    finally:
        if animation_thread and animation_thread.is_alive():
            animation_stop_event.set()
            animation_thread.join(timeout=1.0)
        process_logger.info(f"CRAWLER_PROCESS (PID: {process_pid}) _run_crawler_process_streaming function finished.")


async def crawl_and_analyze_site_tool(
    start_url: str,
    max_depth: int = 1,
    num_threads_per_scan: int = 2, 
    headless: bool = True,
    min_request_delay_seconds: float = 1.0,
    max_request_delay_seconds: float = 3.0,
    active_scanning_enabled: bool = False,
    active_scan_timeout: float = 10.0,
    oob_listener_domain: Optional[str] = None,
    log_level: str = "INFO" 
) -> AsyncGenerator[Dict[str, Any], None]:
    crawl_and_analyze_site_tool._is_streaming_tool = True # type: ignore 
    
    tool_logger = logging.getLogger(f"{__name__}.CrawlToolEntry")

    passive_template_dir_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'CrawlerConfig', 'PassiceScanTemplates') # Corrected typo
    wappalyzer_dir = os.path.join(os.path.dirname(__file__), '..', 'config', 'CrawlerConfig', 'TechFingerprints')
    
    try: 
        actual_max_depth = int(float(max_depth))
        if actual_max_depth < 0: actual_max_depth = 0 
    except ValueError:
        tool_logger.error(f"[{threading.get_ident()}] Invalid max_depth value: {max_depth}. Defaulting to 1.")
        actual_max_depth = 1

    tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Initiating site crawl for {start_url} (depth={actual_max_depth}, active_scan={active_scanning_enabled}) via separate process.")
    
    if not (start_url.startswith("http://") or start_url.startswith("https://")):
        tool_logger.error(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Invalid start_url: {start_url}. Must include scheme.")
        yield {"type": "critical_failure", "__final_result__": True, "data": {"error": "Invalid start_url. Must include http:// or https:// scheme.", "summary": {"status_message": "Crawl ABORTED: Invalid start_url."}}}
        return

    try:
        ctx = multiprocessing.get_context('spawn')
    except Exception:
        tool_logger.warning("Spawn context for multiprocessing not available, using default.")
        ctx = multiprocessing.get_context()

    output_mproc_queue: multiprocessing.Queue = ctx.Queue() 
    tool_logger.debug(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Multiprocessing queue created for {start_url}.")

    process = ctx.Process(
        target=_run_crawler_process_streaming,
        args=(
            start_url, actual_max_depth, num_threads_per_scan,
            wappalyzer_dir, passive_template_dir_path, 
            headless, min_request_delay_seconds, max_request_delay_seconds,
            active_scanning_enabled, active_scan_timeout, oob_listener_domain,
            output_mproc_queue, log_level
        ),
        daemon=True 
    )

    process_pid: Optional[int] = None
    try:
        tool_logger.debug(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Attempting to start Crawler process for {start_url}.")
        process.start()
        process_pid = process.pid 
        tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Crawler process (PID: {process_pid}) launched for {start_url}.")
        yield {"type": "process_started", "pid": process_pid, "message": f"Crawler process started with PID {process_pid}"} 
    except Exception as e_start: 
        tool_logger.error(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Failed to start Crawler process for {start_url}: {e_start}", exc_info=True)
        yield {"type": "critical_failure", "__final_result__": True, "data": {"error": f"Failed to start Crawler process: {str(e_start)}", "summary": {"status_message": f"Crawl ABORTED: Failed to start process: {str(e_start)}"}}}
        if process.is_alive(): process.terminate() 
        return

    PROCESS_COMPLETION_TIMEOUT_SECONDS = int(os.getenv("CRAWLER_PROCESS_TIMEOUT", 3600 * 2)) 
    tool_logger.info(f"CRAWLER_TOOL_ENTRY [{threading.get_ident()}] Crawler process timeout set to {PROCESS_COMPLETION_TIMEOUT_SECONDS} seconds for {start_url}")
    process_start_time = time.monotonic()
    final_result_yielded_from_queue = False 
    last_item_from_proc_debug: Optional[str] = None 

    tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Generator entering read loop for {start_url} (PID: {process_pid}).")

    try: 
        while True: 
            if not process.is_alive() and output_mproc_queue.empty():
                tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Process for {start_url} (PID: {process_pid}) has exited and queue is empty. Exiting generator loop.")
                break
            
            elapsed_time = time.monotonic() - process_start_time
            if elapsed_time > PROCESS_COMPLETION_TIMEOUT_SECONDS:
                tool_logger.error(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Generator loop timeout after {PROCESS_COMPLETION_TIMEOUT_SECONDS}s for {start_url} (PID: {process_pid}).")
                if not final_result_yielded_from_queue:
                    timeout_msg = f"Crawler process for {start_url} timed out after {PROCESS_COMPLETION_TIMEOUT_SECONDS}s."
                    timeout_data = {"type": "timeout", "__final_result__": True, "data": {"error": timeout_msg, "summary": {"status_message": f"Crawl ABORTED: {timeout_msg}"}}}
                    tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Yielding timeout error as final result: {str(timeout_data)[:200]}")
                    yield timeout_data
                    final_result_yielded_from_queue = True
                break 

            item_from_proc: Optional[Dict[str, Any]] = None 
            try:
                item_from_proc = await asyncio.to_thread(output_mproc_queue.get, timeout=0.5)
                last_item_from_proc_debug = str(item_from_proc)[:200] 
                
                is_final_in_item_from_proc = isinstance(item_from_proc, dict) and item_from_proc.get("__final_result__", False)
                tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Generator GOT item from mproc_queue for {start_url}: type={item_from_proc.get('type')}, final_flag={is_final_in_item_from_proc}, keys={list(item_from_proc.keys()) if isinstance(item_from_proc, dict) else 'N/A'}")

                yield item_from_proc 
                tool_logger.debug(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Generator YIELDED item to SSE handler for {start_url}.")

                if is_final_in_item_from_proc: 
                    tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Received __final_result__ marker from Crawler process for {start_url}. Setting flag and breaking generator loop.")
                    final_result_yielded_from_queue = True 
                    break 

            except queue.Empty: 
                tool_logger.debug(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Generator mproc_queue empty for {start_url}. Looping again.")
                await asyncio.sleep(0.1) 
                continue 
            except (EOFError, BrokenPipeError, ConnectionResetError) as q_comm_err: 
                tool_logger.error(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Generator caught queue communication error for {start_url} (PID: {process_pid}): {q_comm_err}", exc_info=False)
                if not final_result_yielded_from_queue: 
                    error_data = {"type": "queue_communication_error", "__final_result__": True, "data": {"error": f"Queue communication error with Crawler process for {start_url}: {str(q_comm_err)}", "summary": {"status_message": f"Crawl ABORTED: Queue error {str(q_comm_err)}"}}}
                    tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Yielding queue communication error as final result: {str(error_data)[:200]}")
                    yield error_data
                    final_result_yielded_from_queue = True 
                break 
            
    except asyncio.CancelledError:
        tool_logger.warning(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] crawl_and_analyze_site_tool generator for {start_url} (PID: {process_pid}) was CANCELLED.")
        if not final_result_yielded_from_queue:
            cancel_data = {"type": "cancelled", "__final_result__": True, "data": {"error": f"Crawl tool for {start_url} was cancelled.", "summary": {"status_message": "Crawl ABORTED: Tool cancelled."}}}
            tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Yielding cancellation error as final result: {str(cancel_data)[:200]}")
            try:
                yield cancel_data 
            except Exception as e_yield_cancel:
                tool_logger.warning(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Could not yield cancellation error: {e_yield_cancel}")
            final_result_yielded_from_queue = True
    except Exception as e_outer_loop: 
        tool_logger.error(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Unhandled exception in crawl_and_analyze_site_tool generator loop for {start_url} (PID: {process_pid}): {e_outer_loop}", exc_info=True)
        if not final_result_yielded_from_queue:
            outer_loop_err_data = {"type": "unhandled_exception", "__final_result__": True, "data": {"error": f"Unexpected error in tool generator for {start_url}: {str(e_outer_loop)}", "summary": {"status_message": f"Crawl ABORTED: Unexpected generator error {str(e_outer_loop)}"}}}
            tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Yielding outer loop error as final result: {str(outer_loop_err_data)[:200]}")
            try:
                yield outer_loop_err_data
            except Exception as e_yield_outer_err:
                 tool_logger.warning(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Could not yield outer loop error: {e_yield_outer_err}")
            final_result_yielded_from_queue = True
    finally:
        tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Crawler tool generator 'finally' block for {start_url} (PID: {process_pid}). final_result_yielded_from_queue={final_result_yielded_from_queue}")

        if process.is_alive():
            tool_logger.warning(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Crawler process (PID: {process_pid}) for {start_url} is still alive after generator exit. Terminating.")
            process.terminate() 
            process.join(timeout=10) 
            if process.is_alive(): 
                tool_logger.critical(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Crawler process (PID: {process_pid}) for {start_url} did not terminate after SIGTERM. Sending SIGKILL.")
                process.kill() 
                process.join(timeout=5) 
                if process.is_alive():
                    tool_logger.error(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] CRITICAL: Crawler process (PID: {process_pid}) for {start_url} FAILED TO DIE after SIGKILL.")
        else:
            tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Crawler process (PID: {process_pid}) for {start_url} has exited. Exit code: {process.exitcode if hasattr(process, 'exitcode') else 'N/A'}.")
        
        try:
            while not output_mproc_queue.empty():
                try: output_mproc_queue.get_nowait()
                except queue.Empty: break
            output_mproc_queue.close()
            output_mproc_queue.join_thread() 
        except Exception as e_q_final_close:
            tool_logger.warning(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Error closing/joining mproc queue in finally block for {start_url}: {e_q_final_close}")

        if not final_result_yielded_from_queue: 
             tool_logger.error(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Generator for {start_url} (PID: {process_pid}) finished, but no __final_result__ was explicitly yielded from queue. Process exit code: {process.exitcode if hasattr(process, 'exitcode') else 'N/A'}. Last item snippet from proc: {last_item_from_proc_debug}")
             fallback_msg = f"Crawler process for {start_url} (PID: {process_pid}) finished without sending an explicit final result via queue. Exit code: {process.exitcode if hasattr(process, 'exitcode') else 'N/A'}."
             fallback_data = {"type": "fallback_error", "__final_result__": True, "data": {"error": fallback_msg, "summary": {"status_message": f"Crawl ABORTED: {fallback_msg}"}}}
             tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Yielding fallback final error for {start_url} because __final_result__ was not confirmed from queue: {str(fallback_data)[:200]}")
             try:
                 yield fallback_data 
             except Exception as e_yield_fallback:
                 tool_logger.warning(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] Could not yield fallback final error: {e_yield_fallback}")

        tool_logger.info(f"CRAWL_TOOL_ENTRY [{threading.get_ident()}] crawl_and_analyze_site_tool for {start_url} has completed its management of the Crawler process.")