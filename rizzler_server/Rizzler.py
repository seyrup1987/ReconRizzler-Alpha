# --- START OF FILE main.py ---
# (Keep existing imports and logging configuration)

from mcp.server.fastmcp import FastMCP
from fastapi import FastAPI, Request, HTTPException
from sse_starlette.sse import EventSourceResponse
from typing import Optional, Dict, Any, AsyncGenerator, List 
import sys
import inspect
import base64
import uvicorn
import json
import logging
import os
import asyncio
import requests
import httpx
from urllib.parse import urlparse
from bs4 import BeautifulSoup, Comment
from datetime import datetime

# Tool imports
from ReconTools.PortParser import portScanner4LLM
from ReconTools.SubdomainMapper import subDomainMapper4LLM
from ReconTools.AddressFinder import AddressFinderForLLM
from ReconTools.ingest2DB import chunk_and_ingest, queryDB, RECON_COLLECTION_NAME, get_faiss_client # Added get_faiss_client
from ReconTools.ingestResults2DB import ingest_results_to_db
from ReconTools.WebFetcher import fetch_web_page_content, DEFAULT_USER_AGENT_AUTONOMOUS
from ReconTools.Crawler import crawl_and_analyze_site_tool as actual_site_mapper_analyzer
from ReconTools.ReportGenerator import generate_pdf_from_summarized_sections


# Logging Configuration (remains the same)
LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = os.path.join(LOG_DIR, f"mcp_pentest_server_{timestamp}.log")
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
console_log_handler = logging.StreamHandler(sys.stdout)
console_log_handler.setFormatter(log_formatter)
console_log_handler.setLevel(logging.DEBUG) 
file_handler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
file_handler.setLevel(logging.DEBUG) 
file_handler.setFormatter(log_formatter)

logger = logging.getLogger("mcp-pentest-server")
logger.setLevel(logging.DEBUG) 
for handler in logger.handlers[:]:
    logger.removeHandler(handler)
    try: handler.close()
    except: pass
logger.addHandler(console_log_handler)
logger.addHandler(file_handler)
logger.propagate = False


mcpServer = FastMCP("PENTEST-MCP-SERVER")
app = FastAPI()

USER_AGENT = "pentest-app/1.0" 
SEARXNG_BASE_URL = os.getenv("SEARXNG_BASE_URL", "http://searxng:7070")
SEARXNG_TIMEOUT = 15.0 

@mcpServer.resource(uri="file:///home/seyrup/Projects_Private/ReCon_Artist/config/WordLists-20111129/Directories_All.txt")
def common_directories(): # Remains the same
    filename = "/home/seyrup/Projects_Private/config/WordLists-20111129/Directories_All.txt"
    logger.debug(f"Loading directories from {filename}")
    try:
        with open(filename, "r") as file:
            directoriesList = [line.strip() for line in file if line.strip()]
        logger.info(f"Loaded {len(directoriesList)} directories")
        return directoriesList
    except FileNotFoundError:
        logger.warning(f"Directory list file {filename} not found, using small default list.")
        return ["admin", "backup", "config", "dashboard", "db", "debug", "images",
                "inc", "include", "js", "log", "login", "old", "private", "robots.txt",
                "scripts", "secret", "temp", "test", "upload", "uploads", "wp-admin", "wp-content"]
    except Exception as e:
        logger.exception(f"Error loading directories: {e}")
        return []

async def tool_call_result_summary_prompt(): # Remains the same
    return """
    Analyze the provided tool call result and generate a concise summary suitable for an LLM.
    Focus on key findings, actionable data, and any errors.
    Tool Result:
    !!RESULT!!
    Concise Summary:
    """

async def web_vulnerability_prompt(): # Remains the same (as per instruction)
    return """
    Instructions:
    1. Goal Understanding: Deconstruct the main 'Problem' into a high-level sequence of objectives.
    2. Initial Planning with STP: Use 'SequentialThinkingPlanner' to lay out your initial sequence of thoughts (steps) to achieve these objectives. Number each thought.
    3. Tool Execution: For thoughts requiring external actions, call the appropriate tool.
    4. Result Analysis & Reflection (CRITICAL STEP):
        - After EACH tool call (especially non-STP tools), analyze its output.
        - Ask:
            - Did the tool succeed and provide the expected information?
            - Does this result align with the current thought and overall plan?
            - Does this result invalidate any previous assumptions or thoughts?
            - Is the overall plan still the most efficient path to the goal?
    5. Plan Adaptation with STP (Self-Correction):
        - If reflection indicates a need for change:
            - Use 'SequentialThinkingPlanner' IMMEDIATELY to document your re-assessment.
            - To correct a flawed previous thought: Use STP with `isRevision=True` and `revisesThought=[thought_number_to_correct]`. Clearly state *why* it's being revised and provide the new thought.
            - To explore an alternative path: Use STP with `branchFromThought=[thought_number]` and a `branchId`.
            - To add a new clarifying thought: Use STP normally.
        - Provide a clear rationale for any plan modifications. Your thought process for *re-planning* is as important as the initial plan.
    6. Iteration: Continue executing tools and reflecting/adapting until the 'Problem' is solved.
    7. Final Answer: Once the 'Problem' is fully addressed and verified, provide a comprehensive final answer. This final answer MUST NOT include any tool calls, not even to 'SequentialThinkingPlanner'.
    8. Periodic Review: After every 3-4 significant tool executions (excluding STP), pause to explicitly review your *entire thought sequence and overall plan progress* using STP. State your confidence in the current plan.
    9. Error Handling: If a tool fails, use STP to log the failure, your analysis of why it might have failed, and your revised plan to overcome this obstacle (e.g., trying different parameters, an alternative tool, or re-evaluating a prior assumption).
    10. Tools: {functions}

    "Function_Call_Format": [func_name1(params_name1=params_value1), func_name2(params)]
    "Example of Revising a Thought with STP":
    Suppose Thought #2 was 'Scan for common web ports (80, 443)' and the PortScanner failed or you realized you need more.
    AI (using STP): SequentialThinkingPlanner(thought='Revising thought #2. Initial scan was too limited and missed potential management interfaces. Expanding port scan.', thoughtNumber=2.1, totalThoughts='approx 5', isRevision=True, revisesThought=2, nextThoughtNeeded=True, context='Port scan adjustment after initial failure/reassessment')
    AI (next call): PortScanner(domain='example.com', startPort=1, endPort=1024)
    """

async def _store_recon_results_internal(results_json: dict, source_info: str, tool_name_for_log: str): # Remains the same
    logger.info(f"Internal: Starting storage for {tool_name_for_log} results. Source: {source_info}")
    if not isinstance(results_json, dict):
        logger.error(f"InternalStore: Invalid input for {tool_name_for_log}: 'results_json' must be a dictionary")
        return {"status": "error", "error": "Input 'results_json' must be a dictionary."}
    try:
        ingestion_result = await ingest_results_to_db(json_data=results_json, source_metadata=source_info)
        if 'error' in ingestion_result:
            logger.error(f"InternalStore: Failed to store {tool_name_for_log} results: {ingestion_result['error']}")
            return {"status": "error", "error": f"Failed to store results: {ingestion_result['error']}"}
        doc_id = ingestion_result.get('id', 'N/A')
        logger.info(f"InternalStore: Successfully stored {tool_name_for_log} results. Result ID: {doc_id}")
        return {"status": "success", "message": f"Stored results from {source_info}.", "id": doc_id}
    except Exception as e:
        logger.exception(f"InternalStore: Unexpected error storing {tool_name_for_log} results: {e}")
        return {"status": "error", "error": f"Unexpected error: {str(e)}"}

def validate_schema(params_schema): # Remains the same
    if not isinstance(params_schema, dict):
        return False
    required_fields = ['type', 'properties']
    return all(field in params_schema for field in required_fields) and isinstance(params_schema.get('properties'), dict)

def is_valid_url(url: str) -> bool: # Remains the same
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and parsed.netloc != ''
    except Exception:
        return False

def calculate_relevance_score(result: dict, query: str) -> float: # Remains the same
    score = 0.0
    query_words = set(query.lower().split())
    title = result.get('title', '').lower()
    title_matches = len([word for word in query_words if word in title])
    score += 0.4 * (title_matches / max(len(query_words), 1))
    body = result.get('body', '').lower()
    body_matches = len([word for word in query_words if word in body])
    score += 0.3 * (body_matches / max(len(query_words), 1))
    body_length = len(body)
    score += 0.2 * min(body_length / 200, 1.0)
    domain = urlparse(result.get('href', '')).netloc.lower()
    high_value_domains = {'.edu', '.gov', '.org', 'wikipedia.org', 'microsoft.com', 'apache.org', 'python.org'}
    if any(domain.endswith(d) for d in high_value_domains):
        score += 0.1
    return score

# --- Standard Tools (Non-Streaming or handled by simple await) ---
@mcpServer.tool()
async def SequentialThinkingPlanner( # Remains the same
        thought: str,
        nextThoughtNeeded: bool,
        thoughtNumber: int,
        totalThoughts: int,
        isRevision: Optional[bool] = False,
        revisesThought: Optional[int] = None,
        branchFromThought: Optional[int] = None,
        branchId: Optional[str] = None,
        needsMoreThoughts: Optional[bool] = None,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
    """
    Facilitates a detailed, step-by-step thinking process for problem-solving and analysis.
    This tool helps structure and record a sequence of thoughts, allowing for revisions,
    branching, and dynamic adjustment of the thought process.

    Args:
        thought (str): The current thinking step or piece of information.
        nextThoughtNeeded (bool): Indicates if another thought step is anticipated to follow this one.
        thoughtNumber (int): The sequential number of the current thought in the process (e.g., 1, 2, 3...).
        totalThoughts (int): The initially estimated total number of thoughts required for the problem.
        isRevision (bool, optional): True if this thought is a revision of a previous thought. Defaults to False.
        revisesThought (int, optional): If isRevision is True, this specifies the thoughtNumber of the thought being revised.
        branchFromThought (int, optional): If this thought starts a new branch of reasoning, this specifies the thoughtNumber it branches from.
        branchId (str, optional): A unique identifier for a branch of thought, if applicable.
        needsMoreThoughts (bool, optional): Can be set by the LLM if it determines more thoughts are needed beyond the current totalThoughts.
        context (str, optional): Additional context or summary of the preceding thoughts or overall problem.

    Returns:
        A dictionary containing the processed thought and its metadata, confirming the step in the sequential thinking process.
    """
    tool_name = "SequentialThinkingPlanner"
    logger.info(
        f"Executing {tool_name}: Thought #{thoughtNumber}/{totalThoughts}, NextNeeded: {nextThoughtNeeded}, Revision: {isRevision}"
    )
    result = {
        "status": "success",
        "processed_thought": {
            "thought": thought, "thoughtNumber": thoughtNumber, "totalThoughts": totalThoughts,
            "nextThoughtNeeded": nextThoughtNeeded, "isRevision": isRevision, "revisesThought": revisesThought,
            "branchFromThought": branchFromThought, "branchId": branchId, "needsMoreThoughts": needsMoreThoughts,
            "context": context, "timestamp": datetime.now().isoformat()
        },
        "message": f"Thought #{thoughtNumber} processed."
    }
    logger.info(f"Completed {tool_name} for thought #{thoughtNumber}. Result: {result}")
    return result

@mcpServer.tool()
async def WebSearch(query: str): # Remains the same
    """
    Use searxng meta search to search the Internet, with filtering and ranking of results.

    Args:
        query: a string containing the text to search for on the Internet.

    Returns:
        List of filtered and ranked URLs that are the most relevant sources for the searched text.
    """
    tool_name = "WebSearch"
    target_info = f"query: '{query}'"
    logger.info(f"Starting {tool_name} for {target_info} using SearxNG.")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{SEARXNG_BASE_URL}/search",
                params={"q": query, "format": "json", "safesearch": 1},
                timeout=SEARXNG_TIMEOUT
            )
            response.raise_for_status() 
            searxng_results = response.json()
        raw_results = searxng_results.get('results', [])
        adapted_results = []
        for r in raw_results:
            if 'url' in r and 'title' in r and 'content' in r:
                adapted_results.append({
                    'href': r['url'],
                    'title': r['title'],
                    'body': r['content']
                })
        if not isinstance(adapted_results, list):
            logger.error(f"[{tool_name}] Expected list, got {type(adapted_results)} from SearxNG.")
            return {"error": f"Invalid result type: {type(adapted_results)} from SearxNG."}
        blocklist_domains = {'twitter.com', 'facebook.com', 'instagram.com', 'pinterest.com', 'tiktok.com'}
        filtered_results = [
            r for r in adapted_results
            if is_valid_url(r.get('href', '')) and
               r.get('title') and r.get('body') and
               not any(urlparse(r.get('href', '')).netloc.lower().endswith(blocked) for blocked in blocklist_domains)
        ]
        ranked_results = sorted(filtered_results, key=lambda r: calculate_relevance_score(r, query), reverse=True)[:15]
        logger.info(f"Completed {tool_name}, returning {len(ranked_results)} results from SearxNG.")
        return {'results': ranked_results}
    except httpx.RequestError as e:
        logger.error(f"Error connecting to SearxNG in {tool_name}: {e}")
        return {"error": f"Failed to connect to SearxNG: {str(e)}"}
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error from SearxNG in {tool_name}: {e}")
        return {"error": f"SearxNG returned HTTP error: {str(e)}"}
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error from SearxNG in {tool_name}: {e}")
        return {"error": f"Failed to parse JSON response from SearxNG: {str(e)}"}
    except Exception as error:
        logger.error(f"Unexpected error in {tool_name}: {error}")
        return {"error": str(error)}

@mcpServer.tool()
async def WebSearch4CVEs(technology: str): # Remains the same
    """
    Use searxng meta search to search the website cvedetails.com for common vulnerabilities and exploits for the given technology.

    Args:
        technology: Technology for which common vulnerabilities and exploits will be searched for.

    Returns:
        List of URLs that are the most relevant sources for the searched text.
    """
    tool_name = "WebSearch4CVEs"
    search_query = f"site:cvedetails.com {technology}"
    logger.info(f"Starting {tool_name} for technology: '{technology}' using SearxNG.")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{SEARXNG_BASE_URL}/search",
                params={"q": search_query, "format": "json", "safesearch": 1},
                timeout=SEARXNG_TIMEOUT
            )
            response.raise_for_status()
            searxng_results = response.json()
        adapted_results = []
        for r in searxng_results.get('results', []):
            if 'url' in r and 'title' in r:
                adapted_results.append({
                    'href': r['url'],
                    'title': r['title'],
                    'body': r.get('content', '') 
                })
        logger.info(f"Completed {tool_name}, found {len(adapted_results)} results from SearxNG.")
        return {'results': adapted_results}
    except httpx.RequestError as e:
        logger.error(f"Error connecting to SearxNG in {tool_name}: {e}")
        return {"error": f"Failed to connect to SearxNG: {str(e)}"}
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error from SearxNG in {tool_name}: {e}")
        return {"error": f"SearxNG returned HTTP error: {str(e)}"}
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error from SearxNG in {tool_name}: {e}")
        return {"error": f"Failed to parse JSON response from SearxNG: {str(e)}"}
    except Exception as error:
        logger.error(f"Unexpected error in {tool_name}: {error}")
        return {"error": str(error)}

@mcpServer.tool()
async def GetWebPages(url: str, force_raw: bool = False, ignore_robots_txt: bool = False): # Remains the same
    """
    Gets visible text from a URL using 'requests'.
    
    Args:
        url: The URL whose visible text will be retreived.
        force_raw: Get simplified, Markdown-formatted text from HTML pages, when set to 'False'.
        ignore_robots_txt: Flag indicating if we should ignore robots.txt
    Returns:
        All of teh visible text in the web page of the URL.
    """
    tool_name = "GetWebPages"
    logger.info(f"Starting {tool_name} for url: {url} (force_raw: {force_raw}, ignore_robots_txt: {ignore_robots_txt})")
    fetch_result = await fetch_web_page_content(
        url=url,
        force_raw=force_raw,
        user_agent=USER_AGENT, 
        ignore_robots_txt=ignore_robots_txt
    )
    if fetch_result["error"]:
        logger.error(f"Error in {tool_name} for {url}: {fetch_result['error']}")
        return {"error": fetch_result["error"]}
    content = fetch_result["content"]
    logger.info(f"Completed {tool_name} for {url}, extracted {len(content)} chars.")
    return {'visibleText': content}

@mcpServer.tool()
async def IngestText2DB(inputText: str, metadata: str): # Remains the same
    """
    Ingests text (single chunk) into DB. Assumes ingest2DB is async.

    Args:
        inputText: Chunk of text to be stored into the vector database.
        metadata: Information detailing the origin of the information in 'inputText'.
    Returns:
        A dictionary containing a list of relevant documents/results found or an error message.
    """
    tool_name = "IngestText2DB"
    logger.warning(f"Calling deprecated {tool_name}")
    from ReconTools.ingest2DB import ingest2DB as actual_ingest2DB
    try:
        results = await actual_ingest2DB(inputText, metadata)
        logger.info(f"Completed {tool_name}")
        return {"results": str(results)}
    except Exception as error:
        logger.error(f"Error in {tool_name}: {error}")
        return {'error': str(error)}

@mcpServer.tool()
async def QueryVectorDB(query: str, n_results: int = 5, collection: str = "documents"): # Remains the same
    """
    Queries a specified Chroma vector database collection to find documents relevant to the input query.

    Args:
        query: The natural language query string to search for.
        n_results: The maximum number of relevant documents to return. Defaults to 5.
        collection: The name of the collection to query (e.g., "documents", "Reconnaissance"). Defaults to "documents".

    Returns:
        A dictionary containing a list of relevant documents/results found or an error message.
    """
    tool_name = "QueryVectorDB"
    logger.info(f"Starting {tool_name} for query: '{query}' in collection '{collection}'")
    try:
        num_res = int(n_results)
        if num_res <= 0: num_res = 5
    except ValueError:
        num_res = 5
        logger.warning(f"[{tool_name}] Invalid n_results '{n_results}', defaulting to 5.")
    try:
        results = await queryDB(query_texts=[query], n_results=num_res, collection_name=collection)
        if results is None:
            logger.error(f"[{tool_name}] queryDB returned None for collection '{collection}'")
            return {"error": f"Failed to query collection '{collection}' or no results."}
        logger.info(f"Completed {tool_name}, found {len(results.get('ids', []))} results")
        return {"results": results}
    except Exception as error:
        logger.error(f"Error in {tool_name}: {error}")
        return {"error": str(error)}

@mcpServer.tool()
async def ProcessAndIngestDocumentation(documentation_text: str, library_name: str, language: str, source_url: str): # Remains the same
    """
    Chunks and ingests documentation. Assumes chunk_and_ingest is async.

    Args:
        documentation_text: Text from the documentation source.
        library_name: Name of the library for whom the documentation is for.
        language: Computer language for whom the documentation is for
        source_url: URL for the web page from where the information was retreieved.

    Returns:
        A dictionary indicating success status and document ID, or an error dictionary.
    """
    tool_name = "ProcessAndIngestDocumentation"
    logger.info(f"Starting {tool_name} for library: {library_name}")
    if not documentation_text:
        logger.warning(f"[{tool_name}] No documentation text provided for {library_name}")
        return {"error": "No documentation text provided"}
    metadata = f"Library: {library_name}, Language: {language}, Source: {source_url}"
    try:
        result = await chunk_and_ingest(full_text=documentation_text, source_metadata=metadata)
        if 'error' in result:
            logger.error(f"[{tool_name}] Failed for {library_name}: {result.get('error')}")
            return result
        logger.info(f"Completed {tool_name} for {library_name}. Chunks: {len(result.get('chunk_ids', []))}")
        return result
    except Exception as e:
        logger.error(f"Unexpected error in {tool_name} for {library_name}: {e}")
        return {"error": f"Unexpected error: {str(e)}"}

@mcpServer.tool()
async def QueryReconData(target: str, max_results: int = 5):
    """
    Query the reconnaissance database for data related to a specific target.
    Now includes db_document_id in the results.
    
    Args:
        target: The target domain or IP to query for.
        max_results: Maximum number of results to return.
    
    Returns:
        List of dictionaries containing the reconnaissance data for the target.
    """
    tool_name = "QueryReconData"
    logger.info(f"Querying recon data for target: {target} (max_results: {max_results})")
    query_text = f"{target}"
    try:
        num_res = int(max_results)
        if num_res <= 0: num_res = 5
    except ValueError:
        num_res = 5
        logger.warning(f"[{tool_name}] Invalid max_results '{max_results}', defaulting to 5.")
    
    # queryDB now returns 'ids' (UUIDs) and 'metadatas' which includes 'db_document_id'
    results = await queryDB(query_texts=[query_text], n_results=num_res, collection_name=RECON_COLLECTION_NAME)
    
    output_results = []
    if results and results.get('documents') and results.get('metadatas') and results.get('ids'):
        retrieved_docs_data = results['documents'] # List of lists, each inner list has one dict
        retrieved_metadatas = results['metadatas'] # List of lists, each inner list has one dict
        retrieved_ids = results['ids'] # List of UUIDs

        min_len = min(len(retrieved_docs_data), len(retrieved_metadatas), len(retrieved_ids))

        for i in range(min_len):
            # Data is already the structured_data dict or fallback string
            actual_data = retrieved_docs_data[i][0] if retrieved_docs_data[i] else {} 
            # Metadata is the dict containing source, timestamp, and db_document_id
            actual_meta = retrieved_metadatas[i][0] if retrieved_metadatas[i] else {}
            db_doc_id_from_meta = actual_meta.get("db_document_id", retrieved_ids[i]) # Prefer from meta, fallback to main ID

            data_target_field = None
            if isinstance(actual_data, dict):
                 data_target_field = actual_data.get("target", actual_data.get("summary", {}).get("target_url"))
            
            source_contains_target = target.lower() in actual_meta.get("source", "").lower()
            
            if (data_target_field and target.lower() == str(data_target_field).lower()) or source_contains_target:
                output_results.append({
                    "db_document_id": db_doc_id_from_meta, # Phase 1.3: Include DB ID
                    "data": actual_data, 
                    "source": actual_meta.get("source", "unknown"), 
                    "timestamp": actual_meta.get("ingest_timestamp", "unknown")
                })
        
        logger.info(f"[{tool_name}] Found and filtered {len(output_results)} results for target '{target}' in '{RECON_COLLECTION_NAME}'.")
        return output_results
    else:
        logger.info(f"[{tool_name}] No results found for target '{target}' in '{RECON_COLLECTION_NAME}'.")
        return []

@mcpServer.tool()
async def FetchDomainDataForReport(target_domain: str) -> Dict[str, Any]:
    """
    Accepts a target domain name and fetches manifest for the database entries for information related to the domain.
    Each section in the manifest includes a db_document_id to fetch its raw data.

    Args:
        target_domain: The primary domain to fetch data for.

    Returns:
        A dictionary containing the target_domain, retrieval_timestamp, and a
        report_structure_manifest list.
    """
    tool_name = "FetchDomainDataForReport"
    request_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
    logger.info(f"[{tool_name}-{request_id}] Initiating data manifest fetch for report on {target_domain}")

    report_structure_manifest = []
    retrieval_ts = datetime.utcnow().isoformat() + "Z"
    
    max_db_results_fetch = 200 
    all_domain_related_data = await QueryReconData(target=target_domain, max_results=max_db_results_fetch)
    
    if not all_domain_related_data:
        logger.warning(f"[{tool_name}-{request_id}] No data found in DB for target '{target_domain}'. Report manifest will be empty.")
        return {
            "target_domain": target_domain,
            "retrieval_timestamp": retrieval_ts,
            "report_structure_manifest": [],
            "message": f"No reconnaissance data found in the database for {target_domain}."
        }

    logger.info(f"[{tool_name}-{request_id}] Retrieved {len(all_domain_related_data)} initial records for '{target_domain}'. Processing into manifest...")

    # Temporary storage to avoid duplicate manifest entries for the same raw data blob
    processed_db_doc_ids = set()

    for record in all_domain_related_data:
        raw_data = record.get("data", {})
        source_str = record.get("source", "") 
        db_doc_id = record.get("db_document_id")

        if not db_doc_id or db_doc_id in processed_db_doc_ids:
            continue # Skip if no DB ID or already processed this raw data blob
        
        processed_db_doc_ids.add(db_doc_id)

        if not isinstance(raw_data, dict): continue

        data_type_hint = "UnknownData"
        title_hint_suffix = "Data"
        specific_target_in_data = raw_data.get("target") 

        if "records" in raw_data and isinstance(raw_data.get("records"), dict) and "dns_records" in raw_data["records"]:
            data_type_hint = "DnsEnumResult"
            title_hint_suffix = f"DNS Enumeration for {specific_target_in_data or target_domain}"
        elif "subdomains" in raw_data and "count" in raw_data:
            data_type_hint = "SubDomainEnumResult"
            title_hint_suffix = f"Subdomain Enumeration for {specific_target_in_data or target_domain}"
        elif "port_details" in raw_data and "ip_address" in raw_data:
            data_type_hint = "PortScanResult"
            title_hint_suffix = f"Port Scan for {specific_target_in_data or target_domain}"
        elif "summary" in raw_data and "scanned_pages_details" in raw_data:
            data_type_hint = "SiteMapAndAnalyzeResult"
            specific_target_in_data = raw_data.get("summary", {}).get("target_url", target_domain)
            title_hint_suffix = f"Web Application Analysis for {specific_target_in_data}"
        
        # Estimate data size
        estimated_size = 0
        try:
            if isinstance(raw_data, (dict,list)):
                estimated_size = len(json.dumps(raw_data)) # Byte size
            elif isinstance(raw_data, str):
                estimated_size = len(raw_data)
        except:
            estimated_size = 0 # Fallback

        section_id_target_part = str(specific_target_in_data or target_domain).replace('.', '_').replace('://','_').replace('/','')
        
        report_structure_manifest.append({
            "section_id": f"{data_type_hint.lower()}_{section_id_target_part}_{db_doc_id[:8]}", # Make section_id more unique
            "section_type": data_type_hint,
            "title_hint": title_hint_suffix,
            "db_document_id": db_doc_id, # Crucial for fetching later
            "estimated_data_size_indicator": {"bytes": estimated_size}
        })
                
    logger.info(f"[{tool_name}-{request_id}] Processed data. Created manifest with {len(report_structure_manifest)} sections for {target_domain}.")
    return {
        "target_domain": target_domain,
        "retrieval_timestamp": retrieval_ts,
        "report_structure_manifest": report_structure_manifest
    }

@mcpServer.tool()
async def CreatePDFReportWithSummaries(report_title: str, sections_with_summaries: List[Dict[str, Any]]) -> Dict[str, Any]: # Remains the same
    """
    Generates a PDF report from a list of pre-summarized sections.
    Each section should contain a title and the summary text generated by an LLM.
    Optionally, a raw data snippet can be included for context in the PDF.

    Args:
        report_title (str): The main title for the PDF report.
        sections_with_summaries (List[Dict[str, Any]]): A list of dictionaries.
            Each dictionary represents a section and should contain:
            - "section_title" (str): The title for this section.
            - "summary_text" (str): The LLM-generated summary for this section.
            - "raw_data_snippet" (Dict[str, Any] | List[Any] | str, optional):
              A small snippet of the raw data related to this section, for context.
              This will be pretty-printed if it's a dict/list.

    Returns:
        Dict[str, Any]: A dictionary containing:
        - "pdf_base64" (str): The base64 encoded string of the generated PDF.
        - "error" (str, optional): An error message if PDF generation failed.
    """
    tool_name = "CreatePDFReportWithSummaries"
    request_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
    logger.info(f"[{tool_name}-{request_id}] Received request to generate PDF: '{report_title}' with {len(sections_with_summaries)} sections.")

    if not isinstance(sections_with_summaries, list):
        logger.error(f"[{tool_name}-{request_id}] 'sections_with_summaries' must be a list.")
        return {"error": "'sections_with_summaries' must be a list."}

    generation_ts = datetime.utcnow().isoformat() + "Z"
    
    try:
        pdf_base64_string = await asyncio.to_thread(
            generate_pdf_from_summarized_sections,
            report_title,
            list(sections_with_summaries), # <--- MODIFIED HERE
            generation_ts
        )
        if not pdf_base64_string or "Critical Error during PDF generation" in base64.b64decode(pdf_base64_string[:400].encode()).decode('utf-8', 'ignore'):
            logger.error(f"[{tool_name}-{request_id}] PDF generation function returned an error or empty string for '{report_title}'.")
            return {"error": "PDF generation failed. The PDF content indicates an error or is empty."}
        
        logger.info(f"[{tool_name}-{request_id}] PDF generated successfully for '{report_title}'.")
        return {"pdf_base64": pdf_base64_string}
    except Exception as e:
        logger.error(f"[{tool_name}-{request_id}] Unexpected error during PDF generation for '{report_title}': {e}", exc_info=True)
        return {"error": f"Unexpected error during PDF creation: {str(e)}"}

@mcpServer.tool()
async def RetrievePaginatedDataSection(
    db_document_id: str,
    page_number: int = 1,  # FastAPI will try to convert query param to int
    page_size: int = 500   # FastAPI will try to convert query param to int
) -> Dict[str, Any]:
    """
    Retrieves a specific "page" of raw data for a given document ID from the database.
    Pagination is based on lines for text or top-level items for structured data.

    Args:
        db_document_id: The unique ID of the document in the FAISS database.
        page_number: The page number to retrieve (1-indexed). FastAPI handles initial conversion.
        page_size: The number of lines/items per page. FastAPI handles initial conversion.

    Returns:
        A dictionary containing:
        - 'db_document_id': The ID of the document.
        - 'page_number': The current page number.
        - 'total_pages': The total number of pages for this document.
        - 'data_page_content': The content of the current page (string or list/dict).
        - 'is_final_page': Boolean indicating if this is the last page.
        - 'error': Optional error message.
    """
    tool_name = "RetrievePaginatedDataSection"
    
    # Use validated/converted parameters directly; FastAPI/Pydantic handles type hints.
    # Add explicit validation for sensible values.
    current_page_number = page_number
    current_page_size = page_size

    if not isinstance(current_page_number, int) or current_page_number < 1:
        logger.warning(f"[{tool_name}] Invalid page_number '{page_number}', defaulting to 1.")
        current_page_number = 1
    if not isinstance(current_page_size, int) or current_page_size < 1:
        logger.warning(f"[{tool_name}] Invalid page_size '{page_size}', defaulting to 500.")
        current_page_size = 500
    
    logger.info(f"[{tool_name}] Request for doc_id: {db_document_id}, page: {current_page_number}, size: {current_page_size}")

    vector_store = get_faiss_client(RECON_COLLECTION_NAME) 
    if not vector_store:
        logger.error(f"[{tool_name}] Failed to get FAISS client for {RECON_COLLECTION_NAME}")
        return {"error": f"Failed to get FAISS client for {RECON_COLLECTION_NAME}", "db_document_id": db_document_id, "page_number": current_page_number, "data_page_content": None, "is_final_page": True, "total_pages":0}

    raw_data = vector_store.get_document_by_id(db_document_id)

    if raw_data is None:
        logger.warning(f"[{tool_name}] Document with ID '{db_document_id}' not found.")
        return {"error": f"Document with ID '{db_document_id}' not found.", "db_document_id": db_document_id, "page_number": current_page_number, "data_page_content": None, "is_final_page": True, "total_pages":0}

    data_page_content = None
    total_pages = 0
    is_final_page = True
    total_items = 0

    try:
        content_to_paginate_iterable: Optional[List[Any]] = None
        is_structured_list_pagination = False

        if isinstance(raw_data, list):
            content_to_paginate_iterable = raw_data
            is_structured_list_pagination = True
            total_items = len(raw_data)
        elif isinstance(raw_data, dict):
            content_to_paginate_iterable = json.dumps(raw_data, indent=2).splitlines()
            total_items = len(content_to_paginate_iterable)
        elif isinstance(raw_data, str):
            content_to_paginate_iterable = raw_data.splitlines()
            total_items = len(content_to_paginate_iterable)
        else:
            logger.error(f"[{tool_name}] Unsupported data type for pagination: {type(raw_data)} for doc_id {db_document_id}")
            return {"error": f"Unsupported data type for pagination: {type(raw_data)}", "db_document_id": db_document_id, "page_number": current_page_number, "data_page_content": None, "is_final_page": True, "total_pages":0}
        
        if total_items == 0:
            total_pages = 1
        else:
            # Ensure current_page_size is used here
            total_pages = (total_items + current_page_size - 1) // current_page_size 
        
        # Ensure current_page_number and current_page_size are used for indexing
        start_index = (current_page_number - 1) * current_page_size
        end_index = start_index + current_page_size
        
        is_final_page = (current_page_number >= total_pages)

        if start_index >= total_items :
            data_page_content = [] if is_structured_list_pagination else ""
        elif content_to_paginate_iterable is not None:
            paginated_slice = content_to_paginate_iterable[start_index:end_index]
            data_page_content = paginated_slice if is_structured_list_pagination else "\n".join(paginated_slice)
        else:
             data_page_content = [] if is_structured_list_pagination else ""

        page_content_len_indicator = 0
        if isinstance(data_page_content, list):
            page_content_len_indicator = len(data_page_content)
        elif isinstance(data_page_content, str):
            page_content_len_indicator = len(data_page_content.splitlines())


        logger.info(f"[{tool_name}] Doc {db_document_id}: Page {current_page_number}/{total_pages}. Final: {is_final_page}. Items on page: {page_content_len_indicator}")
        return {
            "db_document_id": db_document_id,
            "page_number": current_page_number,
            "total_pages": total_pages,
            "data_page_content": data_page_content,
            "is_final_page": is_final_page
        }

    except Exception as e:
        logger.error(f"[{tool_name}] Error during pagination for doc_id {db_document_id}, page {current_page_number}: {e}", exc_info=True)
        return {"error": f"Pagination error: {str(e)}", "db_document_id": db_document_id, "page_number": current_page_number, "data_page_content": None, "is_final_page": True, "total_pages":0}


# --- Streaming Tools Registration (remains the same) ---
@mcpServer.tool()
async def PortScanner(domain: str, startPort: int = 1, endPort: int = 10000, timeOut: float = 5.0, scan_type: str = 'tcp', storeResults: bool = False) -> AsyncGenerator[Dict[str, Any], None]: # Remains the same
    """
    Performs a port scan on the specified domain or IP address using Nmap.
    Streams progress updates and a final detailed report of open ports, services,
    and potentially OS information.

    Args:
        domain (str): The domain name or IP address to scan.
        startPort (int, optional): The starting port number for the scan. Defaults to 1.
        endPort (int, optional): The ending port number for the scan. Defaults to 10000.
        timeOut (float, optional): Timeout for individual Nmap probes in seconds. Defaults to 5.0.
        scan_type (str, optional): Type of Nmap scan to perform ('tcp', 'syn', 'udp'). Defaults to 'tcp'.
                                   'syn' scan requires root privileges.
        storeResults (bool, optional): If True, the final scan results will be stored
                                       in the reconnaissance database. Defaults to False.

    Yields:
        Dict[str, Any]: Dictionaries representing progress updates (e.g., scan start,
                        completion messages) and a final result. The final result is
                        marked with "__final_result__": True and contains a 'data' key
                        with a PortScanResult object detailing all findings.
    """
    logger.info(f"Executing PortScanner (streaming wrapper) for {domain} with timeout {timeOut}")
    stealth_mode = True
    ports =  list(range(int(startPort), int(endPort)))
    os_detection_enabled = True
    service_fingerprinting_enabled = True
    script_engine_enabled = False 
    async for item in portScanner4LLM(
        domain=domain,
        ports=ports,
        scan_type=scan_type,
        os_detection_enabled=os_detection_enabled,
        service_fingerprinting_enabled=service_fingerprinting_enabled,
        script_engine_enabled=script_engine_enabled,
        scan_timeout=timeOut,
        stealth_mode=stealth_mode
        ):
        yield item

@mcpServer.tool()
async def SubDomainEnumerator(domain: str, brute_force_tier: str = "small", storeResults: bool = False) -> AsyncGenerator[Dict[str, Any], None]: # Remains the same
    """
    Enumerates subdomains for a given domain using multiple techniques including
    brute-force, web search (SearXNG), crt.sh, and DNS record analysis.
    Streams progress updates from each method and a final consolidated list of subdomains.

    Args:
        domain (str): The target domain for subdomain enumeration.
        brute_force_tier (str, optional): The tier for brute-force wordlist size.
                                          Options: "small", "medium", "large", "all".
                                          Defaults to "small".
        storeResults (bool, optional): If True, the final list of subdomains will be
                                       stored in the reconnaissance database. Defaults to False.

    Yields:
        Dict[str, Any]: Dictionaries representing progress updates (e.g., method start,
                        subdomains found by a specific method) and a final result.
                        The final result is marked with "__final_result__": True and
                        contains a 'data' key with a SubDomainEnumResult object,
                        including the list of found subdomains and their count.
    """
    logger.info(f"Executing SubDomainEnumerator (streaming wrapper) for {domain} with brute_force_tier='{brute_force_tier}'")
    async for item in subDomainMapper4LLM(domain=domain, brute_force_tier=brute_force_tier):
        yield item

@mcpServer.tool()
async def DnsEnumerator(domain: str, storeResults: bool = False) -> AsyncGenerator[Dict[str, Any], None]: # Remains the same
    """
    Performs detailed DNS enumeration for the specified domain. This includes
    resolving common record types (A, AAAA, MX, NS, TXT, SOA, CNAME), handling
    CNAME chains, attempting DNS zone transfers, and analyzing SPF/DMARC records.
    Streams progress updates and a final comprehensive DNS report.

    Args:
        domain (str): The target domain for DNS enumeration.
        storeResults (bool, optional): If True, the final DNS enumeration results
                                       will be stored in the reconnaissance database.
                                       Defaults to False.

    Yields:
        Dict[str, Any]: Dictionaries representing progress updates (e.g., record type
                        being processed, zone transfer attempts) and a final result.
                        The final result is marked with "__final_result__": True and
                        contains a 'data' key with a DnsEnumResult object, detailing
                        all DNS records and analysis.
    """
    logger.info(f"[WRAPPER] Executing DnsEnumerator streaming wrapper for {domain}.")
    async for item in AddressFinderForLLM(domain=domain):
        yield item

# In main.py
@mcpServer.tool()
async def SiteMapAndAnalyze(
    start_url: str,
    max_depth: int = 1,
    active_scanning_enabled: bool = False,
    oob_listener_domain: Optional[str] = None,
    log_level: str = "INFO", 
    storeResults: bool = False 
) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Performs comprehensive site mapping and vulnerability analysis (passive and active)
    on a target website. Streams progress updates and a final detailed report.
    Args:
        start_url: The starting URL for the site map (e.g., "http://example.com").
                   If scheme is missing, https:// will be assumed.
        max_depth: Maximum depth to crawl from the start_url (default 1).
        # ... other args ...
    Yields:
        Progress updates and a final result dictionary from the site mapping and analysis process.
    """
    
    parsed_url = urlparse(start_url)
    if not parsed_url.scheme:
        logger.warning(f"[SiteMapAndAnalyze Wrapper] Start URL '{start_url}' is missing a scheme. Assuming 'https://'.")
        start_url = f"https://{start_url}"
    elif parsed_url.scheme not in ['http', 'https']:
        logger.error(f"[SiteMapAndAnalyze Wrapper] Start URL '{start_url}' has an invalid scheme '{parsed_url.scheme}'. Aborting.")
        # Yield a final error result immediately
        yield {
            "__final_result__": True,
            "data": {
                "status": "failed",
                "error": f"Invalid scheme in start_url: '{parsed_url.scheme}'. Must be 'http' or 'https'",
                "summary": { # Mimic structure for consistent error handling downstream
                    "target_url": start_url,
                    "status_message": f"ABORTED: Invalid scheme '{parsed_url.scheme}'",
                    "total_pages_processed_with_details": 0,
                    "errors": [f"Invalid scheme in start_url: '{parsed_url.scheme}'"]
                }
            }
        }
        return # Stop further execution

    logger.info(f"Executing SiteMapAndAnalyze (streaming wrapper) for {start_url} with active_scan={active_scanning_enabled}")

    num_threads_per_scan = 2 
    headless = True
    min_request_delay_seconds: float = 1.0
    max_request_delay_seconds: float = 3.0
    active_scan_timeout = 10.0
    
    async for item in actual_site_mapper_analyzer( # actual_site_mapper_analyzer is ReconTools.Crawler.crawl_and_analyze_site_tool
        start_url=start_url, # Pass the potentially corrected start_url
        max_depth=max_depth,
        num_threads_per_scan=num_threads_per_scan,
        headless=headless,
        min_request_delay_seconds=min_request_delay_seconds,
        max_request_delay_seconds=max_request_delay_seconds,
        active_scanning_enabled=active_scanning_enabled,
        active_scan_timeout=active_scan_timeout,
        oob_listener_domain=oob_listener_domain,
        log_level=log_level
    ):
        yield item

PortScanner._is_streaming_tool = True # type: ignore
DnsEnumerator._is_streaming_tool = True # type: ignore
SubDomainEnumerator._is_streaming_tool = True # type: ignore
SiteMapAndAnalyze._is_streaming_tool = True # type: ignore


# SSE Endpoints for Prompts and Tools List (remains the same)
@app.get("/mcp/prompts/summary")
async def listToolCallSummaryPrompts():
    prompt = await tool_call_result_summary_prompt()
    async def eventGenerator():
        if prompt:
            yield {"event": "prompt", "data": json.dumps({"prompt": prompt})}
        else:
            yield {"event": "error", "data": json.dumps({"error": "No Summary Prompts available"})}
    return EventSourceResponse(eventGenerator())

@app.get("/mcp/prompts")
async def listServerPrompts():
    prompt = await web_vulnerability_prompt()
    async def eventGenerator():
        if prompt:
            yield {"event": "prompt", "data": json.dumps({"prompt": prompt})}
        else:
            yield {"event": "error", "data": json.dumps({"error": "No Server Prompts available"})}
    return EventSourceResponse(eventGenerator())

@app.get("/mcp/tools")
async def listServerTools():
    async def eventGenerator():
        request_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
        logger.info(f"[SSE-{request_id}] Listing tools")
        try:
            tools_dict = mcpServer._tool_manager._tools
            tool_schemas = []
            for name, tool_def in tools_dict.items():
                params_schema = getattr(tool_def, 'parameters', getattr(tool_def, 'schema', {}))
                if validate_schema(params_schema):
                    tool_schemas.append({
                        "name": name,
                        "description": getattr(tool_def, 'description', f"Tool named {name}"),
                        "parameters": params_schema
                    })
                else:
                    logger.warning(f"Tool '{name}' has invalid schema, excluding from list. Schema: {params_schema}")
            
            logger.info(f"[SSE-{request_id}] Prepared {len(tool_schemas)} tools with valid schemas.")
            yield {"event": "tools_list", "data": json.dumps({"available_tools": tool_schemas})}
        except Exception as e:
            logger.exception(f"[SSE-{request_id}] Error listing tools: {e}")
            yield {"event": "error", "data": json.dumps({"error": f"Failed to list tools: {str(e)}"})}
    return EventSourceResponse(eventGenerator())


# Tool Execution Endpoint (remains largely the same, streaming logic is preserved)
@app.get("/mcp/tools/{tool_name}")
async def callMCPTool(request: Request, tool_name: str):
    request_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
    logger.info(f"[SSE-Tool-{request_id}] Request received for tool '{tool_name}'")

    tool_object = mcpServer._tool_manager._tools.get(tool_name)

    if tool_object is None:
        logger.error(f"[SSE-Tool-{request_id}] Tool '{tool_name}' not found in manager.")
        async def error_gen_not_found():
            error_data = {
                "tool_name": tool_name,
                "timestamp_completion": datetime.utcnow().isoformat() + "Z",
                "status": "failed",
                "error_payload": {
                    "message": f"Tool '{tool_name}' not found or invalid.",
                    "type": "ToolNotFoundError"
                }
            }
            yield {"event": "tool_result", "data": json.dumps(error_data)}
        return EventSourceResponse(error_gen_not_found(), status_code=404)

    params = {}
    if "arguments" in request.query_params:
        raw_args = request.query_params["arguments"]
        try:
            params = json.loads(raw_args)
            logger.info(f"[SSE-Tool-{request_id}] Parsed arguments for '{tool_name}': {params}")
        except json.JSONDecodeError as error:
            logger.error(f"[SSE-Tool-{request_id}] Invalid JSON in arguments for tool '{tool_name}': {error}. Raw args: {raw_args}")
            async def error_gen_bad_args():
                error_data = {
                    "tool_name": tool_name,
                    "timestamp_completion": datetime.utcnow().isoformat() + "Z",
                    "status": "failed",
                    "error_payload": {
                        "message": f"Invalid JSON arguments provided: {error}",
                        "type": "ArgumentError"
                    }
                }
                yield {"event": "tool_result", "data": json.dumps(error_data)}
            return EventSourceResponse(error_gen_bad_args(), status_code=400)
    else:
        params = dict(request.query_params)
        for key, value in params.items():
            if isinstance(value, str): 
                if value.lower() == 'true': params[key] = True
                elif value.lower() == 'false': params[key] = False
                else:
                    try: params[key] = int(value)
                    except ValueError:
                        try: params[key] = float(value)
                        except ValueError: pass 
        logger.warning(f"[SSE-Tool-{request_id}] No 'arguments' query parameter found, using direct query params for '{tool_name}': {params}")
    
    async def event_generator():
        nonlocal tool_object, params 
        tool_fn = tool_object.fn
        is_streaming_tool = hasattr(tool_fn, '_is_streaming_tool') and tool_fn._is_streaming_tool
        
        yield {
            "event": "tool_progress",
            "data": json.dumps({
                "tool_name": tool_name,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "status_message": "Tool execution request accepted and initiated.",
                "details": {"args": params}
            })
        }

        final_tool_outcome_payload = None 
        tool_status_for_final_event = "completed" 
        
        collected_page_details = [] # Specific to SiteMapAndAnalyze
        collected_bad_urls = []     # Specific to SiteMapAndAnalyze
        collected_active_scan_alerts = [] # Specific to SiteMapAndAnalyze
        collected_summary_data = {} # Specific to SiteMapAndAnalyze

        try:
            logger.info(f"[SSE-Tool-{request_id}] Calling tool function for '{tool_name}' with params: {params}")
            
            if is_streaming_tool:
                logger.info(f"[SSE-Tool-{request_id}] Tool '{tool_name}' is a streaming tool. Awaiting intermediate results.")
                tool_stream_iterator = tool_fn(**params)
                
                async for item_from_tool in tool_stream_iterator:
                    item_type = item_from_tool.get("type") 
                    event_name_from_tool = item_from_tool.get("event") 

                    if item_from_tool.get("__final_result__", False):
                        final_tool_outcome_payload = item_from_tool.get("data", {})
                        if tool_name == "SiteMapAndAnalyze": # Consolidate SiteMapAndAnalyze specific data
                            collected_summary_data = final_tool_outcome_payload.get("summary", {})
                            collected_page_details.extend(final_tool_outcome_payload.get("scanned_pages_details", []))
                            collected_bad_urls.extend(final_tool_outcome_payload.get("unreachable_or_error_urls_summary", []))
                            collected_active_scan_alerts.extend(final_tool_outcome_payload.get("active_scan_vulnerabilities_found", []))
                        
                        if "error" in final_tool_outcome_payload or \
                           (isinstance(final_tool_outcome_payload.get("summary"), dict) and \
                            "ABORTED" in final_tool_outcome_payload["summary"].get("status_message", "").upper()):
                            tool_status_for_final_event = "failed"
                        
                        logger.info(f"[SSE-Tool-{request_id}] Received __final_result__ marker from streaming tool '{tool_name}'. Auto-determined status: {tool_status_for_final_event}.")
                        break 

                    progress_data_to_yield = {
                        "tool_name": tool_name,
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "status_message": f"Tool '{tool_name}' progress update.",
                        "details": item_from_tool 
                    }
                    
                    # SiteMapAndAnalyze specific progress handling (remains)
                    if tool_name == "SiteMapAndAnalyze":
                        if item_type == "page_processing":
                            progress_data_to_yield["status_message"] = f"Processing page: {item_from_tool.get('url')}"
                        elif item_type == "page_result":
                            page_info = item_from_tool.get("page_info")
                            if page_info: collected_page_details.append(page_info)
                            progress_data_to_yield["status_message"] = f"Finished page {page_info.get('url', 'N/A') if page_info else 'N/A'}"
                        elif item_type == "active_scan_alert":
                            alert_data = item_from_tool.get("alert")
                            if alert_data: collected_active_scan_alerts.append(alert_data)
                            progress_data_to_yield["status_message"] = f"Active Vulnerability Found: {alert_data.get('type', 'N/A') if alert_data else 'N/A'}"
                        elif item_type == "process_started":
                            progress_data_to_yield["status_message"] = item_from_tool.get('message', 'Crawler process started.')
                        elif item_type == "critical_failure" or item_type == "worker_critical_error":
                            tool_status_for_final_event = "failed" 
                            progress_data_to_yield["status_message"] = f"Critical Error: {item_from_tool.get('message', 'Unknown critical error')}"
                    elif event_name_from_tool:
                         progress_data_to_yield["status_message"] = f"Tool '{tool_name}' event: {event_name_from_tool}"

                    yield {"event": "tool_progress", "data": json.dumps(progress_data_to_yield)}
                    await asyncio.sleep(0.01)

                if final_tool_outcome_payload is None and tool_status_for_final_event == "completed": 
                    tool_status_for_final_event = "failed" 
                    final_tool_outcome_payload = { 
                        "message": f"Streaming tool '{tool_name}' finished without providing an explicit final result.",
                        "type": "IncompleteToolOutput"
                    }
                    logger.warning(f"[SSE-Tool-{request_id}] Streaming tool '{tool_name}' finished without __final_result__ marker.")
            else: 
                logger.info(f"[SSE-Tool-{request_id}] Tool '{tool_name}' is a regular (non-streaming) tool. Awaiting single final result.")
                final_tool_outcome_payload = await tool_fn(**params)
                logger.info(f"[SSE-Tool-{request_id}] Non-streaming tool '{tool_name}' function call completed.")
                if isinstance(final_tool_outcome_payload, dict) and "error" in final_tool_outcome_payload:
                    tool_status_for_final_event = "failed"

        except Exception as e_exec:
            logger.error(f"[SSE-Tool-{request_id}] Error during execution of tool '{tool_name}': {e_exec}", exc_info=True)
            tool_status_for_final_event = "failed"
            final_tool_outcome_payload = { 
                "message": f"Error during tool '{tool_name}' execution: {str(e_exec)}",
                "type": type(e_exec).__name__,
                "details": {"args_used": params}
            }

        final_event_data = {
            "tool_name": tool_name,
            "timestamp_completion": datetime.utcnow().isoformat() + "Z",
            "status": tool_status_for_final_event
        }

        if tool_status_for_final_event == "completed":
            if is_streaming_tool: # This logic is for tools that ARE streaming, like SiteMapAndAnalyze
                if tool_name == "SiteMapAndAnalyze":
                    final_event_data["result_payload"] = {
                        "summary": collected_summary_data if collected_summary_data else final_tool_outcome_payload.get("summary",{}),
                        "scanned_pages_details": collected_page_details,
                        "unreachable_or_error_urls_summary": collected_bad_urls,
                        "active_scan_vulnerabilities_found": collected_active_scan_alerts
                    }
                else: # Other streaming tools
                    final_event_data["result_payload"] = final_tool_outcome_payload
            else: # Non-streaming tools (like the new RetrievePaginatedDataSection, FetchDomainDataForReport)
                 final_event_data["result_payload"] = final_tool_outcome_payload
            final_event_data["error_payload"] = None
        else: 
            final_event_data["result_payload"] = None
            final_event_data["error_payload"] = final_tool_outcome_payload 
        
        should_store_results = str(params.get('storeResults', 'false')).lower() == 'true'
        data_for_storage = final_event_data.get("result_payload")

        # Storage logic remains, but note that RetrievePaginatedDataSection and FetchDomainDataForReport
        # are unlikely to have storeResults=True directly called by LLM.
        # Storage happens when the original data-generating tools (PortScanner, etc.) are called.
        if should_store_results and tool_status_for_final_event == "completed" and isinstance(data_for_storage, dict) and data_for_storage:
            target_for_storage = "unknown_target"
            if tool_name == "SiteMapAndAnalyze":
                target_for_storage = data_for_storage.get("summary", {}).get("target_url", params.get('start_url', 'unknown_target'))
            elif tool_name in ["FetchDomainDataForReport", "CreatePDFReportWithSummaries", "RetrievePaginatedDataSection"]:
                 # These tools don't typically generate primary data for storage themselves.
                 # FetchDomainDataForReport gets a manifest. RetrievePaginatedDataSection gets a page.
                 # CreatePDFReportWithSummaries generates a PDF from summaries.
                 # If storeResults was True for these, it might be a misconfiguration or specific intent.
                 target_for_storage = params.get('target_domain', 
                                        params.get('report_title', 
                                        params.get('db_document_id', 'unknown_report_target')))
            else: 
                target_for_storage = data_for_storage.get('target', params.get('domain', 'unknown_target'))

            source_info_str = f"Tool: {tool_name}, Target/ID: {target_for_storage}"
            logger.info(f"[SSE-Tool-{request_id}] Attempting to store results for '{tool_name}' on target/ID '{target_for_storage}'.")
            
            storage_op_result = await _store_recon_results_internal(
                results_json=data_for_storage.copy(), 
                source_info=source_info_str,
                tool_name_for_log=tool_name
            )
            final_event_data['storage_info'] = {
                "doc_id": storage_op_result.get('id'),
                "message": storage_op_result.get('message'),
                "status": storage_op_result.get('status', 'error')
            }
            if storage_op_result.get('status') == 'success':
                logger.info(f"[SSE-Tool-{request_id}] Successfully stored results for '{tool_name}', doc_id: {storage_op_result.get('id')}")
            else:
                logger.error(f"[SSE-Tool-{request_id}] Failed to store results for '{tool_name}': {storage_op_result.get('error', 'Unknown storage error')}")
        elif should_store_results:
             logger.warning(f"[SSE-Tool-{request_id}] Storage requested for '{tool_name}', but status is '{tool_status_for_final_event}' or no data. Skipping storage.")

        yield {"event": "tool_result", "data": json.dumps(final_event_data)}
        logger.info(f"[SSE-Tool-{request_id}] Sent final tool_result for '{tool_name}' with status: {tool_status_for_final_event}.")

        if is_streaming_tool and 'tool_stream_iterator' in locals() and tool_stream_iterator is not None:
            try:
                await tool_stream_iterator.aclose()
                logger.info(f"[SSE-Tool-{request_id}] Successfully aclosed the tool's async generator for '{tool_name}'.")
            except Exception as e_aclose:
                logger.error(f"[SSE-Tool-{request_id}] Error during aclose() of tool's async generator for '{tool_name}': {e_aclose}", exc_info=True)
        
        logger.info(f"[SSE-Tool-{request_id}] Event generator for '{tool_name}' is closing.")

    return EventSourceResponse(event_generator())

def main(): # Remains the same
    print("Starting MCP SSE Server...")
    server_host = os.getenv("MCP_SERVER_HOST", "0.0.0.0")
    try:
        server_port = int(os.getenv("MCP_SERVER_PORT", 8000))
    except ValueError:
        print("Warning: Invalid MCP_SERVER_PORT in .env, defaulting to 8000.")
        server_port = 8000
    
    try:
        num_workers = int(os.getenv("MCP_SERVER_WORKERS", 4))
        if num_workers <=0: num_workers = 4
    except ValueError:
        print("Warning: Invalid MCP_SERVER_WORKERS in .env, defaulting to 1.")
        num_workers = 1
    
    logger.info(f"Server configured to run on {server_host}:{server_port} with {num_workers} workers.")
    
    from dotenv import load_dotenv
    load_dotenv()

    uvicorn.run(
        "Rizzler:app", 
        host=server_host,
        port=server_port,
        log_config=None, 
        workers=num_workers
    )
    
    print("MCP SSE Server stopped.")

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv() 
    main()
# --- END OF FILE main.py ---