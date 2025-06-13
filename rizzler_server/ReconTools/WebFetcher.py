# --- START OF FILE ReconTools/WebFetcher.py ---

import asyncio
import logging
import os
import re
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import httpx
import markdownify
import readabilipy.simple_json
from protego import Protego

# Logging Configuration
logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logger.propagate = False

DEFAULT_USER_AGENT_AUTONOMOUS = "ModelContextProtocol/1.0 (Autonomous; +https://github.com/modelcontextprotocol/servers)"

def extract_content_from_html(html: str) -> str:
    """Extract and convert HTML content to Markdown format.

    Args:
        html: Raw HTML content to process

    Returns:
        Simplified markdown version of the content
    """
    try:
        ret = readabilipy.simple_json.simple_json_from_html_string(
            html, use_readability=True
        )
        if not ret["content"]:
            logger.warning("readabilipy failed to simplify HTML, returning error message.")
            return "<error>Page failed to be simplified from HTML</error>"
        content = markdownify.markdownify(
            ret["content"],
            heading_style=markdownify.ATX,
        )
        return content
    except Exception as e:
        logger.error(f"Error during HTML content extraction: {e}")
        return f"<error>Error processing HTML: {e}</error>"


def get_robots_txt_url(url: str) -> str:
    """Get the robots.txt URL for a given website URL.

    Args:
        url: Website URL to get robots.txt for

    Returns:
        URL of the robots.txt file
    """
    parsed = urlparse(url)
    robots_url = urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))
    return robots_url


async def check_may_autonomously_fetch_url(url: str, user_agent: str, proxy_url: str | None = None) -> Tuple[bool, Optional[str]]:
    """
    Check if the URL can be fetched by the user agent according to the robots.txt file.
    Returns (True, None) if allowed, or (False, error_message) if not.
    """
    robot_txt_url = get_robots_txt_url(url)
    logger.debug(f"Checking robots.txt for {url} at {robot_txt_url}")

    try:
        async with httpx.AsyncClient(proxies=proxy_url, timeout=10) as client:
            response = await client.get(
                robot_txt_url,
                follow_redirects=True,
                headers={"User-Agent": user_agent},
            )
    except httpx.HTTPError as e:
        error_msg = f"Failed to fetch robots.txt {robot_txt_url} due to a connection issue: {e}"
        logger.warning(error_msg)
        return True, None # Assume allowed if robots.txt cannot be fetched due to connection issues

    if response.status_code in (401, 403):
        error_msg = f"When fetching robots.txt ({robot_txt_url}), received status {response.status_code} so assuming that autonomous fetching is not allowed."
        logger.warning(error_msg)
        return False, error_msg
    elif 400 <= response.status_code < 500:
        logger.debug(f"robots.txt returned {response.status_code}, assuming no specific disallow rules apply.")
        return True, None # robots.txt not found or client error, usually means no restrictions

    robot_txt = response.text
    processed_robot_txt = "\n".join(
        line for line in robot_txt.splitlines() if not line.strip().startswith("#")
    )
    robot_parser = Protego.parse(processed_robot_txt)
    
    if not robot_parser.can_fetch(str(url), user_agent):
        error_msg = (
            f"The site's robots.txt ({robot_txt_url}) specifies that autonomous fetching of this page is not allowed "
            f"for user agent '{user_agent}'.\n"
            f"URL: {url}\n"
            f"Robots.txt content:\n{robot_txt}"
        )
        logger.warning(error_msg)
        return False, error_msg
    
    logger.debug(f"Robots.txt check passed for {url}")
    return True, None


async def fetch_url_content(
    url: str, user_agent: str, force_raw: bool = False, proxy_url: str | None = None
) -> Tuple[str, Optional[str]]:
    """
    Fetch the URL and return the content in a form ready for the LLM, as well as an error message if any.
    Returns (content, error_message).
    """
    logger.info(f"Attempting to fetch URL: {url} (raw: {force_raw})")
    try:
        async with httpx.AsyncClient(proxies=proxy_url, timeout=30) as client:
            response = await client.get(
                url,
                follow_redirects=True,
                headers={"User-Agent": user_agent},
            )
        response.raise_for_status() # Raise an exception for 4xx or 5xx responses

        page_raw = response.text
        content_type = response.headers.get("content-type", "")
        is_page_html = (
            "<html" in page_raw[:100].lower() or "text/html" in content_type.lower() or not content_type
        )

        if is_page_html and not force_raw:
            logger.debug(f"Extracting markdown content from HTML for {url}")
            return extract_content_from_html(page_raw), None
        
        logger.debug(f"Returning raw content for {url} (Content-Type: {content_type})")
        return page_raw, None

    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP error fetching {url}: Status {e.response.status_code} - {e.response.reason_phrase}"
        logger.error(error_msg)
        return "", error_msg
    except httpx.RequestError as e:
        error_msg = f"Network error fetching {url}: {e}"
        logger.error(error_msg)
        return "", error_msg
    except Exception as e:
        error_msg = f"An unexpected error occurred while fetching {url}: {e}"
        logger.error(error_msg, exc_info=True)
        return "", error_msg


async def fetch_web_page_content(
    url: str,
    force_raw: bool = False,
    user_agent: str = DEFAULT_USER_AGENT_AUTONOMOUS,
    ignore_robots_txt: bool = False,
    proxy_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Main function to fetch web page content, respecting robots.txt.
    Returns a dictionary with 'content' and 'error' keys.
    """
    logger.info(f"Calling fetch_web_page_content for {url}")

    if not ignore_robots_txt:
        can_fetch, robots_error = await check_may_autonomously_fetch_url(url, user_agent, proxy_url)
        if not can_fetch:
            logger.warning(f"Robots.txt disallowed fetching for {url}: {robots_error}")
            return {"content": "", "error": robots_error}

    content, fetch_error = await fetch_url_content(url, user_agent, force_raw, proxy_url)

    if fetch_error:
        logger.error(f"Failed to fetch content for {url}: {fetch_error}")
        return {"content": "", "error": fetch_error}
    
    logger.info(f"Successfully fetched content for {url}. Length: {len(content)}")
    return {"content": content, "error": None}

# --- END OF FILE ReconTools/WebFetcher.py ---