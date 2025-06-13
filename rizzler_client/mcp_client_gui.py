# --- START OF MODIFIED mcp_client_gui.py ---

# mcp_client_gui.py
import dearpygui.dearpygui as dpg
import threading
import asyncio
import json
import datetime
import queue
import time
from typing import Dict, Any, List, Optional
import logging
import base64 
import os     
import re     

# Assuming ReConClient and Models are in the same directory or accessible via PYTHONPATH
from ReConClient import MCPClient, ConfigError, ConnectionError, MaxToolIterationsError # MCPClient is needed for type hinting
from models import AVAILABLE_LLM_MODELS, DEFAULT_LLM_MODEL_ID # Import model definitions
from langchain_core.messages import BaseMessage, AIMessage, HumanMessage, ToolMessage, SystemMessage

logger_gui = logging.getLogger("MCPClientGUI") 
# Basic logging config if not set elsewhere - adjust as needed
if not logger_gui.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger_gui.addHandler(handler)
    logger_gui.setLevel(logging.INFO)


gui_update_queue = queue.Queue()
active_plan_ui_elements: Dict[str, Dict[str, int]] = {} # Stores DPG tags for plan-specific UI elements
mcp_client_instance: Optional[MCPClient] = None # Will hold the MCPClient instance
global_font = None

# Global list for the left-panel "Agent Interaction" / "Initiation History"
INITIATION_HISTORY_MESSAGES: List[BaseMessage] = []


# --- Color Palette (remains the same) ---
COLOR_BACKGROUND = (30, 32, 48, 255)
COLOR_CHILD_BACKGROUND = (40, 42, 68, 255)
COLOR_FRAME_BACKGROUND = (50, 55, 80, 255)
COLOR_FRAME_HOVER = (70, 75, 100, 255)
COLOR_FRAME_ACTIVE = (60, 65, 90, 255)
COLOR_TEXT = (220, 220, 225, 255)
COLOR_TEXT_DISABLED = (150, 150, 150, 255)
COLOR_BORDER = (80, 85, 110, 255)
ACCENT_PRIMARY = (0, 123, 255, 255)
ACCENT_PRIMARY_HOVER = (0, 100, 220, 255)
ACCENT_PRIMARY_ACTIVE = (0, 80, 180, 255)
ACCENT_SECONDARY = (255, 165, 0, 255) # Orange-like accent
ACCENT_SECONDARY_HOVER = (230, 140, 0, 255)
ACCENT_SECONDARY_ACTIVE = (200, 120, 0, 255)
COLOR_TITLE_BAR = COLOR_BACKGROUND
COLOR_BUTTON = ACCENT_SECONDARY
COLOR_BUTTON_HOVER = ACCENT_SECONDARY_HOVER
COLOR_BUTTON_ACTIVE = ACCENT_SECONDARY_ACTIVE
COLOR_HEADER = COLOR_FRAME_BACKGROUND
COLOR_HEADER_HOVER = COLOR_FRAME_HOVER
COLOR_HEADER_ACTIVE = COLOR_FRAME_ACTIVE
COLOR_TAB = COLOR_FRAME_BACKGROUND
COLOR_TAB_HOVER = COLOR_FRAME_HOVER
COLOR_TAB_ACTIVE = ACCENT_PRIMARY
COLOR_TAB_UNFOCUSED = COLOR_FRAME_BACKGROUND
COLOR_TAB_UNFOCUSED_ACTIVE = (int(ACCENT_PRIMARY[0]*0.7), int(ACCENT_PRIMARY[1]*0.7), int(ACCENT_PRIMARY[2]*0.7), 255)
BUTTON_CANCEL_COLOR = (220, 53, 69, 255) 
BUTTON_CANCEL_HOVER = (200, 40, 55, 255)
BUTTON_CANCEL_ACTIVE = (180, 30, 45, 255)


def setup_custom_theme(): # Unchanged
    global global_font
    # Ensure the font path is correct relative to where mcp_client_gui.py is run
    # Or use an absolute path if necessary.
    font_path = "src/fonts/NotoSans-Regular.ttf" 
    try:
        with dpg.font_registry():
            # Check if font file exists
            if not os.path.exists(font_path):
                logger_gui.error(f"Font file not found at '{font_path}'. Using default DPG font.")
                global_font = dpg.add_font_default() # Fallback to default
            else:
                global_font = dpg.add_font(font_path, 18) # Adjust size as needed
        dpg.bind_font(global_font)
        logger_gui.info(f"Font bound. Using: {'Default DPG Font' if not os.path.exists(font_path) else font_path}")
    except Exception as e:
        logger_gui.error(f"Error loading/binding font '{font_path}': {e}. Using default DPG font.")
        if global_font is None: # Ensure global_font is set if add_font failed
             with dpg.font_registry(): global_font = dpg.add_font_default()
             dpg.bind_font(global_font)


    with dpg.theme() as global_theme_id:
        with dpg.theme_component(dpg.mvAll):
            dpg.add_theme_color(dpg.mvThemeCol_Text, COLOR_TEXT)
            dpg.add_theme_color(dpg.mvThemeCol_TextDisabled, COLOR_TEXT_DISABLED)
            dpg.add_theme_color(dpg.mvThemeCol_WindowBg, COLOR_BACKGROUND)
            dpg.add_theme_color(dpg.mvThemeCol_ChildBg, COLOR_CHILD_BACKGROUND)
            dpg.add_theme_color(dpg.mvThemeCol_PopupBg, COLOR_CHILD_BACKGROUND)
            dpg.add_theme_color(dpg.mvThemeCol_Border, COLOR_BORDER)
            dpg.add_theme_color(dpg.mvThemeCol_FrameBg, COLOR_FRAME_BACKGROUND)
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, COLOR_FRAME_HOVER)
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, COLOR_FRAME_ACTIVE)
            dpg.add_theme_color(dpg.mvThemeCol_TitleBg, COLOR_TITLE_BAR)
            dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, ACCENT_PRIMARY)
            dpg.add_theme_color(dpg.mvThemeCol_TitleBgCollapsed, COLOR_TITLE_BAR)
            dpg.add_theme_color(dpg.mvThemeCol_MenuBarBg, COLOR_CHILD_BACKGROUND)
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarBg, COLOR_FRAME_BACKGROUND)
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrab, COLOR_FRAME_ACTIVE)
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabHovered, COLOR_FRAME_HOVER)
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabActive, ACCENT_PRIMARY_ACTIVE)
            dpg.add_theme_color(dpg.mvThemeCol_CheckMark, ACCENT_PRIMARY)
            dpg.add_theme_color(dpg.mvThemeCol_SliderGrab, ACCENT_PRIMARY)
            dpg.add_theme_color(dpg.mvThemeCol_SliderGrabActive, ACCENT_PRIMARY_ACTIVE)
            dpg.add_theme_color(dpg.mvThemeCol_Button, COLOR_BUTTON)
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, COLOR_BUTTON_HOVER)
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, COLOR_BUTTON_ACTIVE)
            dpg.add_theme_color(dpg.mvThemeCol_Header, COLOR_HEADER)
            dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, COLOR_HEADER_HOVER)
            dpg.add_theme_color(dpg.mvThemeCol_HeaderActive, COLOR_HEADER_ACTIVE)
            dpg.add_theme_color(dpg.mvThemeCol_Separator, COLOR_BORDER)
            dpg.add_theme_color(dpg.mvThemeCol_ResizeGrip, COLOR_FRAME_ACTIVE)
            dpg.add_theme_color(dpg.mvThemeCol_ResizeGripHovered, COLOR_FRAME_HOVER)
            dpg.add_theme_color(dpg.mvThemeCol_ResizeGripActive, ACCENT_PRIMARY_ACTIVE)
            dpg.add_theme_color(dpg.mvThemeCol_Tab, COLOR_TAB)
            dpg.add_theme_color(dpg.mvThemeCol_TabHovered, COLOR_TAB_HOVER)
            dpg.add_theme_color(dpg.mvThemeCol_TabActive, COLOR_TAB_ACTIVE)
            dpg.add_theme_color(dpg.mvThemeCol_TabUnfocused, COLOR_TAB_UNFOCUSED)
            dpg.add_theme_color(dpg.mvThemeCol_TabUnfocusedActive, COLOR_TAB_UNFOCUSED_ACTIVE)
            dpg.add_theme_color(dpg.mvThemeCol_TableBorderStrong, COLOR_BORDER)
            dpg.add_theme_color(dpg.mvThemeCol_TableBorderLight, (int(COLOR_BORDER[0]*0.7), int(COLOR_BORDER[1]*0.7), int(COLOR_BORDER[2]*0.7), 255))
            dpg.add_theme_color(dpg.mvThemeCol_TableHeaderBg, COLOR_HEADER)

            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 5.0)
            dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 8.0)
            dpg.add_theme_style(dpg.mvStyleVar_ChildRounding, 6.0)
            dpg.add_theme_style(dpg.mvStyleVar_PopupRounding, 6.0)
            dpg.add_theme_style(dpg.mvStyleVar_ScrollbarRounding, 9.0)
            dpg.add_theme_style(dpg.mvStyleVar_GrabRounding, 4.0)
            dpg.add_theme_style(dpg.mvStyleVar_TabRounding, 4.0)
            dpg.add_theme_style(dpg.mvStyleVar_IndentSpacing, 20.0)
            dpg.add_theme_style(dpg.mvStyleVar_ScrollbarSize, 15.0)
            dpg.add_theme_style(dpg.mvStyleVar_GrabMinSize, 12.0)
            dpg.add_theme_style(dpg.mvStyleVar_ChildBorderSize, 1.0) 
            dpg.add_theme_style(dpg.mvStyleVar_FrameBorderSize, 0.0) # No border for frames like input text
            dpg.add_theme_style(dpg.mvStyleVar_WindowPadding, x=10.0, y=10.0)
            dpg.add_theme_style(dpg.mvStyleVar_FramePadding, x=8.0, y=6.0)
            dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing, x=8.0, y=6.0)
            dpg.add_theme_style(dpg.mvStyleVar_ItemInnerSpacing, x=6.0, y=6.0)

    # Specific theme for the "Cancel Plan" button
    with dpg.theme(tag="CancelButtonActualTheme") as cancel_button_actual_theme_id:
        with dpg.theme_component(dpg.mvButton): # Target only buttons
            dpg.add_theme_color(dpg.mvThemeCol_Button, BUTTON_CANCEL_COLOR)
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, BUTTON_CANCEL_HOVER)
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, BUTTON_CANCEL_ACTIVE)
            dpg.add_theme_color(dpg.mvThemeCol_Text, COLOR_TEXT) # Ensure text color is standard

    dpg.bind_theme(global_theme_id)
    logger_gui.info("Global theme applied.")
    if dpg.does_item_exist("CancelButtonActualTheme"):
        logger_gui.info(f"Cancel button specific theme 'CancelButtonActualTheme' created with ID: {cancel_button_actual_theme_id}")


# --- Helper Functions for Base64 and Downloads ---
def is_likely_base64(s: str) -> bool: # Unchanged
    if not isinstance(s, str) or not s:
        return False
    if not re.fullmatch(r"^[A-Za-z0-9+/=\s]*$", s):
        return False
    stripped_s = s.strip().rstrip("=")
    if len(stripped_s) % 4 == 0 or (len(stripped_s) + 1) % 4 == 0 or (len(stripped_s) + 2) % 4 == 0 :
        if len(s.strip()) % 4 == 0:
            return True
    return False

def sanitize_filename(filename: str) -> str: # Unchanged
    if not filename:
        return "untitled_file"
    s = re.sub(r'[^\w\s.-]', '', filename) 
    s = re.sub(r'\s+', '_', s).strip(' _')
    s = s[:100] 
    if not s:
        return "sanitized_file"
    return s

def _save_file_dialog_callback(sender, app_data, user_data): # Unchanged
    base64_to_save = user_data 

    if not app_data or 'file_path_name' not in app_data:
        logger_gui.warning("File dialog cancelled or no file path selected.")
        if dpg.does_item_exist("status_bar_text"):
            dpg.set_value("status_bar_text", "Download cancelled.")
        return

    file_path = app_data['file_path_name']
    logger_gui.info(f"User selected path for download: {file_path}")

    try:
        decoded_data = base64.b64decode(base64_to_save)
        with open(file_path, "wb") as f:
            f.write(decoded_data)
        logger_gui.info(f"Successfully saved file to: {file_path}")
        if dpg.does_item_exist("status_bar_text"):
            dpg.set_value("status_bar_text", f"Success: File saved to {file_path}")
    except base64.binascii.Error as e:
        logger_gui.error(f"Error decoding base64 string for '{os.path.basename(file_path)}': {e}")
        if dpg.does_item_exist("status_bar_text"):
            dpg.set_value("status_bar_text", f"Error: Invalid base64 data for {os.path.basename(file_path)}.")
    except IOError as e:
        logger_gui.error(f"Error writing file '{file_path}': {e}")
        if dpg.does_item_exist("status_bar_text"):
            dpg.set_value("status_bar_text", f"Error: Could not write file {os.path.basename(file_path)}: {e}")
    except Exception as e:
        logger_gui.error(f"Unexpected error during save for '{os.path.basename(file_path)}': {e}", exc_info=True)
        if dpg.does_item_exist("status_bar_text"):
            dpg.set_value("status_bar_text", f"Error: Unexpected save issue for {os.path.basename(file_path)}.")

# --- MODIFIED _download_button_callback ---
def _download_button_callback(sender, app_data, user_data):
    base64_string, suggested_filename_raw = user_data
    sanitized_default_filename = sanitize_filename(suggested_filename_raw)
    dialog_tag = f"file_dialog_save_b64_{int(time.time())}"

    # --- NEW: Define the default path for the file dialog ---
    # This path is INSIDE the container, but it's mapped to a host directory
    # via the volume mount in docker-compose.yml (e.g., /app/host_downloads).
    default_save_path_in_container = "/app/host_downloads" 
    
    # Optional: Ensure the directory exists inside the container.
    # Docker's volume mounting should create the mount point, but this adds robustness.
    try:
        if not os.path.exists(default_save_path_in_container):
            os.makedirs(default_save_path_in_container, exist_ok=True)
            logger_gui.info(f"Created default save directory in container: {default_save_path_in_container}")
    except OSError as e:
        logger_gui.error(f"Could not create default save directory '{default_save_path_in_container}' in container: {e}. File dialog might not default correctly.")
        # Fallback to current directory if creation fails, though this is less ideal.
        default_save_path_in_container = "."


    if dpg.does_item_exist(dialog_tag):
        logger_gui.warning(f"File dialog with tag {dialog_tag} already exists. Skipping.")
        return

    dpg.add_file_dialog(
        directory_selector=False, show=True, callback=_save_file_dialog_callback, 
        tag=dialog_tag, user_data=base64_string, width=700, height=400,
        default_filename=sanitized_default_filename,
        # --- MODIFIED: Set the default_path for the dialog ---
        default_path=default_save_path_in_container, 
        modal=True
    )
    logger_gui.info(f"Opened file dialog for saving '{sanitized_default_filename}'. Default path (in container): {default_save_path_in_container}. Tag: {dialog_tag}")
    if dpg.does_item_exist("status_bar_text"):
        dpg.set_value("status_bar_text", f"Select location to save {sanitized_default_filename} (defaults to shared host folder)...")

# --- Tool Log Formatting (Unchanged) ---
def _format_tool_log_entry_for_display(log_entry: Dict[str, Any], parent_width: int) -> None: # Unchanged
    tool_name = log_entry.get('tool_name', 'N/A')
    tool_args = log_entry.get('tool_args', {}) 
    status = log_entry.get('status', 'unknown').capitalize()
    timestamp_start_str = log_entry.get('timestamp_start', '')
    header_text = f"Tool: {tool_name} ({status})"
    if timestamp_start_str:
        try:
            dt_start = datetime.datetime.fromisoformat(timestamp_start_str.replace("Z", "+00:00"))
            header_text += f" - Started: {dt_start.strftime('%H:%M:%S.%f')[:-3]}"
        except ValueError: header_text += f" - Started: {timestamp_start_str}"

    timestamp_end_str = log_entry.get('timestamp_end', '')
    if timestamp_end_str and status.lower() not in ['running', 'pending', 'queued', 'initializing']:
        try:
            dt_end = datetime.datetime.fromisoformat(timestamp_end_str.replace("Z", "+00:00"))
            header_text += f" - Ended: {dt_end.strftime('%H:%M:%S.%f')[:-3]}"
        except ValueError: header_text += f" - Ended: {timestamp_end_str}"
            
    dpg.add_text(header_text)
    
    with dpg.tree_node(label=f"Arguments##args_{tool_name}_{timestamp_start_str}", default_open=False):
        try:
            args_pretty = json.dumps(tool_args, indent=2)
            dpg.add_input_text(default_value=args_pretty, multiline=True, readonly=True, width=-1, height=100)
        except Exception: dpg.add_text(f"{str(tool_args)[:500]}{'...' if len(str(tool_args)) > 500 else ''}", wrap=parent_width - 30)

    stream_events = log_entry.get('stream_events', [])
    if stream_events:
        with dpg.tree_node(label=f"Stream Updates ({len(stream_events)})##stream_{tool_name}_{timestamp_start_str}", default_open=True):
            max_events_to_show_directly = 10
            events_to_display = stream_events
            if len(stream_events) > max_events_to_show_directly:
                dpg.add_text(f"(Showing last {max_events_to_show_directly} of {len(stream_events)} stream updates. Expand details for more.)")
                events_to_display = stream_events[-max_events_to_show_directly:]

            for i, event_data in enumerate(events_to_display):
                event_ts_str = event_data.get('timestamp', 'N/A')
                event_msg = event_data.get('status_message', 'No message')
                event_details = event_data.get('details', {})
                try:
                    event_dt = datetime.datetime.fromisoformat(event_ts_str.replace("Z", "+00:00"))
                    event_ts_formatted = event_dt.strftime('%H:%M:%S.%f')[:-3]
                except ValueError: event_ts_formatted = event_ts_str
                event_summary_line = f"[{event_ts_formatted}] {event_msg}"
                if event_details:
                    with dpg.tree_node(label=f"{event_summary_line}##detail_event_{i}_{timestamp_start_str}", default_open=False):
                        try:
                            details_pretty = json.dumps(event_details, indent=2, sort_keys=True)
                            dpg.add_input_text(default_value=details_pretty, multiline=True, readonly=True, width=-1, height=150)
                        except Exception as e:
                            logger_gui.warning(f"Could not pretty print stream event details: {e}")
                            dpg.add_text(f"Details: {str(event_details)[:300]}...", wrap=parent_width - 50)
                else: dpg.add_text(event_summary_line, wrap=parent_width - 30)
                if i < len(events_to_display) -1 : dpg.add_separator()
    elif status.lower() == 'running': dpg.add_text("  (Waiting for stream updates...)")

    if status.lower() == 'completed (cached)':
        dpg.add_text(f"Result: (Retrieved from cache)")
        formatted_llm_cached = log_entry.get('formatted_result_for_llm', 'N/A')
        with dpg.tree_node(label="Formatted Result (for LLM)##cached_llm_res", default_open=True):
            dpg.add_text(f"{formatted_llm_cached}", wrap=parent_width - 30)
    elif status.lower() == 'completed':
        formatted_llm = log_entry.get('formatted_result_for_llm', 'N/A')
        final_event_data = log_entry.get('final_event_data', {})
        full_result_payload = final_event_data.get('result_payload', {})
        with dpg.tree_node(label="Formatted Result (for LLM)##llm_res", default_open=True):
            dpg.add_text(f"{formatted_llm}", wrap=parent_width - 30)
        if full_result_payload and isinstance(full_result_payload, dict):
            with dpg.tree_node(label="Full Result Payload##full_res", default_open=False):
                has_displayed_items = False
                for key, value in full_result_payload.items():
                    if key == "pdf_base64" and isinstance(value, str) and is_likely_base64(value):
                        report_title_from_args = tool_args.get('report_title', f"{tool_name}_report")
                        suggested_filename = f"{report_title_from_args}.pdf"
                        dpg.add_text(f"{key}: (Base64 PDF Data - {len(value)} bytes)")
                        dpg.add_button(label=f"Download {sanitize_filename(suggested_filename)}", user_data=(value, suggested_filename), callback=_download_button_callback)
                        dpg.add_separator(); has_displayed_items = True
                    else:
                        try: item_str = json.dumps({key: value}, indent=2)
                        except: item_str = f"{key}: {str(value)[:200]}{'...' if len(str(value)) > 200 else ''}"
                        if len(item_str) > 500: item_str = item_str[:500] + "\n... (truncated)"
                        dpg.add_text(item_str, wrap=parent_width - 50); has_displayed_items = True
                if not has_displayed_items and full_result_payload: dpg.add_text("Payload content not individually rendered or no specific handlers.")
                elif not full_result_payload: dpg.add_text("Payload is empty.")
        elif full_result_payload:
             with dpg.tree_node(label="Full Result Payload##full_res_str", default_open=False):
                dpg.add_input_text(default_value=str(full_result_payload), multiline=True, readonly=True, width=-1, height=200)
        storage_info = final_event_data.get('storage_info')
        if storage_info: dpg.add_text(f"Storage: {storage_info.get('status', 'N/A')} - {storage_info.get('message', '')} (ID: {storage_info.get('doc_id', 'N/A')})")
    elif status.lower() == 'failed':
        error_info_payload = log_entry.get('error_info', {})
        error_msg_display = "No error details."
        if isinstance(error_info_payload, dict):
            error_msg_display = error_info_payload.get('message', 'No specific error message.')
            error_type_display = error_info_payload.get('type', 'UnknownErrorType')
            error_details_display = error_info_payload.get('details', {})
            dpg.add_text(f"Error Type: {error_type_display}", color=(255,100,100))
            dpg.add_text(f"Message: {error_msg_display}", color=(255,100,100), wrap=parent_width - 30)
            if error_details_display:
                with dpg.tree_node(label="Error Details##err_details", default_open=True):
                    try:
                        err_details_pretty = json.dumps(error_details_display, indent=2)
                        dpg.add_input_text(default_value=err_details_pretty, multiline=True, readonly=True, width=-1, height=100) 
                    except: dpg.add_text(f"{str(error_details_display)}", color=(255,100,100), wrap=parent_width-50)
        else: dpg.add_text(f"Error: {str(error_info_payload)[:500]}...", color=(255,100,100), wrap=parent_width - 30)
    dpg.add_separator()

# --- MCPClient Async Runner (Unchanged) ---
def mcp_client_async_runner(): # Unchanged
    global mcp_client_instance
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    command_processor_task = None
    try:
        mcp_client_instance = MCPClient() # MCPClient will init Models with default LLM
        mcp_client_instance.loop = loop
        mcp_client_instance.gui_update_queue = gui_update_queue
        if hasattr(mcp_client_instance, 'client_command_queue') and mcp_client_instance.client_command_queue is None:
            mcp_client_instance.client_command_queue = asyncio.Queue()

        loop.run_until_complete(mcp_client_instance.initialize_tools())
        gui_update_queue.put({"type": "client_ready"})
        
        async def command_processor():
            try:
                if mcp_client_instance and mcp_client_instance.client_command_queue:
                    logger_gui.info("Command processor started, awaiting commands.")
                    while True:
                        command_data = await mcp_client_instance.client_command_queue.get()
                        if command_data is None: logger_gui.info("Command processor received shutdown signal."); break
                        if hasattr(mcp_client_instance, 'handle_gui_command'):
                            await mcp_client_instance.handle_gui_command(command_data)
                        else: logger_gui.warning(f"MCPClient has no handle_gui_command method. Command ignored: {command_data}")
                        if mcp_client_instance.client_command_queue: mcp_client_instance.client_command_queue.task_done()
            except asyncio.CancelledError: logger_gui.info("Command processor task cancelled.")
            except Exception as e: logger_gui.error(f"Critical error in command processor: {e}", exc_info=True)

        command_processor_task = loop.create_task(command_processor(), name="GuiCommandProcessor")
        loop.run_until_complete(command_processor_task) 
    except ConfigError as e: gui_update_queue.put({"type": "client_error", "message": f"Config Error: {e}"})
    except ConnectionError as e: gui_update_queue.put({"type": "client_error", "message": f"Connection Error: {e}"})
    except Exception as e:
        logger_gui.exception(f"Critical Client Error in mcp_client_async_runner: {e}")
        gui_update_queue.put({"type": "client_error", "message": f"Critical Client Error: {e}"})
    finally:
        if command_processor_task and not command_processor_task.done():
            command_processor_task.cancel()
            try:
                if loop and not loop.is_closed(): loop.run_until_complete(asyncio.wait_for(command_processor_task, timeout=2.0))
            except (asyncio.CancelledError, asyncio.TimeoutError): logger_gui.info("Command processor task cancellation processed or timed out.")
            except Exception as e_cancel: logger_gui.error(f"Error while cancelling command processor task: {e_cancel}")
        if mcp_client_instance and hasattr(mcp_client_instance, 'cleanup') and asyncio.iscoroutinefunction(mcp_client_instance.cleanup):
            if loop and not loop.is_closed(): loop.run_until_complete(mcp_client_instance.cleanup())
        if loop and not loop.is_closed(): loop.close()
        logger_gui.info("mcp_client_async_runner finished.")

# --- Dear PyGui Callback Functions ---
def _format_message_for_display(msg: BaseMessage) -> str: # Unchanged
    if isinstance(msg, HumanMessage): return f"👤 User: {msg.content}"
    elif isinstance(msg, AIMessage):
        content_str = f"🤖 AI: {msg.content if msg.content else ''}"
        if msg.tool_calls: 
            tool_calls_summary = [f"{tc.get('name')}(...)" if isinstance(tc, dict) else str(tc) for tc in msg.tool_calls]
            content_str += f"\n   🛠️ Tool Calls: {', '.join(tool_calls_summary)}"
        elif hasattr(msg, 'additional_kwargs') and msg.additional_kwargs.get('tool_calls'): 
            tool_calls_summary = [f"{tc.get('function',{}).get('name','N/A')}(...)" if isinstance(tc, dict) else str(tc) for tc in msg.additional_kwargs['tool_calls']]
            content_str += f"\n   🛠️ Tool Calls (legacy): {', '.join(tool_calls_summary)}"
        return content_str
    elif isinstance(msg, ToolMessage): return f"⚙️ Tool ({msg.tool_call_id}): {msg.content}"
    elif isinstance(msg, SystemMessage): return f"🖥️ System: {msg.content}"
    return str(msg.content if hasattr(msg, 'content') else msg)

def _update_plan_content_area(area_tag: Optional[int], content_list: List[Any], item_formatter_func, wrap_width_offset=20): # Unchanged
    if not area_tag or not dpg.does_item_exist(area_tag): return
    dpg.delete_item(area_tag, children_only=True)
    parent_width = dpg.get_item_width(area_tag)
    wrap_width = parent_width - wrap_width_offset if parent_width and parent_width > wrap_width_offset else 0
    for item_data in content_list:
        formatted_text = item_formatter_func(item_data)
        if isinstance(formatted_text, tuple): 
            dpg.add_text(formatted_text[0], parent=area_tag, wrap=wrap_width if wrap_width > 0 else -1)
            if formatted_text[1]: dpg.add_separator(parent=area_tag)
        else:
            dpg.add_text(formatted_text, parent=area_tag, wrap=wrap_width if wrap_width > 0 else -1)
            if item_formatter_func == _format_message_for_display: dpg.add_separator(parent=area_tag)

def _update_plan_conversation_history(plan_id: str, history: List[BaseMessage]): # Unchanged
    if plan_id not in active_plan_ui_elements: return
    history_group_tag = active_plan_ui_elements[plan_id].get('history_group_tag')
    _update_plan_content_area(history_group_tag, history, _format_message_for_display)

def _format_thought_for_display(thought_detail: Dict[str, Any]) -> str: # Unchanged
    thought_text = thought_detail.get('thought', 'N/A')
    thought_num = thought_detail.get('thoughtNumber', 'N/A')
    return f"[{thought_num}] {thought_text}"

def _update_plan_thoughts(plan_id: str, thoughts: List[Dict[str, Any]]): # Unchanged
    if plan_id not in active_plan_ui_elements: return
    thoughts_group_tag = active_plan_ui_elements[plan_id].get('thoughts_group_tag')
    _update_plan_content_area(thoughts_group_tag, thoughts, _format_thought_for_display)

def _update_plan_tool_calls_log(plan_id: str, tool_calls_log: List[Dict[str, Any]]): # Unchanged
    if plan_id not in active_plan_ui_elements: return
    tool_log_group_tag = active_plan_ui_elements[plan_id].get('tool_log_group_tag')
    if not tool_log_group_tag or not dpg.does_item_exist(tool_log_group_tag): return
    dpg.delete_item(tool_log_group_tag, children_only=True)
    parent_width = dpg.get_item_width(tool_log_group_tag) or dpg.get_item_width(dpg.get_item_parent(tool_log_group_tag)) or 600
    if not tool_calls_log: dpg.add_text("No tool calls logged yet.", parent=tool_log_group_tag); return
    for entry in tool_calls_log:
        dpg.push_container_stack(tool_log_group_tag) 
        _format_tool_log_entry_for_display(entry, parent_width)
        dpg.pop_container_stack()

def _update_plan_last_tool_result(plan_id: str, tool_calls_log: List[Dict[str, Any]]): # Unchanged
    if plan_id not in active_plan_ui_elements: return
    last_result_group_tag = active_plan_ui_elements[plan_id].get('last_result_group_tag')
    if not last_result_group_tag or not dpg.does_item_exist(last_result_group_tag): return
    dpg.delete_item(last_result_group_tag, children_only=True)
    parent_width = dpg.get_item_width(last_result_group_tag) or dpg.get_item_width(dpg.get_item_parent(last_result_group_tag)) or 600
    if not tool_calls_log: dpg.add_text("No tool calls logged yet to display a last result.", parent=last_result_group_tag); return
    last_meaningful_call = next((call for call in reversed(tool_calls_log) if call.get('tool_name') != "SequentialThinkingPlanner"), tool_calls_log[-1] if tool_calls_log else None)
    if not last_meaningful_call: dpg.add_text("No non-planner tool calls yet.", parent=last_result_group_tag); return
    last_call = last_meaningful_call
    tool_name = last_call.get('tool_name', 'N/A')
    tool_args = last_call.get('tool_args', {})
    status = last_call.get('status', 'unknown').lower()
    final_data = last_call.get('final_event_data', {})
    dpg.add_text(f"Last Tool Executed: {tool_name}", parent=last_result_group_tag)
    dpg.add_separator(parent=last_result_group_tag)
    dpg.add_text("Arguments:", parent=last_result_group_tag)
    try:
        args_pretty = json.dumps(tool_args, indent=2, sort_keys=True)
        dpg.add_input_text(default_value=args_pretty, multiline=True, readonly=True, width=-1, height=100, parent=last_result_group_tag)
    except Exception as e:
        logger_gui.error(f"Could not pretty print args for last result: {e}")
        dpg.add_text(str(tool_args), parent=last_result_group_tag, wrap=parent_width - 30)
    dpg.add_separator(parent=last_result_group_tag)
    if status == 'completed' or status == 'completed (cached)':
        dpg.add_text("Result Payload:", parent=last_result_group_tag)
        result_payload = final_data.get('result_payload', {})
        if isinstance(result_payload, dict):
            has_displayed_items = False
            for r_key, r_value in result_payload.items():
                if r_key == "pdf_base64" and isinstance(r_value, str) and is_likely_base64(r_value):
                    report_title = tool_args.get('report_title', f"{tool_name}_report")
                    suggested_filename = f"{report_title}.pdf"
                    dpg.add_text(f"{r_key}: (Base64 PDF Data - {len(r_value)} bytes)", parent=last_result_group_tag)
                    dpg.add_button(label=f"Download {sanitize_filename(suggested_filename)}", user_data=(r_value, suggested_filename), callback=_download_button_callback, parent=last_result_group_tag)
                    dpg.add_separator(parent=last_result_group_tag); has_displayed_items = True
                else:
                    try: item_str = json.dumps({r_key: r_value}, indent=2)
                    except: item_str = f"{r_key}: {str(r_value)[:200]}{'...' if len(str(r_value)) > 200 else ''}"
                    if len(item_str) > 500: item_str = item_str[:500] + "\n... (truncated)"
                    dpg.add_text(item_str, parent=last_result_group_tag, wrap=parent_width - 30); has_displayed_items = True
            if not has_displayed_items and result_payload: dpg.add_text("(Payload content not individually rendered or no specific handlers)", parent=last_result_group_tag)
            elif not result_payload: dpg.add_text("(Payload is empty)", parent=last_result_group_tag)
        elif result_payload: dpg.add_input_text(default_value=str(result_payload), multiline=True, readonly=True, width=-1, height=250, parent=last_result_group_tag)
        else: dpg.add_text("(No result payload)", parent=last_result_group_tag)
        storage_info = final_data.get('storage_info')
        if storage_info: dpg.add_text(f"Storage: {storage_info.get('status', 'N/A')} - {storage_info.get('message', '')} (ID: {storage_info.get('doc_id', 'N/A')})", parent=last_result_group_tag)
    elif status == 'failed':
        dpg.add_text("Error Payload:", color=(255, 100, 100), parent=last_result_group_tag)
        error_payload = final_data.get('error_payload', last_call.get('error_info', {}))
        try:
            error_pretty = json.dumps(error_payload, indent=2, sort_keys=True)
            dpg.add_input_text(default_value=error_pretty, multiline=True, readonly=True, width=-1, height=150, parent=last_result_group_tag)
        except Exception as e:
            logger_gui.error(f"Could not pretty print error payload for last result: {e}")
            dpg.add_text(str(error_payload), parent=last_result_group_tag, wrap=parent_width - 30, color=(255,100,100))
    else:
        dpg.add_text(f"Current Status: {status.capitalize()}", parent=last_result_group_tag)
        dpg.add_text("Full result/error is not yet available for this tool call.", parent=last_result_group_tag)

def _update_plan_streaming_output(plan_id: str, stream_data: Dict[str, Any]): # Unchanged
    if plan_id not in active_plan_ui_elements: return
    live_stream_group_tag = active_plan_ui_elements[plan_id].get('live_stream_group_tag')
    if not live_stream_group_tag or not dpg.does_item_exist(live_stream_group_tag): return
    dpg.delete_item(live_stream_group_tag, children_only=True)
    parent_width = dpg.get_item_width(live_stream_group_tag) or dpg.get_item_width(dpg.get_item_parent(live_stream_group_tag)) or 600
    data = stream_data 
    try: 
        tool_name_stream = data.get('tool_name'); timestamp_stream = data.get('timestamp')
        status_message_stream = data.get('status_message'); details_stream = data.get('details')
        if tool_name_stream and timestamp_stream and status_message_stream:
            try:
                dt_stream = datetime.datetime.fromisoformat(timestamp_stream.replace("Z", "+00:00"))
                ts_formatted = dt_stream.strftime('%H:%M:%S.%f')[:-3]
            except ValueError: ts_formatted = timestamp_stream
            dpg.add_text(f"Tool: {tool_name_stream} [{ts_formatted}]", parent=live_stream_group_tag)
            dpg.add_text(f"Update: {status_message_stream}", parent=live_stream_group_tag, wrap=parent_width -20)
            if details_stream:
                with dpg.tree_node(label="Details##stream_details", parent=live_stream_group_tag, default_open=True):
                    try:
                        details_pretty = json.dumps(details_stream, indent=2, sort_keys=True)
                        dpg.add_input_text(default_value=details_pretty, multiline=True, readonly=True, width=-1, height=100, parent=dpg.last_item())
                    except: dpg.add_text(str(details_stream), parent=dpg.last_item(), wrap=parent_width-40)
        elif data.get('event_type') or data.get('source'): 
            event_type = data.get('event_type'); source = data.get('source')
            if event_type: dpg.add_text(f"Event Type: {event_type}", parent=live_stream_group_tag)
            if source: dpg.add_text(f"Source: {source}", parent=live_stream_group_tag)
            details_payload = data.get('details')
            if isinstance(details_payload, dict):
                status = details_payload.get('status'); message = details_payload.get('message'); method = details_payload.get('method') 
                if method and method != source: dpg.add_text(f"Method: {method}", parent=live_stream_group_tag)
                if status: dpg.add_text(f"Status: {status}", parent=live_stream_group_tag)
                if message: dpg.add_text(f"Message: {str(message)[:200]}{'...' if len(str(message)) > 200 else ''}", parent=live_stream_group_tag, wrap=parent_width - 20)
                if source in ["brute_force", "crtsh", "web_search", "dns_query"] and 'subdomain' in details_payload:
                    dpg.add_text(f"Found Subdomain: {details_payload['subdomain']}", parent=live_stream_group_tag)
                    if 'ips' in details_payload: dpg.add_text(f"  IPs: {', '.join(details_payload['ips'])}", parent=live_stream_group_tag)
            elif isinstance(details_payload, str): dpg.add_text(f"Detail: {details_payload[:250]}{'...' if len(details_payload) > 250 else ''}", parent=live_stream_group_tag, wrap=parent_width - 20)
            elif details_payload is not None: dpg.add_text(f"Details: {str(details_payload)[:250]}{'...' if len(str(details_payload)) > 250 else ''}", parent=live_stream_group_tag, wrap=parent_width - 20)
        else: 
            dpg.add_text("Parsed Stream Data:", parent=live_stream_group_tag)
            for key, value in data.items(): dpg.add_text(f"  {key}: {str(value)[:150]}{'...' if len(str(value)) > 150 else ''}", parent=live_stream_group_tag, wrap=parent_width - 20)
    except Exception as e:
        logger_gui.error(f"Error formatting live stream output: {e}", exc_info=True)
        dpg.add_text(f"Error displaying stream: {e}", parent=live_stream_group_tag, color=(255,100,100))

def _update_plan_status_and_summary(plan_id: str, plan_data: Dict[str, Any]): # Unchanged
    if plan_id not in active_plan_ui_elements: return
    status_summary_tag = active_plan_ui_elements[plan_id].get('status_summary_tag')
    if not status_summary_tag or not dpg.does_item_exist(status_summary_tag): return
    status = plan_data.get('status', 'Unknown'); query = plan_data.get('query', 'N/A')
    deps = plan_data.get('dependencies', []); unfinished_deps = plan_data.get('unfinished_dependencies', 0)
    summary_lines = [f"Status: {status.upper()}", f"Query: {query[:80]}{'...' if len(query) > 80 else ''}", f"Dependencies: {', '.join(deps) if deps else 'None'} (Unfinished: {unfinished_deps})"]
    if status == 'failed': summary_lines.append(f"Error: {str(plan_data.get('error', 'N/A'))[:120]}{'...' if len(str(plan_data.get('error', 'N/A'))) > 120 else ''}")
    elif status == 'completed': summary_lines.append(f"Result: {str(plan_data.get('result', 'N/A'))[:120]}{'...' if len(str(plan_data.get('result', 'N/A'))) > 120 else ''}")
    dpg.set_value(status_summary_tag, "\n".join(summary_lines))

def cancel_plan_callback(sender, app_data, user_data): # Unchanged
    plan_id = user_data
    if not mcp_client_instance or not mcp_client_instance.loop or not mcp_client_instance.client_command_queue or mcp_client_instance.loop.is_closed():
        logger_gui.warning(f"Cannot cancel plan {plan_id}: MCP Client not ready."); return
    logger_gui.info(f"User requested to cancel plan: {plan_id}")
    command_payload = {"plan_id": plan_id}
    try:
        mcp_client_instance.loop.call_soon_threadsafe(mcp_client_instance.client_command_queue.put_nowait, {"command": "cancel_plan", "payload": command_payload})
        if plan_id in active_plan_ui_elements:
            status_summary_tag = active_plan_ui_elements[plan_id].get('status_summary_tag')
            if status_summary_tag and dpg.does_item_exist(status_summary_tag):
                current_summary = dpg.get_value(status_summary_tag)
                new_summary_lines = current_summary.splitlines() if isinstance(current_summary, str) else []
                dpg.set_value(status_summary_tag, f"Status: CANCELLING...\n" + ("\n".join(new_summary_lines[1:]) if new_summary_lines else f"Query: ..."))
    except Exception as e: logger_gui.error(f"Failed to queue 'cancel_plan' command for {plan_id}: {e}", exc_info=True)

def _create_or_update_plan_tab(plan_id: str, plan_data: Dict[str, Any], full_history: List[BaseMessage]): # Unchanged
    tab_label = f"Plan {plan_id.split('_')[-1]}"; plan_status = plan_data.get('status', 'Unknown').lower()
    tab_tag_str = f"tab_{plan_id}"
    if plan_id not in active_plan_ui_elements:
        if dpg.does_item_exist(tab_tag_str):
            logger_gui.warning(f"Tab with tag {tab_tag_str} already exists. Deleting before recreating.")
            dpg.delete_item(tab_tag_str); 
            if plan_id in active_plan_ui_elements: del active_plan_ui_elements[plan_id]
        with dpg.tab(label=tab_label, parent="plan_display_area", tag=tab_tag_str) as new_tab_id_numerical:
            with dpg.group(): 
                dpg.add_spacer(height=5); status_summary_tag = dpg.add_text("Initializing plan details...")
                cancel_button_tag = dpg.add_button(label="Cancel Plan Execution", user_data=plan_id, callback=cancel_plan_callback, width=-1)
                if dpg.does_item_exist("CancelButtonActualTheme"): dpg.bind_item_theme(cancel_button_tag, dpg.get_alias_id("CancelButtonActualTheme"))
                else: logger_gui.error("Theme 'CancelButtonActualTheme' not found for cancel button.")
                dpg.add_separator(); dpg.add_spacer(height=10)
                with dpg.collapsing_header(label="Full Conversation History", default_open=True):
                    with dpg.child_window(height=200, border=True) as history_child_tag: history_group_tag = dpg.add_group() 
                dpg.add_spacer(height=5)
                with dpg.collapsing_header(label="Thoughts Log", default_open=False):
                    with dpg.child_window(height=180, border=True) as thoughts_child_tag: thoughts_group_tag = dpg.add_group()
                dpg.add_spacer(height=5)
                with dpg.collapsing_header(label="Tool Calls Log", default_open=False):
                    with dpg.child_window(height=180, border=True) as tool_log_child_tag: tool_log_group_tag = dpg.add_group()
                dpg.add_spacer(height=5)
                with dpg.collapsing_header(label="Last Tool Result", default_open=True):
                    with dpg.child_window(height=250, border=True) as last_result_child_tag:
                        last_result_group_tag = dpg.add_group(); dpg.add_text("Waiting for tool results...", parent=last_result_group_tag)
                dpg.add_spacer(height=5)
                with dpg.collapsing_header(label="Live Tool Stream / Output", default_open=True):
                     with dpg.child_window(height=150, border=True) as live_stream_child_tag:
                        live_stream_group_tag = dpg.add_group(); dpg.add_text("Waiting for tool stream...", parent=live_stream_group_tag)
            active_plan_ui_elements[plan_id] = {'tab_tag': tab_tag_str, 'status_summary_tag': status_summary_tag, 'history_group_tag': history_group_tag, 'thoughts_group_tag': thoughts_group_tag, 'tool_log_group_tag': tool_log_group_tag, 'last_result_group_tag': last_result_group_tag, 'live_stream_group_tag': live_stream_group_tag, 'cancel_button_tag': cancel_button_tag}
    if plan_id in active_plan_ui_elements:
        current_cancel_button_id = active_plan_ui_elements[plan_id].get('cancel_button_tag')
        if current_cancel_button_id and dpg.does_item_exist(current_cancel_button_id):
            if plan_status in ["running", "queued", "initializing", "cancelling"]: dpg.enable_item(current_cancel_button_id)
            else: dpg.disable_item(current_cancel_button_id)
        _update_plan_status_and_summary(plan_id, plan_data)
        if full_history: _update_plan_conversation_history(plan_id, full_history)
        if plan_data.get('thoughts'): _update_plan_thoughts(plan_id, plan_data['thoughts'])
        tool_calls_log = plan_data.get('tool_calls_log', [])
        if tool_calls_log: _update_plan_tool_calls_log(plan_id, tool_calls_log); _update_plan_last_tool_result(plan_id, tool_calls_log)
        if plan_data.get('current_stream_update'): _update_plan_streaming_output(plan_id, plan_data['current_stream_update'])
    else: logger_gui.warning(f"Plan ID {plan_id} not found in active_plan_ui_elements after creation/update attempt.")

def _populate_tools_panel(): # Unchanged
    tools_list_tag = "tools_overview_list" 
    if not dpg.does_item_exist(tools_list_tag): logger_gui.error("Tools overview list tag does not exist."); return
    dpg.delete_item(tools_list_tag, children_only=True)
    if not mcp_client_instance or not hasattr(mcp_client_instance, 'tools_schema_for_binding') or not mcp_client_instance.tools_schema_for_binding:
        dpg.add_text("No tools available or client not ready.", parent=tools_list_tag); return
    parent_width = dpg.get_item_width("tools_overview_container") or 350 
    for tool_info in mcp_client_instance.tools_schema_for_binding:
        tool_name = tool_info.get("name", "Unknown Tool"); tool_description = tool_info.get("description", "No description provided.")
        with dpg.tree_node(label=tool_name, parent=tools_list_tag, default_open=False):
            dpg.add_text("Description:", color=(210, 210, 210)); dpg.add_text(tool_description, wrap=parent_width - 40, indent=10) 
            params_schema = tool_info.get("parameters", {})
            if params_schema and params_schema.get("properties"):
                dpg.add_spacer(height=3); dpg.add_text("Parameters:", color=(210, 210, 210))
                props = params_schema.get("properties", {}); required_params = params_schema.get("required", [])
                for param_name, param_details in props.items():
                    param_type = param_details.get("type", "any"); param_desc = param_details.get("description", ""); is_required = param_name in required_params
                    label_text = f"  • {param_name} ({param_type}){' (required)' if is_required else ''}"
                    dpg.add_text(label_text, indent=10)
                    if param_desc: dpg.add_text(f"{param_desc}", wrap=parent_width - 60, indent=30)
            elif params_schema and params_schema.get("type") and params_schema.get("type") != "object": dpg.add_text("Parameters: None", color=(200, 200, 200), indent=10)
            else: dpg.add_text("Parameters: (No specific parameters defined)", color=(180,180,180), indent=10)
        dpg.add_separator(parent=tools_list_tag)

# --- NEW: Callback for LLM Model Selection Dropdown ---
def llm_combo_callback(sender, app_data, user_data): # Unchanged
    selected_display_name = app_data # This is the display name from the combo
    
    # Find the internal model ID corresponding to the selected display name
    internal_model_id = None
    for display_name_key, model_id_val in AVAILABLE_LLM_MODELS.items():
        if display_name_key == selected_display_name:
            internal_model_id = model_id_val
            break
    
    if internal_model_id and mcp_client_instance and mcp_client_instance.client_command_queue:
        logger_gui.info(f"User selected LLM: {selected_display_name} (Internal ID: {internal_model_id})")
        command_to_send = {"command": "switch_llm_model", "payload": {"model_id": internal_model_id}}
        try:
            # Ensure client loop is running for threadsafe call
            if mcp_client_instance.loop and not mcp_client_instance.loop.is_closed():
                mcp_client_instance.loop.call_soon_threadsafe(
                    mcp_client_instance.client_command_queue.put_nowait,
                    command_to_send
                )
                if dpg.does_item_exist("status_bar_text"):
                    dpg.set_value("status_bar_text", f"Requesting switch to LLM: {selected_display_name}...")
            else:
                logger_gui.error("MCPClient loop not running or closed. Cannot queue LLM switch command.")
                if dpg.does_item_exist("status_bar_text"):
                    dpg.set_value("status_bar_text", "Error: Client loop not active for LLM switch.")
        except Exception as e:
            logger_gui.error(f"Failed to queue 'switch_llm_model' command: {e}", exc_info=True)
            if dpg.does_item_exist("status_bar_text"):
                dpg.set_value("status_bar_text", f"Error queueing LLM switch: {e}")
    elif not internal_model_id:
        logger_gui.error(f"Could not find internal ID for selected LLM display name: {selected_display_name}")
        if dpg.does_item_exist("status_bar_text"):
            dpg.set_value("status_bar_text", f"Error: Invalid LLM selection '{selected_display_name}'.")

# --- NEW: Helper to Update Initiation History Display ---
def _update_initiation_history_display(): # Unchanged
    history_group_tag = "initiation_history_group" 
    if not dpg.does_item_exist(history_group_tag):
        logger_gui.debug(f"Initiation history group tag '{history_group_tag}' does not exist. Cannot update.")
        return

    dpg.delete_item(history_group_tag, children_only=True)
    # Estimate parent width for wrapping. This might need adjustment.
    parent_width = dpg.get_item_width(dpg.get_item_parent(history_group_tag)) or 400 

    if not INITIATION_HISTORY_MESSAGES:
        dpg.add_text("Enter your query below to start a new plan.", parent=history_group_tag, wrap=parent_width - 20)
        return

    for msg in INITIATION_HISTORY_MESSAGES:
        formatted_text = _format_message_for_display(msg) 
        dpg.add_text(formatted_text, parent=history_group_tag, wrap=parent_width - 20)
        dpg.add_separator(parent=history_group_tag)
    
    # Scroll to bottom of initiation history (if possible and desired)
    # DPG doesn't have a direct "scroll to bottom" for a group.
    # If the history is in a child window, you can try setting y_scroll_pos to max.
    # For now, this is omitted for simplicity.

# --- MODIFIED: DPG Callback for Submitting Query ---
def submit_query_dpg_callback(): # Unchanged
    if not mcp_client_instance or not mcp_client_instance.loop or \
       not mcp_client_instance.client_command_queue or mcp_client_instance.loop.is_closed():
        dpg.set_value("status_bar_text", "Error: MCP Client not fully initialized or loop closed.")
        logger_gui.warning("Submit query called but client/loop/queue not ready.")
        INITIATION_HISTORY_MESSAGES.append(SystemMessage(content="GUI Error: MCP Client not ready."))
        _update_initiation_history_display()
        return
    
    query_text = dpg.get_value("query_input_text")
    if not query_text:
        dpg.set_value("status_bar_text", "Error: Query cannot be empty.")
        INITIATION_HISTORY_MESSAGES.append(SystemMessage(content="GUI: Query cannot be empty."))
        _update_initiation_history_display()
        return

    # Add user's query to the INITIATION_HISTORY_MESSAGES
    INITIATION_HISTORY_MESSAGES.append(HumanMessage(content=query_text))
    _update_initiation_history_display() # Update the display

    dpg.set_value("status_bar_text", f"Submitting query: {query_text[:40]}...")
    command_payload = {"query_text": query_text}
    try:
        mcp_client_instance.loop.call_soon_threadsafe(
            mcp_client_instance.client_command_queue.put_nowait,
            {"command": "submit_query", "payload": command_payload}
        )
        dpg.set_value("query_input_text", "") # Clear input field
    except Exception as e:
        dpg.set_value("status_bar_text", f"Error queueing query: {e}")
        logger_gui.error(f"Failed to queue 'submit_query' command: {e}", exc_info=True)
        INITIATION_HISTORY_MESSAGES.append(SystemMessage(content=f"GUI Error: Failed to queue query - {e}"))
        _update_initiation_history_display()


# --- Main DPG Window Setup (MODIFIED for new layout) ---
dpg.create_context()
setup_custom_theme() # Apply theme after context creation

with dpg.window(label="Vishu - Master Control Program Client", tag="main_window"):
    # Main horizontal group for the 3 panels
    with dpg.group(horizontal=True, tag="main_app_layout_group"):
        # --- Left Panel (Chat/Initiation) ---
        with dpg.child_window(tag="left_initiation_panel", width=450): # Adjust width as needed
            dpg.add_text("Agent Interaction")
            dpg.add_separator()
            
            # LLM Selector Dropdown
            # Get display names for the combo box
            llm_display_names = list(AVAILABLE_LLM_MODELS.keys())
            # Find the display name for the default model ID
            default_display_name = DEFAULT_LLM_MODEL_ID # Fallback
            for display, internal_id in AVAILABLE_LLM_MODELS.items():
                if internal_id == DEFAULT_LLM_MODEL_ID:
                    default_display_name = display
                    break
            
            dpg.add_combo(
                items=llm_display_names,
                label="Select LLM",
                default_value=default_display_name, 
                callback=llm_combo_callback,
                tag="llm_model_selector_combo",
                width=-1 
            )
            dpg.add_spacer(height=5)

            # Initiation History Area
            dpg.add_text("Interaction Log:") # Title for this section
            # Child window for scrollable history
            with dpg.child_window(tag="initiation_history_display_child", height=-120): # Leave space for input and button
                dpg.add_group(tag="initiation_history_group") 
                # Initial content will be populated by _update_initiation_history_display

            dpg.add_separator()
            # Query Input Area at the bottom of the left panel
            dpg.add_input_text(tag="query_input_text", hint="Ask me anything. Type @ to add context.", 
                               width=-1, multiline=False, on_enter=True, callback=submit_query_dpg_callback)
            dpg.add_button(label="Send Command / Start Plan", width=-1, callback=submit_query_dpg_callback)

        # --- Center Panel (Plan Tabs) ---
        # Takes remaining width after left and right panels are accounted for.
        # Width calculation: - (left_panel_width + right_panel_width + some_padding_if_any)
        # Example: if left is 450, right is 350, total padding/spacing ~20, then width = - (450+350+20) = -820
        # Or, let DPG manage it by setting width of one panel and the other to -1 relative to that.
        # For simplicity, let's give fixed width to left and right, and center takes the rest.
        with dpg.child_window(tag="plan_details_main_container", width=-370): # - (right_panel_width + spacing)
            dpg.add_tab_bar(tag="plan_display_area")
            # Plan tabs will be added here by _create_or_update_plan_tab

        # --- Right Panel (Tools Overview) ---
        with dpg.child_window(tag="tools_overview_container", width=350):
            dpg.add_text("Available Tools")
            dpg.add_separator()
            with dpg.child_window(tag="tools_overview_list_child", border=False, height=-1): # Fill available height
                dpg.add_group(tag="tools_overview_list") 
                dpg.add_text("Loading tools...", parent="tools_overview_list")

    # Status Bar at the very bottom of the main window
    dpg.add_separator() # Separator above status bar
    dpg.add_text("Status: Initializing...", tag="status_bar_text")

dpg.create_viewport(title='Vishu - MCP Client Interface', width=1800, height=1000) # Adjust as needed
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.set_primary_window("main_window", True)

# Initial population of the initiation history (e.g., with a welcome message)
_update_initiation_history_display() 

client_thread = threading.Thread(target=mcp_client_async_runner, daemon=True)
client_thread.start()

# --- DPG Render Loop (MODIFIED for new GUI events and Initiation History) ---
while dpg.is_dearpygui_running():
    try:
        update_task = gui_update_queue.get_nowait()
        
        if update_task["type"] == "client_ready":
            dpg.set_value("status_bar_text", "MCP Client Ready. Awaiting your command, Creator.")
            _populate_tools_panel() # Populate tools now that client is ready
        elif update_task["type"] == "client_error":
            error_message = f"CLIENT ERROR: {update_task['message']}"
            dpg.set_value("status_bar_text", error_message)
            INITIATION_HISTORY_MESSAGES.append(SystemMessage(content=error_message))
            _update_initiation_history_display()
            if dpg.does_item_exist("tools_overview_list"):
                dpg.delete_item("tools_overview_list", children_only=True)
                dpg.add_text(f"Error loading tools: {update_task['message']}", parent="tools_overview_list", color=(255,100,100))

        elif update_task["type"] == "status_update":
            status_msg = update_task['message']
            dpg.set_value("status_bar_text", status_msg)
            # Add significant status updates (especially errors not tied to a plan) to initiation history
            # This heuristic might need refinement based on events from MCPClient
            if "Error:" in status_msg and not any(p_id in status_msg for p_id in active_plan_ui_elements.keys()):
                if not INITIATION_HISTORY_MESSAGES or \
                   (INITIATION_HISTORY_MESSAGES and INITIATION_HISTORY_MESSAGES[-1].content != status_msg): # Avoid duplicates
                    INITIATION_HISTORY_MESSAGES.append(SystemMessage(content=f"System Status: {status_msg}"))
                    _update_initiation_history_display()

        elif update_task["type"] == "new_plan_created" or update_task["type"] == "plan_update":
            plan_id = update_task["plan_id"]
            plan_data = update_task["plan_data"]
            full_history = update_task["full_history"] # This is the plan's own conversation history
            
            if update_task["type"] == "new_plan_created":
                query_that_led_to_plan = plan_data.get('query', 'Unknown query')
                # Add a message to INITIATION_HISTORY_MESSAGES that a plan was created
                INITIATION_HISTORY_MESSAGES.append(
                    AIMessage(content=f"Plan '{plan_id}' created for query: '{query_that_led_to_plan[:50]}...'. See tab for details.")
                )
                # Optionally add a visual separator in the initiation log
                INITIATION_HISTORY_MESSAGES.append(SystemMessage(content="--- New Interaction Cycle ---"))
                _update_initiation_history_display()

            _create_or_update_plan_tab(plan_id, plan_data, full_history)
            # Focus the newly created or updated tab
            if dpg.does_item_exist(f"tab_{plan_id}"):
                dpg.set_value("plan_display_area", dpg.get_alias_id(f"tab_{plan_id}"))
        
        elif update_task["type"] == "plan_stream_event": 
            plan_id = update_task["plan_id"]
            stream_data_dict = update_task.get("stream_content") 
            if stream_data_dict is not None:
                 _update_plan_streaming_output(plan_id, stream_data_dict) 
        
        elif update_task["type"] == "plan_cleared": 
            plan_id = update_task["plan_id"]
            if plan_id in active_plan_ui_elements:
                tab_tag = active_plan_ui_elements[plan_id].get('tab_tag')
                if tab_tag and dpg.does_item_exist(tab_tag):
                    dpg.delete_item(tab_tag) 
                del active_plan_ui_elements[plan_id]
            INITIATION_HISTORY_MESSAGES.append(SystemMessage(content=f"Plan '{plan_id}' was cleared."))
            _update_initiation_history_display()

        elif update_task["type"] == "all_plans_cleared": 
            for plan_id_key in list(active_plan_ui_elements.keys()):
                tab_tag = active_plan_ui_elements[plan_id_key].get('tab_tag')
                if tab_tag and dpg.does_item_exist(tab_tag):
                    dpg.delete_item(tab_tag)
            active_plan_ui_elements.clear()
            dpg.set_value("status_bar_text", "All plans have been cleared.")
            INITIATION_HISTORY_MESSAGES.append(SystemMessage(content="All plans cleared by user."))
            INITIATION_HISTORY_MESSAGES.append(SystemMessage(content="--- Interaction Reset ---"))
            _update_initiation_history_display()
        
        elif update_task["type"] == "plan_tab_closed": # From MCPClient when a plan is fully removed
            plan_id = update_task["plan_id"]
            message = update_task.get("message", f"Plan '{plan_id}' tab closed.")
            if plan_id in active_plan_ui_elements: 
                tab_tag = active_plan_ui_elements[plan_id].get('tab_tag')
                if tab_tag and dpg.does_item_exist(tab_tag):
                    dpg.delete_item(tab_tag)
                del active_plan_ui_elements[plan_id]
            dpg.set_value("status_bar_text", message)
            INITIATION_HISTORY_MESSAGES.append(SystemMessage(content=message))
            _update_initiation_history_display()

    except queue.Empty:
        pass 
    except Exception as e:
        logger_gui.error(f"Error processing GUI update from queue: {e}", exc_info=True)
        if dpg.does_item_exist("status_bar_text"):
            dpg.set_value("status_bar_text", f"GUI Error: {e}")

    dpg.render_dearpygui_frame()

logger_gui.info("Dear PyGui render loop ended. Cleaning up context.")
dpg.destroy_context()
# --- END OF MODIFIED mcp_client_gui.py ---