# --- START OF COMPLETE streamlit_app.py (with TLS Toggle/Status Integrated) ---
import streamlit as st
import os
import sys
import time
import threading
import queue
import logging
import subprocess # For opening folder
import platform # For opening folder
from collections import deque, defaultdict # Added defaultdict

# --- Add project root to path to import Peer ---
# Assuming peer.py, tracker.py are in the same directory as streamlit_app.py
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# --- Constants ---
MAX_LOG_LINES = 100
AUTO_REFRESH_INTERVAL_SECONDS = 0.5 # How often to refresh UI when connected
CACHE_TTL_SECONDS = max(0.5, AUTO_REFRESH_INTERVAL_SECONDS - 0.5)
# --- Setup Basic Logging for Streamlit App (before Peer potentially overrides) ---
# This logger captures Streamlit-side events and puts them in the queue
streamlit_logger = logging.getLogger("StreamlitApp")
streamlit_logger.setLevel(logging.INFO) # Default level for Streamlit-side logs
log_handler = None # Will be set later if queue exists

# --- Initialize Session State ---
if 'peer_instance' not in st.session_state:
    st.session_state.peer_instance = None
if 'peer_running' not in st.session_state:
    st.session_state.peer_running = False
if 'log_queue' not in st.session_state:
    st.session_state.log_queue = queue.Queue()
if 'log_messages' not in st.session_state:
    st.session_state.log_messages = deque(maxlen=MAX_LOG_LINES) # Fixed-size deque for display
if 'available_files_cache' not in st.session_state:
    st.session_state.available_files_cache = [] # Store {'index': idx, 'hash': file_hash, 'filename': filename, 'size': size}
if 'known_peers_cache' not in st.session_state:
    st.session_state.known_peers_cache = []
# --- ADDED: State for TLS Toggle ---
if 'tls_toggle' not in st.session_state:
    st.session_state.tls_toggle = False
# --- END ADDED ---
if 'downloaded_files_cache' not in st.session_state:
    st.session_state.downloaded_files_cache = []

# --- Configure Streamlit-side Logging Handler ---
class QueueHandler(logging.Handler):
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        try:
             # Avoid putting logs from the handler itself back into the queue
            if record.name == "StreamlitApp" and "QueueHandler" in record.pathname:
                 return
            self.log_queue.put(record)
        except Exception:
            self.handleError(record)

# Ensure handler isn't added multiple times if script reruns unexpectedly
if not any(isinstance(h, QueueHandler) for h in streamlit_logger.handlers):
    log_handler = QueueHandler(st.session_state.log_queue)
    streamlit_logger.addHandler(log_handler)
    # streamlit_logger.info("Streamlit log handler initialized.") # Reduce startup noise

# --- Import Peer (Delayed to allow path setup) ---
PEER_AVAILABLE = False
try:
    from peer import (
        Peer,
        SCRIPT_DIR as PEER_SCRIPT_DIR, # Use Peer's script dir if possible
        DEFAULT_CHUNK_DOWNLOAD_DELAY_SECONDS,
        DEFAULT_MAX_PARALLEL_DOWNLOADS,
        MAX_UNCHOKED_UPLOADS
    )
    PEER_AVAILABLE = True
    streamlit_logger.debug("Peer class imported successfully.")
except ImportError as e:
    st.error(f"Fatal Error: Cannot import Peer class from peer.py: {e}")
    streamlit_logger.critical(f"Fatal Error: Cannot import Peer class from peer.py: {e}", exc_info=True)
    st.stop()
except Exception as e:
    st.error(f"An unexpected error occurred during Peer import: {e}")
    streamlit_logger.critical(f"An unexpected error occurred during Peer import: {e}", exc_info=True)
    st.stop()


# --- Utility Functions ---
def update_logs():
    """Reads logs from the queue and adds them to the display deque."""
    # Log format needs to be consistent for parsing level later
    log_formatter = logging.Formatter('%(asctime)s [%(levelname)-7s] (%(threadName)-10s) %(message)s', datefmt='%H:%M:%S')
    while not st.session_state.log_queue.empty():
        try:
            record = st.session_state.log_queue.get_nowait()
            log_entry = log_formatter.format(record)
            st.session_state.log_messages.appendleft(log_entry) # Prepend for newest first
        except queue.Empty:
            break
        except Exception as e:
            err_msg = f"Log processing error: {e}"
            if not any(err_msg in msg for msg in st.session_state.log_messages):
                 st.session_state.log_messages.appendleft(f"[ERROR] {err_msg}") # Prepend ERROR for visibility
                 print(f"ERROR in update_logs: {e}") # Also print to console

def format_size(size_bytes):
    if not isinstance(size_bytes, (int, float)) or size_bytes < 0:
         return "0 B"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024**2:
        return f"{size_bytes/1024:.2f} KiB"
    elif size_bytes < 1024**3:
        return f"{size_bytes/1024**2:.2f} MiB"
    else:
        return f"{size_bytes/1024**3:.2f} GiB"

def format_speed(bps):
    if not isinstance(bps, (int, float)) or bps <= 0:
        return "0.0 B/s"
    if bps < 1024*8:
        return f"{bps/8:.1f} B/s"
    elif bps < 1024**2*8:
        return f"{bps/(1024*8):.1f} KiB/s"
    else:
        return f"{bps/(1024**2*8):.1f} MiB/s"

def open_folder(path):
    """Opens the specified folder in the native file explorer."""
    try:
        abs_path = os.path.abspath(path)
        if not os.path.isdir(abs_path):
            streamlit_logger.warning(f"Cannot open folder, path not found or not a directory: {abs_path}")
            st.error(f"Directory not found: {abs_path}")
            return False

        if platform.system() == "Windows":
            os.startfile(abs_path)
            return True
        elif platform.system() == "Darwin": # macOS
            subprocess.check_call(["open", "--", abs_path])
            return True
        else: # Linux and other Unix-like
            subprocess.check_call(["xdg-open", "--", abs_path])
            return True
    except FileNotFoundError:
        streamlit_logger.error(f"Could not find command to open folder for platform {platform.system()}. Path: {abs_path}")
        st.error(f"Could not find command to open folder for your OS.")
        return False
    except Exception as e:
        streamlit_logger.error(f"Error opening folder '{abs_path}': {e}", exc_info=True)
        st.error(f"Error opening folder: {e}")
        return False
# --- ADDED: Cached Function for Peer Data ---
@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_cached_peer_ui_data(_peer_instance_id: str) -> dict:
    """
    Fetches potentially expensive status data from the peer instance.
    Uses the peer ID in the function signature to ensure cache invalidation
    if the peer instance changes (e.g., disconnect/reconnect).
    """
    # Check if peer exists and is running within session state
    peer = st.session_state.get('peer_instance')
    if peer and st.session_state.get('peer_running', False):
        # Ensure the ID matches the one passed (paranoid check for cache correctness)
        if not hasattr(peer, 'peer_id') or peer.peer_id != _peer_instance_id:
             streamlit_logger.warning(f"Cache key mismatch? Expected {_peer_instance_id[:8]}, Peer has different ID. Clearing cache.")
             get_cached_peer_ui_data.clear()
             return {"connection": {}, "sharing": {}, "downloads": {}}

        streamlit_logger.debug(f"CACHE MISS: Fetching UI data from peer {_peer_instance_id[:8]}")
        try:
            # Call peer methods safely using hasattr and callable
            conn_status = peer.get_connection_status() if hasattr(peer, 'get_connection_status') and callable(peer.get_connection_status) else {}
            sharing_status = peer.get_sharing_status() if hasattr(peer, 'get_sharing_status') and callable(peer.get_sharing_status) else {}
            download_status = peer.get_download_status() if hasattr(peer, 'get_download_status') and callable(peer.get_download_status) else {}
            # Return combined data
            return {
                "connection": conn_status,
                "sharing": sharing_status,
                "downloads": download_status,
            }
        except Exception as e:
            streamlit_logger.error(f"Error fetching data for cache from peer {_peer_instance_id[:8]}: {e}", exc_info=False)
            # Return empty structure on error to prevent breaking UI
            return {"connection": {}, "sharing": {}, "downloads": {}}
    else:
        # Return empty structure if peer isn't running or doesn't exist
        streamlit_logger.debug(f"Cache function called for {_peer_instance_id[:8]} but peer not running/available.")
        return {"connection": {}, "sharing": {}, "downloads": {}}
# --- END ADDED ---
# --- Peer Control Functions ---
# --- MODIFIED: start_peer accepts use_tls_requested ---
def start_peer(tracker_host, tracker_port, use_tls_requested, allow_insecure_requested):
    """Starts the Peer instance, passing the TLS request and insecure policy."""
    if st.session_state.get('peer_running', False) or st.session_state.get('peer_instance') is not None:
        st.warning("Peer is already running or initialization is in progress.")
        streamlit_logger.warning("Attempted to start peer while already running/initializing.")
        return

    # Reset logs
    st.session_state.log_queue = queue.Queue()
    st.session_state.log_messages = deque(maxlen=MAX_LOG_LINES)
    global log_handler
    # Ensure logger has the handler
    if log_handler and log_handler not in streamlit_logger.handlers:
        streamlit_logger.addHandler(log_handler)

    streamlit_logger.info(f"Attempting to start Peer... TLS Requested: {use_tls_requested}, Allow Insecure Uploads: {allow_insecure_requested}")
    update_logs()

    try:
        # Pass use_tls_requested AND allow_insecure_requested to the Peer constructor
        peer = Peer(
            tracker_host=tracker_host,
            tracker_port=tracker_port,
            use_tls=use_tls_requested,
            allow_insecure_uploads_if_tls=allow_insecure_requested # Pass the new policy
        )

        # Attach UI log handler to Peer's logger if possible
        try:
            if hasattr(peer, 'logger') and isinstance(peer.logger, logging.Logger):
                # Check if handler already added (e.g., by peer's setup)
                # Note: Peer's internal setup_logging doesn't know about the UI handler
                if log_handler not in peer.logger.handlers:
                    peer.logger.addHandler(log_handler)
                    streamlit_logger.info("Attached UI log handler to Peer's logger.")
            else:
                streamlit_logger.warning("Could not attach UI handler: Peer instance or logger invalid.")
        except Exception as log_e:
            streamlit_logger.error(f"Failed to attach log handler to Peer's logger: {log_e}")

        st.session_state.peer_instance = peer
        st.session_state.peer_running = True
        # Use peer's actual ID after successful init
        peer_id = getattr(peer, 'peer_id', 'Unknown')
        peer_ip = getattr(peer, 'ip', '?')
        peer_port = getattr(peer, 'port', '?')
        streamlit_logger.info(f"Peer process initialized. ID: {peer_id[:8]}")
        st.success(f"Peer initialized: {peer_id[:8]} on {peer_ip}:{peer_port}")
        update_logs()
        time.sleep(0.1)
        st.rerun()

    except (IOError, ConnectionError) as e: # Catch specific init errors
        st.error(f"FATAL: Failed to start Peer: {e}", icon="🔥")
        streamlit_logger.critical(f"FATAL: Failed to start Peer: {e}", exc_info=True)
        st.session_state.peer_instance = None
        st.session_state.peer_running = False
        update_logs()
    except Exception as e: # Catch other unexpected errors
        st.error(f"Unexpected error starting Peer: {e}", icon="🔥")
        streamlit_logger.critical(f"Unexpected error starting Peer: {e}", exc_info=True)
        st.session_state.peer_instance = None
        st.session_state.peer_running = False
        update_logs()

def stop_peer():
    """Stops the Peer instance."""
    if not st.session_state.get('peer_running', False) or not st.session_state.get('peer_instance'):
        st.warning("Peer is not running.")
        streamlit_logger.warning("Stop requested but peer not running.")
        return

    streamlit_logger.info("Attempting to stop Peer...")
    update_logs()
    peer_to_stop = st.session_state.peer_instance # Keep reference

    # --- Clear Cache ---
    try:
        if peer_to_stop and hasattr(peer_to_stop, 'peer_id'):
            get_cached_peer_ui_data.clear()
            streamlit_logger.info(f"Cleared UI data cache for peer {peer_to_stop.peer_id[:8]}.")
        else:
            get_cached_peer_ui_data.clear()
            streamlit_logger.warning("Cleared UI data cache without specific peer ID during stop.")
    except NameError:
        streamlit_logger.warning("Cache function 'get_cached_peer_ui_data' not found for clearing during stop.")
    except Exception as cache_err:
        streamlit_logger.warning(f"Could not clear cache during stop: {cache_err}")

    # --- Detach Log Handler ---
    try:
        global log_handler
        if hasattr(peer_to_stop, 'logger') and isinstance(peer_to_stop.logger, logging.Logger):
            if log_handler and log_handler in peer_to_stop.logger.handlers:
                peer_to_stop.logger.removeHandler(log_handler)
                streamlit_logger.info("Detached UI log handler from Peer's logger.")
    except Exception as log_e:
        streamlit_logger.error(f"Error detaching log handler from Peer during stop: {log_e}")

    # --- Call Peer Shutdown (with its own exception handling) ---
    shutdown_error_occurred = False
    try:
        if hasattr(peer_to_stop, 'shutdown') and callable(peer_to_stop.shutdown):
            streamlit_logger.info("Calling peer.shutdown()...")
            peer_to_stop.shutdown() # Peer's shutdown handles its internal logic and logging
            streamlit_logger.info("Peer shutdown method call completed.")
        else:
            streamlit_logger.error("Peer object missing 'shutdown' method.")
            st.error("Peer object missing 'shutdown' method.")
            shutdown_error_occurred = True # Mark error occurred
    except Exception as shutdown_err: # *** Catch errors during the shutdown call itself ***
        st.error(f"Error occurred during peer shutdown: {shutdown_err}")
        streamlit_logger.error(f"Error during peer.shutdown() call: {shutdown_err}", exc_info=True)
        shutdown_error_occurred = True # Mark error occurred

    # --- Clear State (This should always run, regardless of shutdown success) ---
    finally:
        st.session_state.peer_instance = None
        st.session_state.peer_running = False
        # Clear specific caches
        st.session_state.available_files_cache = []
        st.session_state.known_peers_cache = []
        st.session_state.downloaded_files_cache = []
        # Log final status
        if shutdown_error_occurred:
            streamlit_logger.warning("Peer stopped, session state cleared, but errors occurred during shutdown.")
            st.warning("Peer disconnected, but errors occurred during shutdown (check logs).")
        else:
            streamlit_logger.info("Peer stopped successfully and session state cleared.")
            st.info("Peer disconnected.")

        update_logs() # Show final logs
        time.sleep(0.1) # Brief pause before rerun
        st.rerun()

# --- UI Layout ---
st.set_page_config(layout="wide", page_title="TorrentGuard")
st.title("TorrentGuard (with TLS Option)")

update_logs() # Update logs at the beginning of each run

# --- Sidebar ---
with st.sidebar:
    st.header("🔌 Connection")
    if st.session_state.peer_running and st.session_state.peer_instance:
        peer = st.session_state.peer_instance
        st.success(f"Connected as {peer.peer_id[:8]}")

        # --- MODIFIED: Display Actual Connection Status ---
        # --- MODIFIED: Use cached data for sidebar status ---
        sidebar_conn_status = {} # Initialize an empty dict for safety
        peer_id_for_cache = getattr(peer, 'peer_id', None) # Safely get the peer_id

        # Only attempt to get cache if we have a valid peer_id
        if peer_id_for_cache:
            try:
                # Call the cached function *again*. If the cache is valid (within TTL),
                # this returns the stored data instantly without calling the peer methods.
                # If the cache expired, it calls the peer methods and updates the cache.
                sidebar_cached_data = get_cached_peer_ui_data(peer_id_for_cache)
                # Extract the 'connection' part from the cached data
                sidebar_conn_status = sidebar_cached_data.get("connection", {})
            except Exception as sidebar_err:
                st.error("Err fetch status") # Keep UI error brief
                streamlit_logger.error(f"Error fetching sidebar status via cache: {sidebar_err}")
        else:
            # This case should ideally not happen if peer_instance is valid, but handle defensively
            st.warning("Cannot fetch status: Peer ID missing.")
            streamlit_logger.warning("Cannot fetch sidebar status: Peer ID missing from peer object.")

        # Extract status details safely from the sidebar_conn_status dictionary
        actual_tls_status = sidebar_conn_status.get('tls_active', False)
        listening_ip = sidebar_conn_status.get('listening_ip', '?')
        listening_port = sidebar_conn_status.get('listening_port', '?')
        tracker_host = sidebar_conn_status.get('tracker_host', '?')
        tracker_port = sidebar_conn_status.get('tracker_port', '?')

        # Use the extracted variables to display the status
        st.caption(f"Listening: {listening_ip}:{listening_port}")
        st.caption(f"Tracker: {tracker_host}:{tracker_port}")
        if actual_tls_status:
            st.markdown(f"🛡️ **TLS:** <span style='color:limegreen; font-weight:bold;'>ACTIVE</span>", unsafe_allow_html=True)
        else:
            st.markdown(f"🔓 **TLS:** <span style='color:orange; font-weight:bold;'>INACTIVE</span>", unsafe_allow_html=True)
        # --- END MODIFIED ---

        if st.button("Disconnect", type="primary", key="disconnect_button"):
            stop_peer()
    else:
        # --- State when Disconnected ---
        st.info("Not Connected")
        # Default tracker settings
        default_tracker_host = os.getenv("TRACKER_HOST") or "127.0.0.1"
        try: default_tracker_port = int(os.getenv("TRACKER_PORT", 5000))
        except ValueError: default_tracker_port = 5000

        # Input fields for tracker
        tracker_host = st.text_input("Tracker Host", value=default_tracker_host, key="tracker_host_input")
        tracker_port = st.number_input("Tracker Port", min_value=1, max_value=65535, value=default_tracker_port, key="tracker_port_input")

        # --- TLS Toggle Checkbox ---
        # Update the session state based on the UI checkbox interaction
        st.session_state.tls_toggle = st.checkbox(
            "Enable TLS/VPN Security",
            key="tls_checkbox_ui", # Unique key for the UI element
            value=st.session_state.get('tls_toggle', False), # Control its state via session_state
            help="Requires vpn.py and cryptography library. Encrypts peer-to-peer traffic if both peers support it."
        )
        enable_tls = st.session_state.tls_toggle # Use the session state value

        # --- NEW: Checkbox for allowing insecure uploads when TLS is ON ---
        # Initialize state if needed
        if 'allow_insecure_toggle' not in st.session_state:
            st.session_state.allow_insecure_toggle = False

        # Only show this checkbox if TLS is selected
        if enable_tls:
            st.session_state.allow_insecure_toggle = st.checkbox(
                "Allow Insecure Uploads (When TLS Enabled)",
                key="allow_insecure_checkbox_ui",
                value=st.session_state.allow_insecure_toggle,
                help="If checked, this peer (when TLS is ON) will accept incoming plain TCP connections from non-TLS peers. SECURITY RISK!"
            )
            allow_insecure = st.session_state.allow_insecure_toggle
        else:
            # If TLS is off, this policy doesn't apply, default to False conceptually
            allow_insecure = False
            st.session_state.allow_insecure_toggle = False # Reset state if TLS is disabled
            # Optionally disable/hide the checkbox visually:
            # st.checkbox("Allow Insecure Uploads...", disabled=True, help="Only applicable if TLS is enabled.")

        # Connect Button
        if st.button("Connect", key="connect_button"):
            if tracker_host and tracker_port > 0:
                if not st.session_state.get('peer_running', False):
                    # Pass the current state of BOTH toggles to start_peer
                    start_peer(tracker_host, tracker_port, enable_tls, allow_insecure)
                else:
                    st.warning("Peer seems to be running already.")
            else:
                st.warning("Please enter a valid Tracker Host and Port.")

    st.divider()
    st.header("📜 Logs")
    log_level_options = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    # Ensure index is valid, default to INFO if state is bad
    try: default_log_index = log_level_options.index(st.session_state.get('log_level_ui', 'INFO'))
    except ValueError: default_log_index = 1 # Default to INFO

    log_level_str = st.selectbox(
        "Log Level (App UI)",
        log_level_options,
        index=default_log_index,
        key="log_level_select"
    )
    st.session_state['log_level_ui'] = log_level_str # Store selection back into state

    try:
        log_level = getattr(logging, log_level_str.upper(), logging.INFO)
        streamlit_logger.setLevel(log_level)
        # Also set Peer's logger level IF the handler is attached
        if log_handler and st.session_state.peer_instance and hasattr(st.session_state.peer_instance, 'logger'):
            peer_logger = st.session_state.peer_instance.logger
            if log_handler in peer_logger.handlers:
                 peer_logger.setLevel(log_level)
                 streamlit_logger.debug(f"Set Peer logger level to {log_level_str}")

    except AttributeError:
        streamlit_logger.warning(f"Invalid log level string: {log_level_str}")

    # Display Logs
    log_container = st.container(height=300)
    with log_container:
        displayed_logs = list(st.session_state.log_messages)
        for msg in displayed_logs:
             # Use simple string checks for log level keywords for coloring
             lower_msg = msg.lower()
             if "[critical]" in lower_msg: st.error(msg, icon="🔥")
             elif "[error]" in lower_msg : st.error(msg, icon="🔥")
             elif "[warning]" in lower_msg: st.warning(msg, icon="⚠️")
             elif "[debug]" in lower_msg: st.code(msg, language='log') # Use code block for debug clarity
             else: st.text(msg) # Use plain text for INFO and others

# --- Main Area with Tabs (Inside the `if st.session_state.peer_running...` block) ---
if st.session_state.peer_running and st.session_state.peer_instance:
    peer = st.session_state.peer_instance
    # --- Call the cached function ONCE here ---
    cached_data = {}
    peer_id_for_cache = getattr(peer, 'peer_id', None)
    if peer_id_for_cache:
        try:
            cached_data = get_cached_peer_ui_data(peer_id_for_cache)
        except Exception as cache_fetch_err:
             st.error(f"Error fetching UI data: {cache_fetch_err}")
             streamlit_logger.error(f"Error calling get_cached_peer_ui_data: {cache_fetch_err}", exc_info=True)
    else:
        st.error("Cannot fetch UI data: Peer ID missing.")
        streamlit_logger.error("Cannot fetch UI data: Peer ID missing from peer object.")

    # Extract data for easier use in tabs
    conn_status_cached = cached_data.get("connection", {})
    sharing_status_cached = cached_data.get("sharing", {})
    active_downloads_cached = cached_data.get("downloads", {})
    # --- Get local peer's TLS status ---
    my_tls_status = conn_status_cached.get('tls_active', False)

    # --- Get paths safely from peer instance or defaults ---
    base_dir = getattr(peer, 'SCRIPT_DIR', SCRIPT_DIR)
    shared_dir_path = getattr(peer, 'shared_dir_path', os.path.join(base_dir, 'shared_files'))
    downloads_dir_path = getattr(peer, 'downloads_dir_path', os.path.join(base_dir, 'downloads'))
    try:
        start_path = os.getcwd(); shared_dir_rel = os.path.relpath(shared_dir_path, start=start_path); downloads_dir_rel = os.path.relpath(downloads_dir_path, start=start_path)
    except ValueError: shared_dir_rel = shared_dir_path; downloads_dir_rel = downloads_dir_path

    # --- Define Tabs ---
    tab_list, tab_share, tab_download, tab_progress, tab_downloads, tab_peers, tab_choking = st.tabs([
        "List Files", "Share My Files", "Download File", "Progress", "Downloads", "Peers", "Choking"
    ])

    # --- List Files Tab ---
    with tab_list:
        st.subheader("🌎 Files Available on Network")
        if st.button("Refresh File List", key="refresh_list"):
            get_cached_peer_ui_data.clear() # Clear main cache
            st.session_state.available_files_cache = [] # Clear cache
            try:
                streamlit_logger.info("Requesting file list from tracker...")
                with st.spinner("Fetching file list from tracker..."):
                    if not hasattr(peer, 'send_to_tracker_with_retry'):
                         st.error("Peer object missing 'send_to_tracker_with_retry' method.")
                         streamlit_logger.error("Peer object missing 'send_to_tracker_with_retry' method.")
                         st.stop() # Stop execution if peer is broken
                    response = peer.send_to_tracker_with_retry({'type': 'list_files'})
                streamlit_logger.debug(f"Tracker list_files response: {response}")

                if response and isinstance(response, dict) and response.get('status') == 'success':
                    files_dict = response.get('files', {})
                    if files_dict:
                         # Sort files by filename, case-insensitive
                         file_items = sorted(list(files_dict.items()), key=lambda item: item[1].get('filename', '').lower())
                         st.session_state.available_files_cache = [{
                             'index': idx, 'hash': f_hash,
                             'filename': f_info.get('filename', '?'),
                             'size': f_info.get('size', 0),
                             'chunks': f_info.get('chunks', '?') # Use tracker's chunk count if available
                         } for idx, (f_hash, f_info) in enumerate(file_items, 1)]
                         streamlit_logger.info(f"Fetched {len(st.session_state.available_files_cache)} files.")
                         # No need to rerun here, data will display below
                    else:
                        st.info("No files found on the network.")
                        st.session_state.available_files_cache = [] # Ensure cache is cleared
                        streamlit_logger.info("Tracker reported no available files.")
                else:
                    err_msg = response.get('message', 'Unknown tracker error') if isinstance(response, dict) else 'Invalid/No response'
                    st.error(f"Failed to fetch file list: {err_msg}")
                    streamlit_logger.error(f"Failed to fetch file list: {err_msg}. Response: {response}")
                    st.session_state.available_files_cache = []
            except Exception as e:
                st.error(f"Error contacting tracker for file list: {e}")
                streamlit_logger.error(f"Error contacting tracker for file list: {e}", exc_info=True)
                st.session_state.available_files_cache = []
            st.rerun() # Rerun after refresh attempt regardless of outcome

        # Display the cached file list
        if not st.session_state.available_files_cache:
            st.caption("No files listed. Click refresh or check logs.")
        else:
            files_data = [{
                "#": f['index'],
                "Filename": f['filename'],
                "Size": format_size(f.get('size', 0)),
                "Chunks": f.get('chunks', '?'),
                "Hash": f.get('hash', 'N/A')[:12]+"...",
                "_hash_full": f.get('hash', 'N/A') # Store full hash for potential use later
            } for f in st.session_state.available_files_cache]
            st.dataframe(files_data, hide_index=True, use_container_width=True, column_config={"_hash_full": None}) # Hide the full hash column

    # --- Share My Files Tab ---
    with tab_share:
        st.subheader(f"💻 Share Files From `./{shared_dir_rel}`")
        st.caption(f"Full Path: `{shared_dir_path}`")
        try:
            shared_dir_exists = os.path.isdir(shared_dir_path)
            if not shared_dir_exists:
                st.warning(f"Shared directory not found: {shared_dir_path}")
                if st.button("Attempt to Create Shared Directory"):
                    try:
                        os.makedirs(shared_dir_path, exist_ok=True)
                        st.success(f"Created shared directory: {shared_dir_path}")
                        streamlit_logger.info(f"Created shared directory: {shared_dir_path}")
                        st.rerun()
                    except OSError as e:
                        st.error(f"Could not create shared directory: {e}")
                        streamlit_logger.error(f"Could not create {shared_dir_path}: {e}")
            else:
                # List files in the shared directory
                local_files = []
                try:
                    local_files = sorted([f for f in os.listdir(shared_dir_path) if os.path.isfile(os.path.join(shared_dir_path, f)) and not f.endswith('.tmp')], key=str.lower)
                except OSError as e:
                    st.error(f"Error reading shared directory {shared_dir_path}: {e}")
                    streamlit_logger.error(f"Error listing {shared_dir_path}: {e}", exc_info=True)

                if not local_files:
                     st.info(f"No files found in your shared directory (`./{shared_dir_rel}`). Add some files to share.")
                else:
                    # File selection and sharing button
                    selected_files = st.multiselect("Select files in shared directory to share/re-share with tracker:", local_files, key="share_multiselect")
                    if st.button("Share Selected Files", disabled=not selected_files, key="share_button"):
                         with st.spinner("Sharing files with tracker..."):
                             success_count, error_count = 0, 0
                             for filename in selected_files:
                                 filepath = os.path.join(shared_dir_path, filename)
                                 streamlit_logger.info(f"Attempting to share file: {filepath}")
                                 try:
                                     if not hasattr(peer, 'share_file'):
                                         st.error("Peer object missing 'share_file' method."); streamlit_logger.error("Missing 'share_file'"); error_count += len(selected_files); break
                                     if peer.share_file(filepath): success_count += 1; streamlit_logger.info(f"Successfully shared/updated {filename}")
                                     else: error_count += 1; streamlit_logger.warning(f"Peer.share_file returned false for {filename}")
                                 except Exception as e:
                                     error_count += 1; st.error(f"Error sharing {filename}: {e}"); streamlit_logger.error(f"Error calling share_file for {filename}: {e}", exc_info=True)
                         if success_count > 0: st.success(f"Shared/updated {success_count} file(s) with tracker.")
                         if error_count > 0: st.error(f"Failed to share {error_count} file(s) (check logs).")
                         time.sleep(0.5); st.rerun() # Rerun to update the "Currently Shared" list below

            st.divider()
            st.subheader("✅ Files Currently Shared by You (According to Peer State)")
            # Display currently shared files based on peer's internal state
            sharing_status, my_shared_files = {}, {}
            if hasattr(peer, 'get_sharing_status'):
                try:
                    sharing_status = peer.get_sharing_status() or {}
                    my_shared_files = sharing_status_cached.get("shared_files", {})
                except Exception as e:
                    st.error(f"Error getting sharing status: {e}")
                    streamlit_logger.error(f"Error calling get_sharing_status: {e}", exc_info=True)
            else:
                st.warning("Cannot retrieve sharing status from the Peer instance.")

            if not my_shared_files: st.info("You are not currently sharing any files (or status unavailable).")
            else:
                 my_files_data = [{
                     "Filename": info.get('filename','?'), "Size": format_size(info.get('size',0)),
                     "Chunks": info.get('chunks', '?'), "Hash": f_hash[:12]+"..."
                 } for f_hash, info in sorted(my_shared_files.items(), key=lambda item: item[1].get('filename','').lower())]
                 st.dataframe(my_files_data, hide_index=True, use_container_width=True)
        except Exception as e: st.error(f"Error in 'Share My Files' tab: {e}"); streamlit_logger.error(f"Error in Share tab: {e}", exc_info=True)


    # --- Download File Tab (SIGNIFICANT CHANGES) ---
    with tab_download:
        st.subheader("🔽 Download a File from the Network")
        if not st.session_state.available_files_cache:
            st.info("Go to 'List Files' and refresh to see available files.")
        else:
            # Create options for the selectbox
            file_options = {f"{f['index']}. {f.get('filename','?')} ({format_size(f.get('size',0))})": f.get('hash','N/A') for f in st.session_state.available_files_cache}
            valid_file_options = {display: hash_val for display, hash_val in file_options.items() if hash_val != 'N/A'}

            if not valid_file_options:
                st.warning("No valid files with hashes found in the available list.")
            else:
                selected_file_display = st.selectbox("Choose a file to download:", options=list(valid_file_options.keys()), key="download_select")

                if selected_file_display:
                    selected_hash = valid_file_options[selected_file_display]
                    selected_file_info = next((f for f in st.session_state.available_files_cache if f.get('hash') == selected_hash), None)

                    if selected_file_info:
                        default_filename = selected_file_info.get('filename', f"file_{selected_hash[:8]}")
                        downloads_dir_exists = os.path.isdir(downloads_dir_path)

                        # --- Create Downloads Dir if needed ---
                        if not downloads_dir_exists:
                            st.warning(f"Downloads directory not found: {downloads_dir_path}")
                            if st.button("Attempt Create Downloads Dir", key=f"create_dl_dir_{selected_hash}"):
                                try: os.makedirs(downloads_dir_path, exist_ok=True); st.success(f"Created: {downloads_dir_path}"); st.rerun()
                                except OSError as e: st.error(f"Could not create: {e}"); streamlit_logger.error(f"Could not create {downloads_dir_path}: {e}")
                            # Stop further processing in this tab run if dir doesn't exist
                            st.stop()

                        # --- Proceed if Downloads Dir Exists ---
                        save_name = st.text_input("Save as (filename only):", value=default_filename, key=f"save_name_{selected_hash}")
                        col_dl_params1, col_dl_params2 = st.columns(2)
                        with col_dl_params1:
                            default_delay = DEFAULT_CHUNK_DOWNLOAD_DELAY_SECONDS if 'DEFAULT_CHUNK_DOWNLOAD_DELAY_SECONDS' in globals() else 0.0
                            dl_delay = st.number_input("Debug Delay per chunk (s)", 0.0, value=default_delay, step=0.1, format="%.1f", key=f"delay_{selected_hash}")
                        with col_dl_params2:
                            default_parallel = DEFAULT_MAX_PARALLEL_DOWNLOADS if 'DEFAULT_MAX_PARALLEL_DOWNLOADS' in globals() else 4
                            max_parallel = st.number_input("Max parallel chunks", 1, value=default_parallel, step=1, key=f"parallel_{selected_hash}")

                        # --- Fetch Peers & Check TLS Compatibility ---
                        allow_insecure_download = False
                        tls_mismatch_warning = False
                        peer_check_error = None
                        potential_peers = []

                        try:
                            if not hasattr(peer, 'get_peers_for_file'):
                                peer_check_error = "Error: Peer object missing 'get_peers_for_file' method."
                                streamlit_logger.error(peer_check_error)
                            else:
                                streamlit_logger.debug(f"Fetching peers for file {selected_hash[:8]}...")
                                # Use a spinner maybe? Can be slow if tracker is busy.
                                potential_peers, peer_status_msg = peer.get_peers_for_file(selected_hash)
                                if potential_peers is None: # Indicates an error during fetch
                                     peer_check_error = f"Error fetching peer list: {peer_status_msg}"
                                     streamlit_logger.warning(f"get_peers_for_file failed for {selected_hash[:8]}: {peer_status_msg}")
                                     potential_peers = [] # Ensure it's a list even on error
                                else:
                                     # Check for mismatch only if peers were found
                                     if potential_peers:
                                         for p_info in potential_peers:
                                             peer_tls_capable = p_info.get('tls_capable', False)
                                             if peer_tls_capable != my_tls_status:
                                                 tls_mismatch_warning = True
                                                 streamlit_logger.warning(f"TLS Mismatch detected for file {selected_hash[:8]}. Peer {p_info.get('peer_id','?')[:8]} TLS:{peer_tls_capable}, Self TLS:{my_tls_status}")
                                                 break # One mismatch is enough to warn
                                         if not tls_mismatch_warning:
                                             streamlit_logger.debug(f"TLS status compatible with {len(potential_peers)} potential peer(s) for {selected_hash[:8]}.")
                                     else:
                                          streamlit_logger.debug(f"No peers currently found by tracker for file {selected_hash[:8]}.")

                        except Exception as e:
                            peer_check_error = f"Exception fetching peers: {e}"
                            streamlit_logger.error(f"Exception calling get_peers_for_file: {e}", exc_info=True)
                            potential_peers = []

                        # --- Display Warnings/Checkboxes based on TLS check ---
                        if peer_check_error:
                            st.error(peer_check_error)
                        if tls_mismatch_warning:
                            warning_msg = f"⚠️ Potential TLS incompatibility detected! Your TLS status ('{('On' if my_tls_status else 'Off')}') differs from some peers providing this file. Connection may be insecure or fail."
                            st.warning(warning_msg)
                            # Use session state to hold the checkbox state, keyed by hash
                            checkbox_key = f"proceed_insecure_{selected_hash}"
                            if checkbox_key not in st.session_state: st.session_state[checkbox_key] = False
                            st.session_state[checkbox_key] = st.checkbox(
                                "Proceed with potentially incompatible TLS?",
                                key=checkbox_key + "_ui", # Unique UI key
                                value=st.session_state[checkbox_key], # Controlled value
                                help="Allows download attempt even if TLS settings don't match all peers."
                            )
                            allow_insecure_download = st.session_state[checkbox_key]
                        elif not peer_check_error and not potential_peers:
                             st.info("ℹ️ No peers currently listed for this file. Download will start and wait for peers.")
                             allow_insecure_download = True # Allow starting even if no peers yet
                        elif not peer_check_error and not tls_mismatch_warning:
                             st.success("✅ TLS status is compatible with known peers.")
                             allow_insecure_download = True # Compatible or no peers, allow download start

                        # --- File Existence and Overwrite Logic ---
                        sanitized_name = default_filename
                        if save_name:
                            temp_sanitized = save_name.replace('/', '_').replace('\\', '_')
                            valid_chars = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; temp_sanitized = "".join(c for c in temp_sanitized if c in valid_chars).strip()
                            sanitized_name = temp_sanitized or f"download_{selected_hash[:8]}"

                        save_path = os.path.join(downloads_dir_path, sanitized_name)
                        temp_path = save_path + '.tmp'
                        file_exists, temp_exists = os.path.exists(save_path), os.path.exists(temp_path)
                        allow_proceed_if_exists = False

                        if file_exists or temp_exists:
                            st.warning(f"File '{sanitized_name}' or `.tmp` already exists.")
                             # Use session state for overwrite checkbox too
                            overwrite_key = f"overwrite_cb_{selected_hash}"
                            if overwrite_key not in st.session_state: st.session_state[overwrite_key] = False
                            st.session_state[overwrite_key] = st.checkbox(
                                "Confirm Overwrite/Resume?",
                                key=overwrite_key + "_ui",
                                value=st.session_state[overwrite_key],
                                help="Overwrites final file or resumes from .tmp."
                            )
                            allow_proceed_if_exists = st.session_state[overwrite_key]

                        # --- Determine if Download Button Should Be Enabled ---
                        # Conditions:
                        # 1. No peer check error occurred.
                        # 2. EITHER TLS is compatible/no peers OR user confirmed insecure download.
                        # 3. EITHER file doesn't exist OR user confirmed overwrite/resume.
                        enable_download_button = (
                            not peer_check_error and
                            allow_insecure_download and
                            (not (file_exists or temp_exists) or allow_proceed_if_exists)
                        )

                        # --- Start Download Button ---
                        if st.button("Start Download", key=f"start_dl_{selected_hash}", disabled=not enable_download_button):
                            if not save_name: st.warning("Please enter a filename."); # Should be caught by disabled state, but safety check
                            elif not enable_download_button: st.warning("Cannot start download. Check warnings above or confirm overwrite/insecure connection.")
                            else:
                                # All checks passed, initiate download
                                streamlit_logger.info(f"Proceeding with download initiation: '{sanitized_name}' (Hash: {selected_hash[:8]})")
                                try:
                                    if not hasattr(peer, 'download_file'): st.error("Peer missing 'download_file'"); streamlit_logger.error("Missing 'download_file'")
                                    else:
                                        with st.spinner(f"Initiating download for '{sanitized_name}'..."):
                                            success = peer.download_file(
                                                file_hash=selected_hash, save_path=os.path.abspath(save_path),
                                                download_delay=dl_delay, max_parallel=max_parallel
                                            )
                                        if success:
                                            st.success(f"Download initiated/resumed for '{sanitized_name}'. Check Progress tab."); streamlit_logger.info(f"Download initiated/resumed: {sanitized_name}")
                                            # Clear confirmation checkboxes after successful start
                                            if f"proceed_insecure_{selected_hash}" in st.session_state: st.session_state[f"proceed_insecure_{selected_hash}"] = False
                                            if f"overwrite_cb_{selected_hash}" in st.session_state: st.session_state[f"overwrite_cb_{selected_hash}"] = False
                                            time.sleep(0.5); st.rerun() # Rerun to clear inputs/checkboxes
                                        else: st.error("Failed to initiate download (check logs)."); streamlit_logger.error(f"peer.download_file returned false for {sanitized_name}")
                                except Exception as e: st.error(f"Error initiating download: {e}"); streamlit_logger.error(f"Error calling download_file: {e}", exc_info=True)

    # --- Progress Tab (No significant changes needed based on request, but check cancel logic) ---
    with tab_progress:
        # [ Existing Progress Tab Code - Ensure cancel_download error handling is robust ]
        # The cancel logic provided in the previous prompt looks reasonable.
        # Make sure the try/except around peer.cancel_download is present.
        st.subheader("📊 Live Download Progress")
        active_downloads = active_downloads_cached
        if not active_downloads: st.info("No active downloads. Check the 'Downloads' tab for completed files.")
        else:
            sorted_downloads = sorted(active_downloads.items(), key=lambda item: item[1].get('filename', ''))
            for file_hash, info in sorted_downloads:
                if not isinstance(info, dict): continue
                try:
                    filename=info.get('filename',f'F_{file_hash[:8]}'); total_size=info.get('total_size',0); state=info.get('state','?').upper()
                    progress_percent=info.get('progress_percent',0.0); speed_str=format_speed(info.get('current_speed_bps',0.0))
                    workers=info.get('active_workers',0); max_cfg=info.get('max_parallel','?'); status_counts=info.get('status_counts',{})
                    chunk_objects=info.get('chunk_objects',[]); total_chunks=info.get('total_chunks',len(chunk_objects))

                    st.markdown(f"**{filename}** ({format_size(total_size)}) - **{state}**")
                    prog_val=max(0.0,min(1.0,progress_percent/100.0)); st.progress(prog_val,text=f"{progress_percent:.1f}%")
                    cols=st.columns(4)
                    cols[0].metric("Speed", speed_str)
                    cols[1].metric("Workers", f"{workers}/{max_cfg}")
                    s_parts=[]; sc=status_counts;
                    if sc.get('complete',0)>0: s_parts.append(f"C:{sc['complete']}")
                    if sc.get('downloading',0)>0: s_parts.append(f"D:{sc['downloading']}")
                    if sc.get('needed',0)>0: s_parts.append(f"N:{sc['needed']}")
                    if sc.get('failed',0)>0: s_parts.append(f"F:{sc['failed']}")
                    s_detail=", ".join(s_parts) or "N/A";
                    cols[2].metric("Chunks", s_detail, delta=f"/ {total_chunks}" if isinstance(total_chunks,int) else "")

                    with cols[3]:
                        cancel_err_flag = False # Flag to check if cancel itself failed
                        if state in ["DOWNLOADING", "FINDING_PEERS", "PROCESSING", "UNKNOWN", "FAILED"]:
                            st.markdown('<div style="margin-top: 28px;"></div>', unsafe_allow_html=True)
                            if st.button("Cancel", key=f"cancel_dl_{file_hash}", type="secondary", use_container_width=True):
                                streamlit_logger.info(f"User cancel request: {file_hash[:8]}")
                                cancelled = False
                                if hasattr(peer, 'cancel_download') and callable(peer.cancel_download):
                                    try:
                                        with st.spinner(f"Cancelling '{filename}'..."):
                                            cancelled = peer.cancel_download(file_hash)
                                    except Exception as cancel_err:
                                        st.error(f"Error during cancel: {cancel_err}")
                                        streamlit_logger.error(f"Error calling cancel_download for {file_hash[:8]}: {cancel_err}", exc_info=True)
                                        cancel_err_flag = True # Set flag if cancel itself raised error

                                    if not cancel_err_flag: # Only process result if cancel call didn't crash
                                        if cancelled:
                                            st.success(f"Cancelled '{filename}'.")
                                            get_cached_peer_ui_data.clear(); time.sleep(0.5); st.rerun()
                                        else:
                                            st.warning(f"Could not cancel '{filename}' (Peer returned false).")
                                else:
                                    st.error("Peer missing 'cancel_download' method.")
                                    streamlit_logger.error("Peer missing 'cancel_download' method.")
                        else: st.write("") # Placeholder

                    with st.expander(f"Chunk Details ({len(chunk_objects)})"):
                        if not chunk_objects: st.caption("N/A.")
                        else:
                            c_data = []; sorted_chunks = sorted(chunk_objects, key=lambda c: c.get('index', -1))
                            for chunk in sorted_chunks:
                                p_id=chunk.get('completed_by_peer', chunk.get('last_tried_peer',None))
                                c_data.append({"Idx":chunk.get('index','?'),"Status":chunk.get('status','?').upper(),"Size":format_size(chunk.get('size',0)),"Peer":f"{p_id[:8]}..." if p_id else "N/A"})
                            h=(min(len(c_data),10)+1)*35+3; st.dataframe(c_data, hide_index=True, use_container_width=True, height=h)
                    st.divider()
                except Exception as e: st.error(f"Error display progress for {filename}: {e}"); streamlit_logger.error(f"Error display progress {file_hash[:8]}: {e}", exc_info=True)

    # --- Downloads Tab (Completed Files) ---
    with tab_downloads:
        st.subheader("📁 Completed Downloads")
        st.caption(f"Location: `{downloads_dir_path}`")

        col1_dl, col2_dl = st.columns([3, 1])
        with col1_dl:
             if st.button("Refresh Downloaded List", key="refresh_completed"):
                 get_cached_peer_ui_data.clear() # Clear main cache
                 st.session_state.downloaded_files_cache = [] # Clear cache
                 st.rerun() # Force reload of the list from disk
        with col2_dl:
             if st.button("Open Downloads Folder", key="open_dl_folder"):
                  open_folder(downloads_dir_path)

        # Populate cache if empty by reading the directory
        if not st.session_state.downloaded_files_cache:
            st.session_state.downloaded_files_cache = []
            try:
                if os.path.isdir(downloads_dir_path):
                    for filename in os.listdir(downloads_dir_path):
                         # Ignore temp files
                         if not filename.endswith('.tmp'):
                            filepath = os.path.join(downloads_dir_path, filename)
                            if os.path.isfile(filepath):
                                try:
                                    size = os.path.getsize(filepath)
                                    st.session_state.downloaded_files_cache.append({'filename': filename, 'size': size, 'path': filepath})
                                except OSError: continue # Skip files we can't get size for
                    # Sort by filename after populating
                    st.session_state.downloaded_files_cache.sort(key=lambda x: x['filename'].lower())
                # else: Directory doesn't exist yet, list will be empty
            except OSError as e:
                st.error(f"Error accessing downloads directory: {e}")
                streamlit_logger.error(f"Error listing downloads directory {downloads_dir_path}: {e}")

        # Display the cached list
        if not st.session_state.downloaded_files_cache: st.info("No completed downloads found.")
        else:
             downloads_data = [{"Filename": f['filename'], "Size": format_size(f['size'])} for f in st.session_state.downloaded_files_cache]
             st.dataframe(downloads_data, hide_index=True, use_container_width=True)

    # --- Peers Tab ---
    with tab_peers:
        st.subheader("👥 Known Peers (From Tracker)")
        if st.button("Refresh Peer List", key="refresh_peers"):
            get_cached_peer_ui_data.clear() # Clear main ca
            st.session_state.known_peers_cache = [] # Clear cache on refresh
            try:
                streamlit_logger.info("Requesting peer list from tracker...")
                with st.spinner("Fetching peer list..."):
                     if not hasattr(peer, 'send_to_tracker_with_retry'): st.error("Missing 'send_to_tracker_with_retry'"); st.stop()
                     # Use 'list_peers' type if tracker supports it, otherwise might need 'get_peers' without chunk hash
                     response = peer.send_to_tracker_with_retry({'type': 'list_peers', 'peer_id': peer.peer_id})
                streamlit_logger.debug(f"Tracker list_peers response: {response}")
                if response and isinstance(response, dict) and response.get('status') == 'success':
                     fetched_peers = response.get('peers', [])
                     self_id = peer.peer_id
                     # Filter out self and ensure entries are dicts
                     st.session_state.known_peers_cache = [p for p in fetched_peers if isinstance(p, dict) and p.get('peer_id') != self_id]
                     streamlit_logger.info(f"Fetched {len(st.session_state.known_peers_cache)} other peers.")
                else:
                    err_msg = response.get('message', 'Unknown error') if isinstance(response, dict) else 'Invalid/No response'
                    st.error(f"Failed to fetch peer list: {err_msg}"); streamlit_logger.error(f"Failed peer list: {err_msg}. Resp: {response}"); st.session_state.known_peers_cache = []
            except Exception as e: st.error(f"Error contacting tracker for peer list: {e}"); streamlit_logger.error(f"Error getting peer list: {e}", exc_info=True); st.session_state.known_peers_cache = []
            st.rerun() # Rerun after attempt

        # Display cached peer list
        if not st.session_state.known_peers_cache: st.caption("No other peers listed by tracker.")
        else:
             peers_data = []
             for p in st.session_state.known_peers_cache:
                 if isinstance(p, dict): # Validate entry structure
                     peers_data.append({
                         "Peer ID": p.get('peer_id', 'N/A')[:12]+"...", # Shorten ID
                         "Address": f"{p.get('ip','?')}:{p.get('port','?')}",
                         "TLS Capable": "Yes" if p.get('tls_capable', False) else "No",
                     })
                 else: streamlit_logger.warning(f"Invalid peer entry received from tracker: {p}")
             if peers_data: st.dataframe(peers_data, hide_index=True, use_container_width=True)
             else: st.info("Peer list received was empty or contained invalid entries.")

    # --- Choking Tab ---
    with tab_choking:
        st.subheader("🚦 Upload Choking Status")
        max_unchoked_val = MAX_UNCHOKED_UPLOADS if 'MAX_UNCHOKED_UPLOADS' in globals() else '?'
        st.metric("Regular Upload Slots (Max Unchoked)", max_unchoked_val)
        st.caption("(Plus one additional slot for Optimistic Unchoking)")
        if st.button("Refresh Choking Info", key="refresh_choking"):
             get_cached_peer_ui_data.clear() # Clear main ca
             streamlit_logger.debug("Manual refresh choking"); 
             st.rerun()

        # Get choking status from peer
        sharing_status, choking_info = {}, {}
        if hasattr(peer, 'get_sharing_status'):
             try: sharing_status = peer.get_sharing_status() or {}; choking_info = sharing_status_cached.get("choking_info", {})
             except Exception as e: st.error(f"Error getting sharing status: {e}"); streamlit_logger.error(f"Error calling get_sharing_status: {e}", exc_info=True)
        else: st.warning("Cannot retrieve sharing/choking status.")

        # Safely extract data from choking_info
        unchoked_set = set(choking_info.get('unchoked_peers', []))
        optimistic_id = choking_info.get('optimistic_unchoke', None)
        interested_list = choking_info.get('interested_peers', [])
        dl_stats = choking_info.get('dl_stats', {}) # peer_id -> rate_bps
        ul_stats = choking_info.get('ul_stats', {}) # peer_id -> rate_bps

        # Display Unchoked Peers
        st.markdown("---"); st.markdown("**Currently Unchoked Peers (Uploading To):**")
        if not unchoked_set: st.info("Not actively uploading to any peers.")
        else:
            unchoked_data = []
            # Sort by download rate from them (higher rate = higher priority)
            sorted_unchoked = sorted(list(unchoked_set), key=lambda pid: dl_stats.get(str(pid), 0.0), reverse=True)
            for pid in sorted_unchoked:
                pid_str = str(pid) # Ensure string keys for dict lookups
                rate_from_bps = dl_stats.get(pid_str, 0.0)
                rate_to_bps = ul_stats.get(pid_str, 0.0)
                reason = "Optimistic" if pid_str == optimistic_id else "Rate-Based"
                unchoked_data.append({
                    "Peer ID": pid_str[:12]+"...", "Unchoke Reason": reason,
                    "DL Rate From Them": format_speed(rate_from_bps),
                    "UL Rate To Them": format_speed(rate_to_bps) # Show our upload rate to them
                })
            st.dataframe(unchoked_data, hide_index=True, use_container_width=True)

        # Display Interested Peers
        st.markdown("---"); st.markdown("**Interested Peers (Want Chunks, Might Be Choked):**")
        if not interested_list: st.info("No peers currently interested in data from us.")
        else:
            interested_data = []
            # Sort interested peers by download rate from them as well
            sorted_interested = sorted(interested_list, key=lambda pid: dl_stats.get(str(pid), 0.0), reverse=True)
            for pid in sorted_interested:
                 pid_str = str(pid)
                 status = "UNCHOKED" if pid_str in unchoked_set else "CHOKED"
                 dl_rate_bps = dl_stats.get(pid_str, 0.0)
                 ul_rate_bps = ul_stats.get(pid_str, 0.0)
                 interested_data.append({
                     "Peer ID": pid_str[:12]+"...", "Upload Status": status,
                     "DL Rate From Them": format_speed(dl_rate_bps), # How fast we download from them
                     "UL Rate To Them": format_speed(ul_rate_bps) # How fast we upload to them (if unchoked)
                 })
            st.dataframe(interested_data, hide_index=True, use_container_width=True)

    # --- Auto Refresh Logic ---
    if st.session_state.peer_running: time.sleep(AUTO_REFRESH_INTERVAL_SECONDS); st.rerun()

# --- Footer/Instructions When Not Connected ---
elif not PEER_AVAILABLE:
    # Error message handled during import check
    pass
else:
    # Displayed when peer is not running
    st.info("ℹ️ Connect to a tracker using the sidebar to begin.")
    default_tracker_host = os.getenv("TRACKER_HOST") or "127.0.0.1"
    try: default_tracker_port = int(os.getenv("TRACKER_PORT", 5000))
    except ValueError: default_tracker_port = 5000
    st.markdown(f"""
        **Instructions:**

        1.  **Run Tracker:** Ensure `tracker.py` is running (`python tracker.py`).
        2.  **Configure Connection:** Enter the tracker's host/port in the sidebar.
        3.  **(Optional) Enable TLS:** Check the box to secure peer connections (requires `vpn.py` & `cryptography`).
        4.  **Connect:** Click 'Connect' to start the peer client.
        5.  **Share Files:** Place files you want to share into the `shared_files` directory (it will be created if needed). Use the 'Share My Files' tab to select and publish them.
        6.  **Download:** Use 'List Files' to see network files, then 'Download File' to select and start downloading to the `downloads` directory.
        7.  **Monitor:** Check 'Progress', 'Peers', and 'Choking' tabs.
        8.  **Disconnect:** Use the 'Disconnect' button in the sidebar to shut down gracefully.
    """)
    st.warning("Ensure `peer.py`, `tracker.py`, and `vpn.py` (if using TLS) are compatible and in the same directory.")

# --- END OF COMPLETE streamlit_app.py ---