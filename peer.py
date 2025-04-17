# --- START OF peer.py (v2.3 - Streamlit Focused) ---
import os
import socket
import threading
import json
import hashlib
import random
import time
from collections import defaultdict
import sys
import traceback
import logging
import platform
import ssl
from typing import Dict, List, Set, Tuple, Optional
import struct # For socket options like SO_LINGER

# --- Determine Script Directory ---
try:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    SCRIPT_DIR = os.path.abspath(os.getcwd())
    # Use print for initial setup errors before logger is ready
    print(f"Warning: Could not determine script directory using __file__. Using CWD: {SCRIPT_DIR}")
    print("         Ensure 'logs', 'shared_files', 'downloads', and 'vpn.py' are relative.")

# --- VPN Integration ---
VPN_AVAILABLE = False
CRYPTOGRAPHY_AVAILABLE = False
try:
    # Temporarily add SCRIPT_DIR to path for import
    original_sys_path = list(sys.path)
    if SCRIPT_DIR not in sys.path:
        sys.path.insert(0, SCRIPT_DIR)

    import vpn
    VPN_AVAILABLE = True
    try:
        from cryptography import x509 # Check dependency explicitly
        CRYPTOGRAPHY_AVAILABLE = True
    except ImportError:
        print("INFO: cryptography library not found. TLS disabled.")

    # Restore original sys.path
    sys.path = original_sys_path

except ImportError:
    sys.path = original_sys_path # Ensure path is restored even if vpn import fails
    print("INFO: vpn.py not found or failed to import. TLS disabled.")
except Exception as import_err:
    sys.path = original_sys_path # Ensure path is restored on any error
    print(f"ERROR during VPN/Crypto check: {import_err}. TLS disabled.")


# --- Config Constants ---
CHUNK_SIZE = 1024 * 256
TRACKER_RETRIES = 3
BASE_TIMEOUT = 15
MAINTENANCE_INTERVAL = 10 # Check maintenance tasks every 10s
SPEED_CALC_INTERVAL = 5 # Calculate download speed every 5s
MAX_UNCHOKED_UPLOADS = 4
OPTIMISTIC_UNCHOKE_INTERVAL = 30
CHOKE_RECALC_INTERVAL = 10
DEFAULT_CHUNK_DOWNLOAD_DELAY_SECONDS = 0.0
DEFAULT_MAX_PARALLEL_DOWNLOADS = 4
INITIAL_FAILED_CHUNK_RESET_DELAY = 10 # Seconds before first check for failed chunks
PEER_LIST_REFRESH_INTERVAL = 60 # Seconds (e.g., refresh full list every minute)

# --- File Locking ---
if platform.system() == 'Windows':
    try:
        import msvcrt
        def lock_file(file):
            try: 
                msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
            except (ImportError, OSError, AttributeError, ValueError): 
                pass
        def unlock_file(file):
            try: 
                msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
            except (ImportError, OSError, AttributeError, ValueError): 
                pass
    except ImportError: 
        def lock_file(file): 
            pass
        def unlock_file(file): 
            pass
else:
    try:
        import fcntl
        def lock_file(file):
            try: 
                fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (ImportError, OSError, AttributeError, ValueError): 
                pass
        def unlock_file(file):
            try: 
                fcntl.flock(file.fileno(), fcntl.LOCK_UN)
            except (ImportError, OSError, AttributeError, ValueError): 
                pass
    except ImportError: 
        def lock_file(file): 
            pass
        def unlock_file(file): 
            pass

# --- Peer Class ---
class Peer:
# --- START OF MODIFIED __init__ ---
    # MODIFIED: Added allow_insecure_uploads_if_tls parameter
    def __init__(self, tracker_host='localhost', tracker_port=5000, use_tls: bool = False, allow_insecure_uploads_if_tls: bool = False):
        """Initializes the Peer instance."""
        self.peer_id = hashlib.sha1(str(random.random()).encode()).hexdigest()
        self.running = True
        self.logger = self.setup_logging() # Call without arguments
        self.lock = threading.Lock()

        # --- MOVE THIS BLOCK EARLIER ---
        # File/Download State (Initialize core state variables early)
        self.shared_files: Dict[str, Dict] = {} # Keyed by absolute path
        self.available_chunks: Set[str] = set() # Hashes of chunks this peer has
        self.downloads: Dict[str, Dict] = {} # Keyed by file_hash being downloaded
        self.chunk_sources: Dict[str, Set[str]] = defaultdict(set) # chunk_hash -> {file_hash, ...}
        # Known Peers from tracker (Initialize here as well)
        self.peers: Dict[str, Dict] = {} # {peer_id: {'ip': ..., 'port': ..., 'tls_capable':..., 'last_seen': ...}}
        # --- END MOVED BLOCK ---

        # Paths (Relative to Script) - Define BEFORE TLS setup uses certs_dir_path
        self.shared_dir_path = os.path.join(SCRIPT_DIR, 'shared_files')
        self.downloads_dir_path = os.path.join(SCRIPT_DIR, 'downloads')
        self.certs_dir_path = os.path.join(SCRIPT_DIR, 'certs')
        # Now it's safe to call setup_directories which calls cleanup_temp_files
        self.setup_directories() # Create directories including certs (BEFORE TLS init)

        # --- Configuration dependent on TLS setup ---
        self.use_tls = False # Final state after checks
        # NEW: Policy for TLS server behavior
        self.allow_insecure_uploads_if_tls = False # Final state after checks
        self.server_ssl_context = None
        self.client_ssl_context = None

        # Attempt TLS setup if requested *and* possible
        if use_tls and VPN_AVAILABLE and CRYPTOGRAPHY_AVAILABLE:
            self.logger.info("Attempting to initialize TLS as requested...")
            try:
                # Pass peer_id for certificate generation/lookup and the certs path
                if vpn.ensure_self_signed_cert(self.peer_id, self.certs_dir_path): # Already Correct
                    # --- MODIFIED CALLS ---
                    self.server_ssl_context = vpn.create_server_context(self.certs_dir_path, self.peer_id) # Pass peer_id
                    self.client_ssl_context = vpn.create_client_context(self.certs_dir_path) # Pass certs_dir (peer_id not needed unless loading peer-specific CAs)
                    # --- END MODIFIED CALLS ---
                    if self.server_ssl_context and self.client_ssl_context:
                        self.use_tls = True # Mark TLS as successfully enabled
                        # Set the policy based on the input parameter ONLY if TLS is enabled
                        self.allow_insecure_uploads_if_tls = allow_insecure_uploads_if_tls
                        self.logger.info(f"TLS contexts created successfully. TLS ENABLED. Allow Insecure Uploads: {self.allow_insecure_uploads_if_tls}")
                    else:
                         self.logger.warning("Failed to create TLS contexts. TLS remains DISABLED.")
                else:
                     self.logger.warning("Failed to ensure self-signed certificate. TLS remains DISABLED.")
            except Exception as tls_err:
                 self.logger.error(f"Error during TLS initialization: {tls_err}. TLS remains DISABLED.", exc_info=True)
                 self.logger.error(f"Error during TLS initialization: {tls_err}. TLS remains DISABLED.", exc_info=True)
        elif use_tls:
            if not VPN_AVAILABLE: self.logger.warning("TLS requested but vpn.py is missing. TLS DISABLED.")
            if not CRYPTOGRAPHY_AVAILABLE: self.logger.warning("TLS requested but cryptography library is missing. TLS DISABLED.")

        # Ensure policy is False if TLS ended up disabled
        if not self.use_tls:
            self.allow_insecure_uploads_if_tls = False # Cannot allow insecure if TLS isn't even on

        # Network Info
        self.ip = self.get_local_ip()
        self.port = None
        for attempt in range(3):
             self.port = self._find_available_port(5001, 6000)
             if self.port is not None:
                 self.logger.info(f"Successfully found port {self.port} on attempt {attempt+1}.")
                 break
             self.logger.warning(f"Failed to find available port on attempt {attempt+1}, retrying...")
             time.sleep(0.2 + random.uniform(0, 0.1)) # Small random delay
        if self.port is None:
            # Critical error if no port found
            self.logger.critical("FATAL: No available port found for peer after multiple attempts.")
            raise IOError("FATAL: No available port found for peer after multiple attempts.")

        # Tracker Info
        self.tracker_host = tracker_host
        self.tracker_port = tracker_port

        # Server Socket Setup
        self.server_socket = self.setup_server_socket()
        if not self.server_socket:
            self.logger.critical("FATAL: Server socket setup failed.")
            raise ConnectionError("FATAL: Server socket setup failed.")

        # Choking/Unchoking State
        self.unchoked_upload_peers: Set[str] = set() # Peers we are currently uploading to
        self.peer_upload_stats = defaultdict(lambda: {'bytes_up_interval': 0, 'rate_bps': 0.0}) # Our upload rate TO peers
        self.peer_download_stats = defaultdict(lambda: {'bytes_down_interval': 0, 'rate_bps': 0.0}) # Our download rate FROM peers
        self.interested_peers: Dict[str, float] = {} # Peers interested in data *from us* (peer_id -> last_seen_time)
        self.last_choke_recalc_time = time.time()
        self.last_optimistic_unchoke_time = time.time()
        self.optimistic_unchoke_peer: Optional[str] = None # Peer chosen for optimistic unchoke

        # Initial State & Registration with Tracker
        self.register_with_tracker()
        # self.initialize_shared_files() # Scan shared dir and publish initial files - this should be safe here

        # Start Background Threads
        threading.Thread(target=self.accept_connections, name="Acceptor", daemon=True).start()
        threading.Thread(target=self.maintenance_tasks, name="Maintenance", daemon=True).start()
        self.logger.info(f"Peer initialized: ID {self.peer_id[:8]} listening on {self.ip}:{self.port}")

    # --- Add this helper function right after __init__ or with other helpers ---
    def setup_logging(self, logger_name: str):
        """Configures logging for the peer instance."""
        logger = logging.getLogger(logger_name)
        if getattr(logger, '_configured', False):
             print(f"Warning: Logger '{logger_name}' already configured.")
             return logger
        logger.setLevel(logging.DEBUG)
        if logger.hasHandlers(): logger.handlers.clear()
        # Define certs_dir_path here or ensure it's defined before logger setup if needed elsewhere early
        # For now, log dir is independent
        log_dir_path = os.path.join(SCRIPT_DIR, 'logs')
        log_file_path = None
        try:
            os.makedirs(log_dir_path, exist_ok=True)
            # Include PID in log filename to avoid conflicts if multiple peers run from same dir
            log_file_path = os.path.join(log_dir_path, f'p2p_{logger_name}.log')
        except OSError as e:
             print(f"ERROR: Could not create log directory '{log_dir_path}': {e}. Console only.")

        formatter = logging.Formatter('%(asctime)s [%(levelname)-7s] (%(threadName)-10s) %(message)s')
        if log_file_path:
            try:
                file_handler = logging.FileHandler(log_file_path, mode='w', encoding='utf-8')
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except Exception as e:
                print(f"ERROR: Could not create file handler '{log_file_path}': {e}. Console only.")
                log_file_path = None
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        if VPN_AVAILABLE: logging.getLogger('vpn').setLevel(logging.WARNING)
        if log_file_path: print(f"--- {logger_name} logging to console and file: {os.path.basename(log_file_path)} ---")
        else: print(f"--- {logger_name} logging to console ONLY ---")
        logger.propagate = False
        logger._configured = True
        return logger


    def get_connection_status(self) -> Dict:
        """
        Returns basic connection status including Peer ID, address, tracker,
        and whether TLS is currently active.
        """
        with self.lock: # Ensure thread safety reading self.use_tls
            return {
                "peer_id": self.peer_id,
                "listening_ip": self.ip,
                "listening_port": self.port,
                "tracker_host": self.tracker_host,
                "tracker_port": self.tracker_port,
                "tls_active": self.use_tls # Read the current state of TLS activation
            }
        

    def setup_logging(self): # Keep this version (inside the class)
        """Configures logging for the peer instance."""
        # Unique logger name per instance/process
        logger_name = f"Peer-{self.peer_id[:8]}-{os.getpid()}"
        logger = logging.getLogger(logger_name)

        # Avoid reconfiguring if logger already exists (e.g., due to unexpected re-init)
        if getattr(logger, '_configured', False):
             print(f"Warning: Logger '{logger_name}' already configured.")
             return logger

        logger.setLevel(logging.DEBUG) # Set base level low; actual filtering done by handlers
        if logger.hasHandlers(): logger.handlers.clear() # Clear existing handlers if any

        log_dir_path = os.path.join(SCRIPT_DIR, 'logs')
        log_file_path = None
        try:
            os.makedirs(log_dir_path, exist_ok=True)
            log_file_path = os.path.join(log_dir_path, f'p2p_{self.peer_id[:8]}_{os.getpid()}.log')
        except OSError as e:
             print(f"ERROR: Could not create log directory '{log_dir_path}': {e}. Console only.")

        formatter = logging.Formatter('%(asctime)s [%(levelname)-7s] (%(threadName)-10s) %(message)s')

        # File Handler
        if log_file_path:
            try:
                # Use 'w' mode to overwrite log on each start
                file_handler = logging.FileHandler(log_file_path, mode='w', encoding='utf-8')
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except Exception as e:
                print(f"ERROR: Could not create file handler '{log_file_path}': {e}. Console only.")
                log_file_path = None # Indicate file logging failed

        # Console Handler (always add)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # Set vpn logger level if available (less verbose)
        if VPN_AVAILABLE: logging.getLogger('vpn').setLevel(logging.WARNING)

        # Initial log message via print (logger might not be fully ready)
        if log_file_path: print(f"--- Peer {self.peer_id[:8]} logging to console and file: {os.path.basename(log_file_path)} ---")
        else: print(f"--- Peer {self.peer_id[:8]} logging to console ONLY ---")

        logger.propagate = False # Prevent messages reaching root logger
        logger._configured = True # Mark logger as configured
        return logger

    def setup_directories(self):
        """Creates required directories (shared, downloads, certs)."""
        for dir_path in [self.shared_dir_path, self.downloads_dir_path, self.certs_dir_path]:
            try:
                os.makedirs(dir_path, exist_ok=True)
                self.logger.debug(f"Ensured directory exists: {dir_path}")
            except OSError as e:
                self.logger.error(f"Failed to create directory '{dir_path}': {e}")
        # Initial cleanup of potentially orphaned temp files
        self.cleanup_temp_files(self.downloads_dir_path)

    def _find_available_port(self, start_port, end_port) -> Optional[int]:
        """Attempts to find and bind to an available port within the specified range."""
        for port in range(start_port, end_port + 1):
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Try binding to the specific IP first
                try:
                     s.bind((self.ip, port))
                except OSError as bind_err:
                    # If specific IP fails, try binding to all interfaces (0.0.0.0)
                     if "Cannot assign requested address" in str(bind_err) or "assign requested address" in str(bind_err):
                         self.logger.debug(f"Could not bind {self.ip}:{port}, trying 0.0.0.0:{port}")
                         try: s.bind(('0.0.0.0', port))
                         except OSError: continue # Still fails, try next port
                     else: continue # Other bind error, try next port

                time.sleep(0.05) # Small delay to allow OS to register bind
                return port # Found available port
            except OSError:
                continue # Port likely in use or other error
            finally:
                if s:
                    try: s.close()
                    except Exception: pass
        self.logger.error(f"No available port found between {start_port}-{end_port}")
        return None

    def setup_server_socket(self) -> Optional[socket.socket]:
        """Creates and binds the main server socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind to 0.0.0.0 to accept connections on all available interfaces
            sock.bind(('0.0.0.0', self.port))
            sock.listen(10) # Listen for incoming connections
            self.logger.info(f"Server socket listening on *:{self.port} (Externally visible IP: {self.ip})")
            return sock
        except Exception as e:
            self.logger.error(f"Server socket setup failed on port {self.port}: {e}", exc_info=True)
            return None

    def get_local_ip(self) -> str:
        """Attempts to determine the primary local IP address."""
        try:
            # Connect to a public address (doesn't send data)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1.0) # Timeout for connect attempt
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                return ip
        except OSError as e:
             self.logger.warning(f"Could not determine local IP via external connect ({e}), trying hostname.")
             try:
                 # Fallback using hostname
                 return socket.gethostbyname(socket.gethostname())
             except socket.gaierror:
                 self.logger.warning("Could not determine local IP via hostname, using 127.0.0.1.")
                 return "127.0.0.1" # Final fallback

    def initialize_shared_files(self):
        """Scans the shared directory, shares files, and informs the tracker."""
        shared_dir = self.shared_dir_path
        if not os.path.isdir(shared_dir):
            self.logger.warning(f"Shared directory not found: '{shared_dir}'. Create it to share files.")
            return
        self.logger.info(f"Scanning shared directory: '{os.path.relpath(shared_dir, SCRIPT_DIR)}'")
        files_shared_count = 0
        try:
            for filename in os.listdir(shared_dir):
                filepath = os.path.join(shared_dir, filename)
                if os.path.isfile(filepath) and not filename.endswith('.tmp'): # Ignore temp files
                    # share_file handles checking if already shared and publishing
                    if self.share_file(filepath):
                        files_shared_count += 1
        except OSError as e:
            self.logger.error(f"Error reading shared directory '{shared_dir}': {e}")

        if files_shared_count > 0:
            self.logger.info(f"Finished initial scan. Shared {files_shared_count} file(s).")
            # No need for explicit update_tracker_chunks here, share_file sends 'publish'
        else:
            self.logger.info("Initial scan complete. No new files found to share.")

    def calculate_file_hash(self, filepath) -> Optional[str]:
        """Calculates the SHA1 hash of a file."""
        hasher = hashlib.sha1()
        try:
            with open(filepath, 'rb') as file:
                while True:
                    # Read in chunks to handle large files
                    chunk = file.read(1024 * 1024) # 1MB chunks
                    if not chunk: break
                    hasher.update(chunk)
            return hasher.hexdigest()
        except OSError as e:
            self.logger.error(f"Error hashing file '{os.path.basename(filepath)}': {e}")
            return None
        except Exception as e:
             self.logger.error(f"Unexpected error hashing file '{os.path.basename(filepath)}': {e}", exc_info=True)
             return None

    def split_file_into_chunks(self, filepath) -> Optional[Tuple[List[Dict], int]]:
        """Splits a file into chunks and returns metadata."""
        chunks = []
        try:
            total_size = os.path.getsize(filepath)
            if total_size == 0: return [], 0 # Handle empty files gracefully

            with open(filepath, 'rb') as f:
                chunk_index = 0
                while True:
                    offset = chunk_index * CHUNK_SIZE
                    # Stop if we've read the whole file
                    if offset >= total_size: break
                    # Read chunk data
                    data = f.read(CHUNK_SIZE)
                    if not data: break # End of file
                    # Calculate chunk hash
                    chunk_hash = hashlib.sha1(data).hexdigest()
                    # Store chunk metadata
                    chunks.append({'index': chunk_index, 'hash': chunk_hash, 'offset': offset, 'size': len(data)})
                    chunk_index += 1
            return chunks, total_size
        except OSError as e:
            self.logger.error(f"Error splitting file '{os.path.basename(filepath)}': {e}")
            return None # Return None to indicate error
        except Exception as e:
            self.logger.error(f"Unexpected error splitting file '{os.path.basename(filepath)}': {e}", exc_info=True)
            return None

    def share_file(self, filepath) -> bool:
        """
        Shares a single file: calculates metadata, updates internal state,
        and publishes to the tracker if the file is new or changed.
        Returns True if the file is successfully processed/shared, False otherwise.
        """
        abs_path = os.path.abspath(filepath)
        filename = os.path.basename(abs_path)
        if not os.path.isfile(abs_path):
             self.logger.warning(f"Attempted to share non-file: {filepath}")
             return False

        # Calculate hash first (potentially slow, do outside lock if possible)
        file_hash = self.calculate_file_hash(abs_path)
        if not file_hash: return False # Hashing failed

        needs_processing = False
        with self.lock:
            # Check if file is already shared and if its hash matches
             if abs_path not in self.shared_files or self.shared_files[abs_path].get('hash') != file_hash:
                 needs_processing = True

        # If file is already shared and unchanged, nothing more to do
        if not needs_processing:
             self.logger.debug(f"File '{filename}' already shared and unchanged.")
             return True

        # Split file into chunks (potentially slow, do outside lock)
        split_result = self.split_file_into_chunks(abs_path)
        if split_result is None: return False # Splitting failed
        chunks, total_size = split_result

        needs_publish = False
        with self.lock:
            # Re-check under lock in case another thread processed it while we were splitting
            if abs_path not in self.shared_files or self.shared_files[abs_path].get('hash') != file_hash:
                 self.logger.info(f"Processing share for '{filename}' ({file_hash[:8]})...")
                 # Remove old chunk references if replacing an existing entry
                 if abs_path in self.shared_files:
                     old_info = self.shared_files[abs_path]
                     old_file_hash = old_info.get('hash')
                     if old_file_hash:
                         for chunk_meta in old_info.get('chunks', []):
                             ch = chunk_meta.get('hash')
                             if ch and ch in self.chunk_sources:
                                 # Remove old file_hash source for this chunk
                                 self.chunk_sources[ch].discard(old_file_hash)
                                 # If no file provides this chunk anymore, remove from chunk_sources
                                 if not self.chunk_sources[ch]:
                                      self.chunk_sources.pop(ch, None) # Safely pop

                 # Add new file information
                 self.shared_files[abs_path] = {'filename': filename, 'hash': file_hash, 'chunks': chunks, 'size': total_size}
                 # Update available chunks and sources
                 for chunk_meta in chunks:
                     chunk_hash = chunk_meta.get('hash')
                     if chunk_hash:
                         self.available_chunks.add(chunk_hash)
                         # Record that this file_hash provides this chunk_hash
                         self.chunk_sources.setdefault(chunk_hash, set()).add(file_hash)
                 needs_publish = True # Mark that tracker needs update
            # else: Another thread shared it while we were splitting - ok

        # Publish to tracker if needed (outside lock)
        if needs_publish:
            try:
                chunk_hashes_list = [c['hash'] for c in chunks if 'hash' in c]
                chunk_count = len(chunk_hashes_list)
                self.logger.debug(f"Publishing '{filename}' ({file_hash[:8]}) to tracker...")
                response = self.send_to_tracker_with_retry({
                    'type': 'publish', 'peer_id': self.peer_id,
                    'file_hash': file_hash, 'filename': filename,
                    'chunk_hashes': chunk_hashes_list, # Send list of chunk hashes
                    'chunks': chunk_count, # Send total chunk count
                    'size': total_size})
                if response.get('status') == 'success':
                    self.logger.info(f"Shared/Published: '{filename}' ({file_hash[:8]}, {chunk_count} chunks)")
                    return True
                else:
                     self.logger.error(f"Publish failed for '{filename}': {response.get('message', 'Tracker error')}")
                     # Optional: Consider reverting state if publish fails? Currently doesn't.
                     return False
            except Exception as e:
                self.logger.error(f"Error during publish of '{filename}': {e}", exc_info=True)
                return False
        # Return True if already shared or successfully published
        return True

    def verify_shared_files(self):
        """Periodically checks shared files for existence/changes and updates state/tracker."""
        self.logger.debug("Running shared file verification...")
        removed_paths, rescan_paths = [], []
        # Work on a copy to avoid holding lock during IO
        with self.lock: shared_copy = dict(self.shared_files.items())

        for path, info in shared_copy.items():
            if not os.path.exists(path):
                self.logger.warning(f"Shared file removed from disk: '{info.get('filename', path)}'.")
                removed_paths.append(path)
            else:
                # Check hash only if file still exists
                current_hash = self.calculate_file_hash(path)
                if current_hash is None or current_hash != info.get('hash'):
                    self.logger.warning(f"Shared file changed on disk: '{info.get('filename', path)}'. Rescanning.")
                    removed_paths.append(path) # Treat as removed first
                    rescan_paths.append(path) # Then rescan

        needs_tracker_update = False
        if removed_paths:
            needs_tracker_update = True # Assume tracker needs update if anything removed/changed
            with self.lock:
                truly_removed_chunk_hashes = set() # Chunks that are no longer available from *any* file
                for path in removed_paths:
                    old_info = self.shared_files.pop(path, None)
                    if old_info:
                        old_file_hash = old_info.get('hash')
                        if old_file_hash:
                            # Update chunk sources
                            for chunk_meta in old_info.get('chunks', []):
                                ch = chunk_meta.get('hash')
                                if ch and ch in self.chunk_sources:
                                    self.chunk_sources[ch].discard(old_file_hash)
                                    # If this was the last file providing the chunk, mark for removal
                                    if not self.chunk_sources[ch]:
                                        self.chunk_sources.pop(ch) # Remove entry from sources dict
                                        truly_removed_chunk_hashes.add(ch)

                # Remove chunks from available_chunks only if no longer sourced
                if truly_removed_chunk_hashes:
                     # Double check against current sources just in case
                     final_removed = set()
                     for ch_rem in truly_removed_chunk_hashes:
                          if ch_rem not in self.chunk_sources:
                               final_removed.add(ch_rem)
                     if final_removed:
                         self.available_chunks.difference_update(final_removed)
                         self.logger.info(f"Removed {len(final_removed)} chunk hashes from available set due to file removal/change.")

        # Rescan files marked as changed
        if rescan_paths:
            self.logger.info(f"Rescanning {len(rescan_paths)} changed file(s)...")
            for path in rescan_paths:
                self.share_file(path) # This handles publishing if successful

        # Send update_chunks message to tracker if state changed
        if needs_tracker_update:
            self.update_tracker_chunks()
        else:
             self.logger.debug("Shared file verification complete. No changes requiring tracker update.")

    def update_tracker_chunks(self):
        """Informs the tracker about the peer's currently available set of chunk hashes."""
        with self.lock: current_chunk_hashes = list(self.available_chunks)
        # Send update even if empty, allows tracker to clear state if needed
        self.logger.info(f"Updating tracker with current {len(current_chunk_hashes)} available chunks.")
        try:
            response = self.send_to_tracker_with_retry({
                'type': 'update_chunks',
                'peer_id': self.peer_id,
                'available_chunk_hashes': current_chunk_hashes
            })
            if response.get('status') != 'success':
                 self.logger.warning(f"Tracker chunk update failed: {response.get('message', 'Error')}")
            else:
                 self.logger.debug("Tracker chunk update successful.")
        except Exception as e:
            self.logger.error(f"Failed to send chunk update to tracker: {e}", exc_info=True)

    def download_file(self, file_hash: str, save_path: str,
                      download_delay: float = DEFAULT_CHUNK_DOWNLOAD_DELAY_SECONDS,
                      max_parallel: int = DEFAULT_MAX_PARALLEL_DOWNLOADS) -> bool:
        """
        Initiates the download process for a given file hash.
        Returns True if initiation was successful (or already active), False otherwise.
        """
        abs_save_path = os.path.abspath(save_path)
        # Sanitize parameters
        max_parallel = max(1, max_parallel) if isinstance(max_parallel, int) else DEFAULT_MAX_PARALLEL_DOWNLOADS
        download_delay = max(0.0, download_delay) if isinstance(download_delay, (int, float)) else DEFAULT_CHUNK_DOWNLOAD_DELAY_SECONDS

        self.logger.info(f"Download Request: {file_hash[:8]} -> '{os.path.basename(abs_save_path)}' (P:{max_parallel}, D:{download_delay}s)")
        if not isinstance(file_hash, str) or len(file_hash) != 40:
            self.logger.error(f"Invalid file hash format: {file_hash}")
            return False
        temp_path = abs_save_path + '.tmp'

        try:
            # 1. Get File Info from Tracker
            self.logger.debug(f"Requesting file info for {file_hash[:8]} from tracker...")
            response = self.send_to_tracker_with_retry({'type': 'get_file_info', 'file_hash': file_hash})
            if response.get('status') != 'success':
                self.logger.error(f"Failed get_file_info {file_hash[:8]}: {response.get('message','Tracker error')}")
                return False

            chunk_hashes = response.get('chunks') # Tracker should send list of hashes
            total_size = response.get('size')
            filename = response.get('filename', f"f_{file_hash[:8]}.unk") # Default filename if missing

            # Validate file info
            if not isinstance(chunk_hashes, list) or not isinstance(total_size, int) or total_size < 0:
                 self.logger.error(f"Invalid file info received from tracker for {file_hash[:8]}.")
                 return False
            chunk_count = len(chunk_hashes)
            self.logger.info(f"File info OK: '{filename}' ({file_hash[:8]}), Size={total_size}, Chunks={chunk_count}")

            # Handle 0-byte files immediately
            if chunk_count == 0 and total_size == 0:
                self.logger.info(f"Handling 0-byte file: '{filename}'. Creating empty file.")
                os.makedirs(os.path.dirname(abs_save_path), exist_ok=True)
                open(abs_save_path, 'wb').close() # Create empty file
                self.logger.info(f"Download complete (0 bytes): '{filename}'")
                return True # Treat as successful download initiation
            # Handle inconsistent info
            if (chunk_count == 0 and total_size > 0) or (chunk_count > 0 and total_size == 0):
                self.logger.error(f"Inconsistent file info {file_hash[:8]}: Size {total_size}, Chunks {chunk_count}.")
                return False

            # 2. Prepare Temp File
            os.makedirs(os.path.dirname(abs_save_path), exist_ok=True) # Ensure download dir exists
            try:
                if os.path.exists(temp_path):
                    # Check if existing temp file size matches expected size
                    current_temp_size = os.path.getsize(temp_path)
                    if current_temp_size != total_size:
                        self.logger.warning(f"Temp file '{os.path.basename(temp_path)}' size mismatch ({current_temp_size}/{total_size}). Overwriting.")
                        with open(temp_path, 'wb') as f_ow: f_ow.truncate(total_size) # Overwrite/truncate
                    else:
                        self.logger.info(f"Resuming download using existing temp file: '{os.path.basename(temp_path)}'")
                else:
                    # Create new temp file and pre-allocate space
                    with open(temp_path, 'wb') as f_cr: f_cr.truncate(total_size)
                    self.logger.info(f"Created new temp file '{os.path.basename(temp_path)}'.")
            except IOError as e:
                self.logger.error(f"Failed to prepare temp file '{temp_path}': {e}", exc_info=True)
                # Attempt cleanup if creation failed midway
                if os.path.exists(temp_path): 
                    try: os.remove(temp_path); 
                    except OSError: pass
                return False

            # 3. Add to Active Downloads & Start Supervisor Thread
            with self.lock:
                # Check if already downloading
                if file_hash in self.downloads:
                    self.logger.info(f"Download {file_hash[:8]} ('{filename}') is already active.")
                    return True # Indicate already running

                # Create structured list of chunk objects
                chunk_objects = self._create_chunk_objects(chunk_hashes, total_size)
                if chunk_objects is None: return False # Error during creation

                # Store download state
                self.downloads[file_hash] = {
                    'filename': filename,
                    'total_size': total_size,
                    'downloaded_bytes': 0, # Track progress
                    'start_time': time.time(),
                    'temp_path': temp_path,
                    'save_path': abs_save_path,
                    'chunk_objects': chunk_objects, # Detailed status per chunk
                    'peers_for_chunks': defaultdict(list), # Cache peers per chunk hash
                    'last_peer_refresh': 0, # Timestamp of last peer list fetch
                    'last_progress_time': time.time(), # Timestamp of last successful chunk download
                    'last_speed_calc_time': time.time(), # Timestamp for speed calc
                    'bytes_since_last_calc': 0, # Bytes downloaded since last speed calc
                    'current_speed_bps': 0.0, # Calculated speed
                    'download_delay': download_delay, # Configured delay per chunk
                    'max_parallel': max_parallel, # Configured parallelism
                    'active_workers': set() # Set of active worker threads
                }
                self.logger.info(f"Download initialized for '{filename}' ({file_hash[:8]}). Starting supervisor...")

            # Start the download manager thread for this file
            threading.Thread(target=self._manage_download, args=(file_hash,),
                             name=f"DLM-{filename[:10]}-{file_hash[:6]}", daemon=True).start()
            return True # Initiation successful

        except Exception as e:
            # Catch-all for unexpected errors during initiation
            self.logger.error(f"Unexpected error initiating download for {file_hash[:8]}: {e}", exc_info=True)
            # Clean up state if download object was partially created
            with self.lock: self.downloads.pop(file_hash, None)
            # Clean up temp file if created
            if os.path.exists(temp_path): 
                try: os.remove(temp_path); 
                except OSError: pass
            return False

    def _manage_download(self, file_hash: str):
        """Supervises and coordinates the download of chunks for a specific file."""
        thread_name = threading.current_thread().name
        # Get initial static info safely
        filename_for_log = '?'; max_parallel = DEFAULT_MAX_PARALLEL_DOWNLOADS; initial_start_time = time.time()
        with self.lock:
             if file_hash in self.downloads:
                  info = self.downloads[file_hash]
                  filename_for_log = info.get('filename', '?')
                  max_parallel = info.get('max_parallel', DEFAULT_MAX_PARALLEL_DOWNLOADS)
                  initial_start_time = info.get('start_time', time.time())
             else:
                  self.logger.warning(f"[{thread_name}] Download {file_hash[:8]} vanished before supervisor start.")
                  return # Exit if download was somehow removed immediately
        self.logger.info(f"[{thread_name}] Supervisor started for '{filename_for_log}' (P:{max_parallel}).")

        final_info_on_complete = None # Store info needed for finalization outside loop
        last_progress_print_time = 0; PROGRESS_PRINT_INTERVAL = 1.0 # For CLI logging rate limit

        try:
            while self.running: # Main supervisor loop
                if not self.running: break # Exit if peer is shutting down

                # --- State Refresh & Worker Cleanup (Under Lock) ---
                is_complete = False; active_worker_count = 0; needs_peer_refresh = False; needed_chunk_hashes = []; status_counts = defaultdict(int); current_speed_bps = 0.0
                with self.lock:
                    # Check if download still exists
                    if file_hash not in self.downloads:
                        self.logger.info(f"[{thread_name}] Download {file_hash[:8]} no longer active. Supervisor exiting.")
                        return

                    info = self.downloads[file_hash]
                    chunks = info.get('chunk_objects', [])
                    total_chunks = len(chunks)
                    active_workers = info.get('active_workers', set())
                    current_speed_bps = info.get('current_speed_bps', 0.0) # Get current speed for display

                    # Clean up finished worker threads from the active set
                    finished_workers = {w for w in active_workers if not w.is_alive()}
                    if finished_workers:
                         self.logger.debug(f"[{thread_name}] Cleaning up {len(finished_workers)} finished workers.")
                         info['active_workers'].difference_update(finished_workers)
                    active_worker_count = len(info['active_workers'])

                    # Check completion status and count chunk statuses
                    if total_chunks > 0:
                        completed_count = 0
                        for c in chunks:
                            status = c.get('status', 'unknown')
                            status_counts[status] += 1
                            if status == 'complete': completed_count += 1
                        is_complete = (completed_count == total_chunks)
                    else: is_complete = True # 0-byte file case

                    # Handle Completion: If all chunks complete and no workers active
                    if is_complete and active_worker_count == 0:
                        final_status_line = f"Download Complete: '{filename_for_log[:40]}' ({total_chunks}/{total_chunks} chunks)."
                        print(f"\r{' ' * 80}\r{final_status_line}") # Overwrite last CLI progress line
                        self.logger.info(f"[{thread_name}] All chunks downloaded for {file_hash[:8]}. Triggering finalization.")
                        final_info_on_complete = info.copy() # Store info for finalization
                        del self.downloads[file_hash] # Remove from active downloads
                        break # Exit the supervisor loop

                    # Determine if peer list refresh is needed (only if not complete)
                    if not is_complete:
                        needed_chunk_hashes = [c['hash'] for c in chunks if c.get('status') == 'needed' and c.get('hash')]
                        if needed_chunk_hashes:
                            # Refresh more often if we lack peers for some needed chunks
                            needs_refresh_due_to_missing = any(not info['peers_for_chunks'].get(ch) for ch in needed_chunk_hashes)
                            refresh_interval = 15 if needs_refresh_due_to_missing else 60 # Seconds
                            if time.time() - info.get('last_peer_refresh', 0) > refresh_interval:
                                needs_peer_refresh = True

                # --- Actions Outside Lock ---

                # Refresh Peer List If Needed
                if needs_peer_refresh and needed_chunk_hashes:
                    self.logger.debug(f"[{thread_name}] Refreshing peers for {len(needed_chunk_hashes)} chunks of {file_hash[:8]}.")
                    peers_map = self._get_peers_for_chunks(needed_chunk_hashes) # Blocking call
                    # Update peers map under lock
                    with self.lock:
                         if file_hash in self.downloads: # Check download still exists
                             self.downloads[file_hash]['peers_for_chunks'] = peers_map
                             self.downloads[file_hash]['last_peer_refresh'] = time.time()
                             # Log if some chunks still have no peers
                             missing_peers_for = [h[:6] for h in needed_chunk_hashes if not peers_map.get(h)]
                             if missing_peers_for:
                                  self.logger.warning(f"[{thread_name}] No peers found for needed chunks: {missing_peers_for} (File: {filename_for_log})")

                # Launch New Workers If Slots Available and Download Not Complete
                if not is_complete and active_worker_count < max_parallel:
                    chunks_to_start = []
                    with self.lock:
                         if file_hash in self.downloads: # Check download exists
                              info = self.downloads[file_hash]
                              current_active_count = len(info['active_workers'])
                              num_to_start = max_parallel - current_active_count
                              if num_to_start > 0:
                                   # Select rarest 'needed' chunks to start
                                   potential_chunks = self._select_multiple_chunks(file_hash, num_to_start)
                                   for chunk_to_start in potential_chunks:
                                        chunk_index = chunk_to_start.get('index')
                                        # Re-verify status and index validity before marking
                                        if 0 <= chunk_index < len(info['chunk_objects']) and info['chunk_objects'][chunk_index].get('status') == 'needed':
                                             info['chunk_objects'][chunk_index]['status'] = 'downloading'
                                             chunks_to_start.append(chunk_to_start)
                                        else:
                                             self.logger.warning(f"[{thread_name}] Chunk {chunk_index} status changed before worker start?")

                    # Start worker threads outside lock
                    for chunk_info in chunks_to_start:
                         if not self.running: break
                         worker_name = f"DLW-{file_hash[:6]}-C{chunk_info.get('index')}"
                         self.logger.debug(f"[{thread_name}] Starting worker {worker_name}")
                         worker_thread = threading.Thread(target=self._chunk_download_worker,
                                                          args=(file_hash, chunk_info),
                                                          name=worker_name, daemon=True)
                         worker_thread.start()
                         # Add to tracked set *after* starting
                         with self.lock:
                             if file_hash in self.downloads:
                                 self.downloads[file_hash]['active_workers'].add(worker_thread)

                # Reset Failed Chunks (with initial delay)
                # This check runs periodically based on the main loop sleep
                if status_counts.get('failed', 0) > 0 and \
                   (time.time() - initial_start_time > INITIAL_FAILED_CHUNK_RESET_DELAY):
                     with self.lock:
                          if file_hash in self.downloads: # Check download exists
                               info = self.downloads[file_hash]
                               reset_count = 0
                               for chunk in info.get('chunk_objects', []):
                                    if chunk.get('status') == 'failed':
                                         self.logger.debug(f"[{thread_name}] Resetting failed chunk {chunk.get('index')} to 'needed'.")
                                         chunk['status'] = 'needed'
                                         # Reset attempt count for the failed chunk
                                         chunk['peer_attempts'] = defaultdict(int)
                                         reset_count += 1
                               # If chunks were reset, force a peer refresh soon
                               if reset_count > 0:
                                    self.logger.info(f"[{thread_name}] Reset {reset_count} failed chunk(s) for '{filename_for_log}' to 'needed'.")
                                    info['last_peer_refresh'] = 0

                # Print Dynamic Progress Line to Console (for standalone debugging)
                now = time.time()
                if not is_complete and (now - last_progress_print_time > PROGRESS_PRINT_INTERVAL):
                     try:
                          display_filename = (filename_for_log[:30] + '...') if len(filename_for_log) > 33 else filename_for_log
                          completed_chunks = status_counts['complete']
                          progress_percent = (completed_chunks / total_chunks) * 100 if total_chunks > 0 else 100.0
                          speed_kibps = current_speed_bps / (1024 * 8)
                          speed_mibps = current_speed_bps / (1024 * 1024 * 8)
                          speed_str = f"{speed_mibps:.1f}MiB/s" if speed_mibps >= 0.1 else (f"{speed_kibps:.1f}KiB/s" if speed_kibps >= 0.1 else f"{current_speed_bps:.0f}B/s")
                          status_str_parts = [f"C:{completed_chunks}"]
                          if status_counts['downloading'] > 0: status_str_parts.append(f"D:{status_counts['downloading']}")
                          if status_counts['needed'] > 0: status_str_parts.append(f"N:{status_counts['needed']}")
                          if status_counts['failed'] > 0: status_str_parts.append(f"F:{status_counts['failed']}")
                          status_detail = ",".join(status_str_parts)
                          status_line = f"DL '{display_filename}': {progress_percent:.1f}% ({status_detail}/{total_chunks}) W:{active_worker_count}/{max_parallel} [{speed_str}] "
                          padded_line = status_line.ljust(79)
                          # Use print for console output
                          print(f"\r{padded_line}", end='', flush=True)
                          last_progress_print_time = now
                     except Exception as print_err:
                          self.logger.error(f"[{thread_name}] Error printing console progress: {print_err}")
                          last_progress_print_time = now + PROGRESS_PRINT_INTERVAL # Delay next attempt

                # Main supervisor loop sleep
                if not self.running: break
                time.sleep(0.2) # Short sleep to avoid busy-waiting

        except Exception as e:
            # Catch unexpected errors in the supervisor loop
            print() # Ensure cursor moves to next line after potential partial progress line
            self.logger.error(f"[{thread_name}] CRITICAL error in download supervisor for {file_hash[:8]}: {e}", exc_info=True)
            # Clean up download state if supervisor crashes
            with self.lock: self.downloads.pop(file_hash, None)
        finally:
            # Log supervisor stop and trigger finalization if needed
            self.logger.info(f"[{thread_name}] Supervisor stopped for {file_hash[:8]}.")
            # Call finalize outside the loop and lock
            if final_info_on_complete:
                self.finalize_download(file_hash, final_info_on_complete)

    def _select_multiple_chunks(self, file_hash: str, count: int) -> List[Dict]:
        """Selects up to 'count' rarest 'needed' chunks for download attempts."""
        MAX_ATTEMPTS_PER_PEER = 3 # Max times to try downloading a chunk from the *same* peer
        # This method assumes it's called under self.lock
        if file_hash not in self.downloads: return []

        info = self.downloads[file_hash]
        chunks = info.get('chunk_objects', [])
        peers_map = info.get('peers_for_chunks', {}) # chunk_hash -> [peer_info_dict, ...]
        if not chunks: return []

        candidate_chunks = [] # List of (chunk_dict, valid_peer_count)
        for chunk in chunks:
            if chunk.get('status') == 'needed':
                chunk_hash = chunk.get('hash')
                attempts_info = chunk.get('peer_attempts', defaultdict(int)) # peer_id -> attempt_count
                if not chunk_hash: continue

                available_peers = peers_map.get(chunk_hash, [])
                # Count how many peers haven't exceeded the max attempts for *this specific chunk*
                valid_peer_count = sum(1 for p in available_peers
                                    if isinstance(p, dict) and attempts_info.get(p.get('peer_id'), 0) < MAX_ATTEMPTS_PER_PEER)

                # Only consider chunks that have at least one valid peer to try
                if valid_peer_count > 0:
                    candidate_chunks.append((chunk, valid_peer_count))

        if not candidate_chunks:
            # self.logger.debug(f"No chunks with valid peers found for selection in {file_hash[:8]}")
            return []

        # Sort candidates by rarity (ascending peer count)
        candidate_chunks.sort(key=lambda x: x[1])

        # Return the chunk dictionaries for the rarest 'count' chunks
        return [chunk_rarity_tuple[0] for chunk_rarity_tuple in candidate_chunks[:count]]

    def _chunk_download_worker(self, file_hash: str, chunk_info: Dict):
        """Worker thread responsible for downloading a single chunk from an appropriate peer."""
        thread_name = threading.current_thread().name
        chunk_index = chunk_info.get('index', -1)
        chunk_hash = chunk_info.get('hash')
        success = False
        final_status = 'failed' # Assume failure initially
        download_delay = 0
        selected_peer_id = None # Track which peer was used/attempted

        if chunk_index < 0 or not chunk_hash:
            self.logger.error(f"[{thread_name}] Invalid chunk info received: {chunk_info}")
            return # Cannot proceed

        MAX_ATTEMPTS_PER_PEER = 3
        peers_to_try = []
        # Get necessary info under lock
        with self.lock:
            if file_hash in self.downloads:
                info = self.downloads[file_hash]
                download_delay = info.get('download_delay', 0.0)
                try:
                    # Get the current state of the chunk object
                    chunk_obj = info['chunk_objects'][chunk_index]
                    # Check if the manager still expects this chunk to be downloading
                    if chunk_obj.get('status') != 'downloading':
                        self.logger.debug(f"[{thread_name}] Chunk {chunk_index} status is no longer 'downloading'. Worker exiting.")
                        return

                    # Get peers known to have this chunk
                    peers_map = info.get('peers_for_chunks', {})
                    all_peers_for_chunk = peers_map.get(chunk_hash, [])
                    # Get attempt counts for this specific chunk
                    attempts_info = chunk_obj.get('peer_attempts', defaultdict(int))
                    # Filter peers: only those not exceeding max attempts for this chunk
                    peers_to_try = [p for p in all_peers_for_chunk
                                    if isinstance(p, dict) and attempts_info.get(p.get('peer_id'), 0) < MAX_ATTEMPTS_PER_PEER]
                except (IndexError, KeyError, TypeError) as e:
                    self.logger.error(f"[{thread_name}] Error accessing download/chunk state: {e}")
                    return # State inconsistency
            else:
                self.logger.warning(f"[{thread_name}] Download {file_hash[:8]} removed during worker startup.")
                return # Download gone

        # Attempt download if peers available
        if not peers_to_try:
            final_status = 'failed'
            self.logger.debug(f"[{thread_name}] No valid peers available for chunk {chunk_index}. Failing immediately.")
        else:
            random.shuffle(peers_to_try) # Try peers in random order
            for peer_info in peers_to_try:
                 if not self.running: break # Check if peer is shutting down
                 peer_id = peer_info.get('peer_id')
                 if not peer_id: continue # Skip if peer info is invalid

                 selected_peer_id = peer_id # Store peer being attempted
                 should_attempt = False
                 # Increment attempt count under lock before attempting download
                 with self.lock:
                     if file_hash in self.downloads: # Check download still active
                         try:
                             chunk_data = self.downloads[file_hash]['chunk_objects'][chunk_index]
                             # Re-check status hasn't changed
                             if chunk_data.get('status') == 'downloading':
                                 # Ensure attempt dict exists
                                 if 'peer_attempts' not in chunk_data: chunk_data['peer_attempts'] = defaultdict(int)
                                 # Only proceed if attempt count is below limit
                                 if chunk_data['peer_attempts'].get(peer_id, 0) < MAX_ATTEMPTS_PER_PEER:
                                     chunk_data['peer_attempts'][peer_id] += 1 # Increment attempt count
                                     should_attempt = True
                                 # else: Max attempts reached for this peer, try next peer
                         except (IndexError, KeyError, TypeError): pass # Ignore if state changed

                 # Perform download attempt (outside lock)
                 if should_attempt:
                      self.logger.debug(f"[{thread_name}] Attempting chunk {chunk_index} from {peer_id[:8]}...")
                      if self._download_chunk_from_peer(peer_info, chunk_info, file_hash):
                          success = True
                          final_status = 'complete'
                          self.logger.info(f"[{thread_name}] SUCCESS downloading chunk {chunk_index} from {peer_id[:8]}.")
                          break # Stop trying other peers on success
                      else:
                          self.logger.debug(f"[{thread_name}] FAILED attempt chunk {chunk_index} from {peer_id[:8]}.")

            # If loop finishes without success
            if not success:
                 self.logger.warning(f"[{thread_name}] Failed to download chunk {chunk_index} after trying {len(peers_to_try)} peer(s).")
                 final_status = 'failed'

        # Final Status Update (Under Lock)
        with self.lock:
            if file_hash in self.downloads: # Check download still exists
                 try:
                     chunk_obj = self.downloads[file_hash]['chunk_objects'][chunk_index]
                     # Only update status if it's still marked as 'downloading' by the manager
                     if chunk_obj.get('status') == 'downloading':
                          chunk_obj['status'] = final_status
                          # Store which peer completed it or was last tried
                          if success and selected_peer_id:
                              chunk_obj['completed_by_peer'] = selected_peer_id
                              # Update last progress time for the download
                              self.downloads[file_hash]['last_progress_time'] = time.time()
                          elif not success and selected_peer_id: # Store last tried peer on failure
                              chunk_obj['last_tried_peer'] = selected_peer_id
                     # else: Manager changed status (e.g., reset stalled), ignore worker result
                 except (IndexError, KeyError, TypeError): pass # Ignore if state changed underneath

        # Apply configured delay after successful chunk download
        if success and download_delay > 0 and self.running:
             self.logger.debug(f"[{thread_name}] Applying {download_delay:.2f}s post-chunk delay...")
             time.sleep(download_delay)

        self.logger.debug(f"[{thread_name}] Worker finished for chunk {chunk_index}. Final Status: {final_status}")

    def _create_chunk_objects(self, chunk_hashes: List[str], total_size: int) -> Optional[List[Dict]]:
        """Creates the structured list of chunk metadata for tracking download state."""
        chunk_objects = []
        current_offset = 0
        for i, chash in enumerate(chunk_hashes):
            # Calculate chunk size, handling the last potentially smaller chunk
            chunk_size = min(CHUNK_SIZE, total_size - current_offset)
            # Check for inconsistencies (should not happen with valid tracker info)
            if chunk_size <= 0:
                 if total_size == current_offset and i == len(chunk_hashes): break # Correctly handled last chunk
                 else: self.logger.error(f"Chunk size calculation error. Offset {current_offset}, Total Size {total_size}, Index {i}"); return None

            chunk_objects.append({
                'index': i,
                'hash': chash,
                'offset': current_offset,
                'size': chunk_size,
                'status': 'needed', # Initial status
                'peer_attempts': defaultdict(int), # Track attempts per peer for this chunk
                'completed_by_peer': None, # Track which peer successfully sent this chunk
                'last_tried_peer': None # Track last peer attempted on failure
            })
            current_offset += chunk_size
        # Final validation
        if current_offset != total_size:
            self.logger.error(f"Chunk object creation size mismatch. Calculated {current_offset} != Total {total_size}.")
            return None
        return chunk_objects

    def _get_peers_for_chunks(self, chunk_hashes: List[str]) -> Dict[str, List[Dict]]:
        """Requests peer lists for multiple chunk hashes from the tracker AND updates self.peers.""" # Added to docstring
        if not chunk_hashes: return defaultdict(list)
        unique_hashes = list(set(chunk_hashes))
        peer_map = defaultdict(list) # chunk_hash -> [peer_info_dict, ...]
        self.logger.debug(f"Requesting peers from tracker for {len(unique_hashes)} unique chunk(s)...")

        for chash in unique_hashes:
             if not self.running: break
             try:
                 response = self.send_to_tracker_with_retry({'type': 'get_peers', 'chunk_hash': chash, 'peer_id': self.peer_id})
                 if response.get('status') == 'success':
                     fetched_peers = response.get('peers', [])
                     valid_peers = [] # Store validated peers for the current chunk hash
                     peers_added_or_updated = 0
                     # --- START MODIFICATION: Update self.peers ---
                     with self.lock: # Lock needed to modify self.peers safely
                         for p in fetched_peers:
                             # Validate peer dictionary structure
                             if isinstance(p, dict) and all(k in p for k in ['peer_id', 'ip', 'port']) and p['peer_id'] != self.peer_id:
                                 peer_id = p['peer_id']
                                 tls_capable = p.get('tls_capable', False) # Default if missing
                                 # Reconstruct dict for consistency before adding/using
                                 peer_info_dict = {
                                     'peer_id': peer_id, 'ip': p['ip'], 'port': p['port'],
                                     'tls_capable': tls_capable
                                 }
                                 valid_peers.append(peer_info_dict) # Add to list for this chunk_hash

                                 # Add or update the peer in the main self.peers dictionary
                                 if peer_id not in self.peers:
                                     self.peers[peer_id] = {
                                         'ip': p['ip'],
                                         'port': p['port'],
                                         'tls_capable': tls_capable,
                                         'last_seen': time.time() # Record first seen time
                                     }
                                     peers_added_or_updated += 1
                                     # Optional: Log new peer discovery at DEBUG level
                                     # self.logger.debug(f"Discovered new peer {peer_id[:8]} via tracker.")
                                 else:
                                     # Update last_seen and potentially other info if needed
                                     self.peers[peer_id]['last_seen'] = time.time()
                                     # Optionally update ip/port/tls_capable if they might change?
                                     # self.peers[peer_id]['ip'] = p['ip']
                                     # self.peers[peer_id]['port'] = p['port']
                                     # self.peers[peer_id]['tls_capable'] = tls_capable

                         # --- END MODIFICATION ---

                     if valid_peers:
                         peer_map[chash] = valid_peers
                         if peers_added_or_updated > 0:
                             self.logger.debug(f"Added/Updated {peers_added_or_updated} entries in self.peers based on tracker response for chunk {chash[:8]}.")

                 # Removed logging for failed tracker responses here for brevity, main logic above
             except Exception as e:
                 self.logger.error(f"Error getting peers for chunk {chash[:8]}: {e}")

        num_found = sum(1 for h in unique_hashes if h in peer_map)
        self.logger.debug(f"Received peer lists for {num_found}/{len(unique_hashes)} requested chunks.")
        # Log the size of self.peers after update for verification
        with self.lock:
             self.logger.debug(f"Total known peers in self.peers: {len(self.peers)}")
        return peer_map
    
    def _refresh_peer_list_from_tracker(self):
        """Fetches the full list of peers from the tracker and updates self.peers."""
        thread_name = threading.current_thread().name
        self.logger.debug(f"[{thread_name}] Refreshing full peer list from tracker...")
        try:
            response = self.send_to_tracker_with_retry({'type': 'list_peers', 'peer_id': self.peer_id})

            if response.get('status') == 'success':
                fetched_peers = response.get('peers', [])
                if not isinstance(fetched_peers, list):
                     self.logger.warning(f"[{thread_name}] Invalid peer list received from tracker (not a list): {fetched_peers}")
                     return

                added_count = 0
                updated_count = 0
                now = time.time()

                with self.lock:
                    current_peer_ids = set(self.peers.keys()) # Get existing keys before iteration
                    received_peer_ids = set()

                    for p in fetched_peers:
                         # Basic validation of peer entry from tracker
                        if isinstance(p, dict) and all(k in p for k in ['peer_id', 'ip', 'port']) and p['peer_id'] != self.peer_id:
                            peer_id = p['peer_id']
                            received_peer_ids.add(peer_id) # Track received IDs
                            tls_capable = p.get('tls_capable', False)

                            if peer_id not in self.peers:
                                # Add new peer
                                self.peers[peer_id] = {
                                    'ip': p['ip'],
                                    'port': p['port'],
                                    'tls_capable': tls_capable,
                                    'last_seen': now # Use current time as last_seen
                                }
                                added_count += 1
                            else:
                                # Update existing peer's last_seen time
                                self.peers[peer_id]['last_seen'] = now
                                # Optionally update other info if tracker provides changes
                                # self.peers[peer_id]['ip'] = p['ip']
                                # self.peers[peer_id]['port'] = p['port']
                                # self.peers[peer_id]['tls_capable'] = tls_capable
                                updated_count += 1
                        else:
                            self.logger.warning(f"[{thread_name}] Invalid peer entry in list_peers response: {p}")

                    # Optional: Prune peers no longer reported by the tracker?
                    # This assumes the tracker list is authoritative. Might remove peers temporarily offline.
                    peers_to_remove = current_peer_ids - received_peer_ids
                    removed_count = 0
                    if peers_to_remove:
                        self.logger.debug(f"[{thread_name}] Peers reported by tracker no longer include: {[pid[:6] for pid in peers_to_remove]}. Removing from local list.")
                        for pid_to_remove in peers_to_remove:
                            self.peers.pop(pid_to_remove, None)
                            # Also consider cleaning up stats for removed peers?
                            self.peer_download_stats.pop(pid_to_remove, None)
                            self.peer_upload_stats.pop(pid_to_remove, None)
                            self.interested_peers.pop(pid_to_remove, None)
                        removed_count = len(peers_to_remove)


                self.logger.info(f"[{thread_name}] Peer list refresh: Added {added_count}, Updated {updated_count}, Removed {removed_count}. Total known: {len(self.peers)}")

            else:
                self.logger.warning(f"[{thread_name}] Failed to refresh peer list from tracker: {response.get('message', 'Unknown error')}")

        except Exception as e:
            self.logger.error(f"[{thread_name}] Error during peer list refresh: {e}", exc_info=True)


    def maintenance_tasks(self):
        """Performs periodic background tasks like tracker updates, file verification, etc."""
        thread_name=threading.current_thread().name
        self.logger.info(f"[{thread_name}] Maintenance thread started (Interval: {MAINTENANCE_INTERVAL}s).")
        # Define intervals for various tasks
        TRACKER_UPDATE_INTERVAL = 4 * 60 # Update tracker less often (e.g., 4 mins)
        VERIFY_FILES_INTERVAL = 15 * 60 # Verify shared files periodically (e.g., 15 mins)
        CLEANUP_INTERVAL = 20 * 60 # Cleanup orphaned temp files (e.g., 20 mins)
        STALLED_CHECK_INTERVAL = 60 # Check for stalled downloads (e.g., 1 min)
        # --- ADDED: Interval for full peer list refresh ---
        PEER_LIST_REFRESH_INTERVAL_ACTUAL = PEER_LIST_REFRESH_INTERVAL # Use constant
        # --- END ADDED ---

        # Track last execution time for each task
        last_tracker_update = time.time()
        last_verify_files = time.time()
        last_cleanup = time.time()
        last_stalled_check = time.time()
        # --- ADDED: Track last peer list refresh ---
        last_peer_list_refresh = time.time()
        # --- END ADDED ---

        while self.running:
            start_time = time.time()
            now = time.time()
            try:
                # --- Frequent Tasks ---
                self.recalculate_choking()
                # (Download Speed Calculation remains here)
                with self.lock:
                    for fhash, info in self.downloads.items():
                         time_since_last_calc = now - info.get('last_speed_calc_time', now)
                         if time_since_last_calc >= SPEED_CALC_INTERVAL:
                             bytes_since_calc = info.get('bytes_since_last_calc', 0)
                             current_speed_bps = (bytes_since_calc * 8) / time_since_last_calc if time_since_last_calc > 0 else 0.0
                             info['current_speed_bps'] = current_speed_bps
                             info['bytes_since_last_calc'] = 0
                             info['last_speed_calc_time'] = now

                # --- Less Frequent Tasks ---
                if now - last_tracker_update >= TRACKER_UPDATE_INTERVAL:
                    self.logger.debug("Maintenance: Updating tracker chunks...")
                    self.update_tracker_chunks()
                    last_tracker_update = now
                if now - last_verify_files >= VERIFY_FILES_INTERVAL:
                    self.logger.debug("Maintenance: Verifying shared files...")
                    self.verify_shared_files()
                    last_verify_files = now
                if now - last_cleanup >= CLEANUP_INTERVAL:
                    self.logger.debug("Maintenance: Cleaning up temp files...")
                    self.cleanup_temp_files(self.downloads_dir_path)
                    last_cleanup = now
                if now - last_stalled_check >= STALLED_CHECK_INTERVAL:
                    self.logger.debug("Maintenance: Checking for stalled downloads...")
                    self.check_stalled_downloads()
                    last_stalled_check = now

                # --- ADDED: Refresh full peer list ---
                if now - last_peer_list_refresh >= PEER_LIST_REFRESH_INTERVAL_ACTUAL:
                    self._refresh_peer_list_from_tracker()
                    last_peer_list_refresh = now
                # --- END ADDED ---

            except Exception as e:
                self.logger.error(f"[{thread_name}] Error during maintenance cycle: {e}", exc_info=True)

            elapsed = time.time() - start_time
            sleep_time = max(0.1, MAINTENANCE_INTERVAL - elapsed)
            # Use min sleep time based on maintenance interval to avoid busy loop if tasks take long
            # Ensure sleep_time is reasonably small, e.g., cap at MAINTENANCE_INTERVAL
            sleep_time = min(sleep_time, MAINTENANCE_INTERVAL)
            time.sleep(sleep_time)


        self.logger.info(f"[{thread_name}] Maintenance thread stopped.")
    
    def get_peers_for_file(self, file_hash: str) -> Tuple[Optional[List[Dict]], str]:
        """
        Fetches file info and a list of unique peers providing any chunk for a given file hash.

        Args:
            file_hash: The SHA1 hash of the file.

        Returns:
            A tuple containing:
            - A list of unique peer dictionaries (e.g., [{'peer_id':..., 'ip':..., 'port':..., 'tls_capable':...}, ...])
              or None if file info fails.
            - A status message string (e.g., "Success", "File not found", "Tracker error").
        """
        if not isinstance(file_hash, str) or len(file_hash) != 40:
            return None, "Invalid file hash format"

        self.logger.debug(f"Requesting file info and peers for file {file_hash[:8]}...")

        # 1. Get File Info (including chunk hashes) from Tracker
        try:
            file_info_response = self.send_to_tracker_with_retry(
                {'type': 'get_file_info', 'file_hash': file_hash}
            )
            if file_info_response.get('status') != 'success':
                msg = file_info_response.get('message', 'Tracker error fetching file info')
                self.logger.warning(f"Failed get_file_info {file_hash[:8]}: {msg}")
                return None, msg
            # Extract chunk hashes needed for the next step
            chunk_hashes = file_info_response.get('chunks')
            if not isinstance(chunk_hashes, list):
                 self.logger.error(f"Invalid chunk list in file info for {file_hash[:8]}.")
                 return None, "Invalid chunk list from tracker"
            if not chunk_hashes: # Handle 0-chunk files (e.g., 0-byte files)
                 self.logger.debug(f"File {file_hash[:8]} has 0 chunks. No peers to fetch.")
                 return [], "Success (0 chunks)" # Return empty list, success

        except Exception as e:
            self.logger.error(f"Error during get_file_info for {file_hash[:8]}: {e}", exc_info=True)
            return None, f"Error fetching file info: {e}"

        # 2. Get Peers for those Chunks (using existing internal method)
        try:
            peers_map = self._get_peers_for_chunks(chunk_hashes) # chunk_hash -> [peer_info, ...]
        except Exception as e:
            self.logger.error(f"Error during _get_peers_for_chunks for {file_hash[:8]}: {e}", exc_info=True)
            return None, f"Error fetching peers for chunks: {e}"

        # 3. Aggregate and De-duplicate Peer Information
        unique_peers = {} # Use dict keyed by peer_id for uniqueness
        for chunk_hash, peer_list in peers_map.items():
            for peer_info in peer_list:
                if isinstance(peer_info, dict) and 'peer_id' in peer_info:
                    # Store the most complete peer_info (or just the first encountered)
                    if peer_info['peer_id'] not in unique_peers:
                        unique_peers[peer_info['peer_id']] = peer_info

        aggregated_peer_list = list(unique_peers.values())
        num_peers = len(aggregated_peer_list)
        self.logger.debug(f"Found {num_peers} unique peers for file {file_hash[:8]}.")

        return aggregated_peer_list, "Success"


    def _download_chunk_from_peer(self, peer_info: Dict, chunk_info: Dict, file_hash: str) -> bool:
        """
        Attempts to download a specific chunk from a single peer via network.
        Handles TCP connection and optional TLS handshake based on peer capabilities.
        Note: The decision to *warn* about TLS mismatches is handled by the UI *before*
        this worker attempts the download. This function attempts connection based on mutual capability.
        """
        peer_id, peer_ip, peer_port = peer_info.get('peer_id'), peer_info.get('ip'), peer_info.get('port')
        chunk_hash, chunk_index, expected_size = chunk_info.get('hash'), chunk_info.get('index'), chunk_info.get('size', -1)
        thread_name = threading.current_thread().name

        # Basic validation of input
        if not all([peer_id, peer_ip, peer_port, chunk_hash]) or expected_size < 0:
            self.logger.error(f"[{thread_name}] Invalid arguments for chunk download: Peer {peer_id}, Chunk {chunk_index}/{chunk_hash}, Size {expected_size}")
            return False

        sock = None # Initialize socket variable
        start_time = time.monotonic()
        connected_protocol = "TCP" # Assume plain TCP initially
        try:
            # 1. Establish Connection (TCP + optional TLS)
            self.logger.debug(f"[{thread_name}] Connecting to {peer_id[:8]} ({peer_ip}:{peer_port}) for chunk {chunk_index}...")
            plain_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            plain_sock.settimeout(BASE_TIMEOUT) # Connection timeout
            plain_sock.connect((peer_ip, peer_port))
            sock = plain_sock # Start with plain socket

            # Determine if TLS should be attempted: Requires *both* peers to be configured for TLS.
            # The UI pre-check handles user warnings about mismatches.
            peer_is_tls_capable = peer_info.get('tls_capable', False)
            should_attempt_tls = self.use_tls and self.client_ssl_context and peer_is_tls_capable

            if should_attempt_tls:
                self.logger.debug(f"[{thread_name}] Attempting TLS handshake with {peer_id[:8]} (Peer TLS capable: {peer_is_tls_capable})...")
                try:
                    # Use IP for SNI/hostname check if required by context, adjust if using peer IDs/certs
                    sock = self.client_ssl_context.wrap_socket(plain_sock, server_side=False, server_hostname=peer_ip)
                    sock.settimeout(BASE_TIMEOUT) # Handshake timeout
                    sock.do_handshake() # Explicit handshake attempt
                    connected_protocol = "TLS" # Update protocol if successful
                    self.logger.debug(f"[{thread_name}] TLS handshake successful with {peer_id[:8]}. Protocol: {connected_protocol}")
                except (ssl.SSLError, socket.timeout, ConnectionError, OSError, Exception) as ssl_err:
                    # Log specific TLS failure reasons
                    if isinstance(ssl_err, ssl.SSLCertVerificationError):
                        self.logger.warning(f"[{thread_name}] TLS CERTIFICATE VERIFICATION FAILED with {peer_ip}:{peer_port}: {ssl_err}. Closing.")
                    elif isinstance(ssl_err, socket.timeout):
                         self.logger.warning(f"[{thread_name}] TLS handshake TIMEOUT with {peer_ip}:{peer_port}. Closing.")
                    elif isinstance(ssl_err, ssl.SSLError) and "WRONG_VERSION_NUMBER" in str(ssl_err):
                         self.logger.warning(f"[{thread_name}] TLS handshake failed with {peer_ip}:{peer_port} (Likely peer not using TLS): {ssl_err}. Closing.")
                    else:
                         self.logger.warning(f"[{thread_name}] TLS handshake failed with {peer_ip}:{peer_port}: {ssl_err}. Closing.")

                    try: plain_sock.close() # Ensure original socket is closed on TLS failure
                    except Exception: pass
                    return False # Treat TLS failure as download attempt failure for this peer
            else:
                 # Log why TLS wasn't attempted if applicable
                 if self.use_tls and not peer_is_tls_capable:
                      self.logger.debug(f"[{thread_name}] Not attempting TLS with {peer_id[:8]}: Peer reported not TLS capable.")
                 # If we are not use_tls, no message needed. Connection proceeds over TCP.
                 self.logger.debug(f"[{thread_name}] Proceeding with plain TCP connection to {peer_id[:8]}.")


            # Set timeout for subsequent operations on the established socket (plain or TLS)
            sock.settimeout(BASE_TIMEOUT)

            # 2. Send Chunk Request (JSON format)
            request_payload = json.dumps({'type': 'chunk_request', 'chunk_hash': chunk_hash, 'peer_id': self.peer_id}).encode('utf-8')
            request_header = b'J' + len(request_payload).to_bytes(4, 'big') # 'J' = JSON type
            self.logger.debug(f"[{thread_name}] Sending request for chunk {chunk_hash[:6]} to {peer_id[:8]} ({connected_protocol}).")
            sock.sendall(request_header + request_payload)

            # 3. Receive Response Header (Type(1) + Hash(40) + Size(4))
            self.logger.debug(f"[{thread_name}] Waiting for header from {peer_id[:8]}...")
            header = self._receive_all(sock, 45, BASE_TIMEOUT) # Read exactly 45 bytes
            if len(header) != 45:
                self.logger.warning(f"[{thread_name}] Failed to receive full header from {peer_id[:8]} (got {len(header)} bytes). Peer may be busy/choked or disconnected ({connected_protocol}).")
                return False

            resp_type, recv_hash_bytes, size_bytes = header[0:1], header[1:41], header[41:45]
            chunk_data_size = int.from_bytes(size_bytes, 'big')

            # 4. Validate Header Data
            if resp_type != b'D': # 'D' = Data response type expected
                # Check for specific rejection types if protocol evolves
                # e.g., if resp_type == b'C': self.logger.debug(...) # Choked response
                self.logger.debug(f"[{thread_name}] Peer {peer_id[:8]} denied chunk {chunk_hash[:6]} (Type: {resp_type!r}). Possibly choked or unavailable.")
                return False # Peer refused or sent wrong response type
            try: received_chunk_hash = recv_hash_bytes.decode('ascii')
            except UnicodeDecodeError: self.logger.warning(f"[{thread_name}] Invalid chunk hash encoding in header from {peer_id[:8]}."); return False
            # Check if hash and size match expectation
            if received_chunk_hash != chunk_hash or chunk_data_size != expected_size:
                self.logger.warning(f"[{thread_name}] Header mismatch from {peer_id[:8]}. ExpHash:{chunk_hash[:6]} Got:{received_chunk_hash[:6]}, ExpSize:{expected_size} Got:{chunk_data_size}")
                return False
            self.logger.debug(f"[{thread_name}] Header OK from {peer_id[:8]}. Expecting {chunk_data_size} bytes.")

            # 5. Receive Chunk Data
            chunk_data = b''
            if chunk_data_size > 0:
                # Calculate dynamic timeout based on expected size (e.g., min 8 KiB/s) + base
                data_receive_timeout = max(BASE_TIMEOUT, int(chunk_data_size / 8192) + 5)
                self.logger.debug(f"[{thread_name}] Receiving {chunk_data_size} bytes from {peer_id[:8]} ({connected_protocol}, Timeout: {data_receive_timeout}s)...")
                chunk_data = self._receive_all(sock, chunk_data_size, data_receive_timeout)
                if len(chunk_data) != chunk_data_size:
                     self.logger.warning(f"[{thread_name}] Incomplete chunk data received from {peer_id[:8]} (got {len(chunk_data)}/{chunk_data_size}).")
                     return False

            # 6. Verify Data Hash
            self.logger.debug(f"[{thread_name}] Verifying hash for chunk {chunk_index} from {peer_id[:8]}...")
            if hashlib.sha1(chunk_data).hexdigest() != chunk_hash:
                self.logger.warning(f"[{thread_name}] HASH MISMATCH for chunk {chunk_index} received from {peer_id[:8]}. Data corrupted?")
                return False

            # 7. Save Chunk to Temp File (updates stats internally)
            if self.save_chunk(file_hash, chunk_info, chunk_data):
                dl_bytes = len(chunk_data)
                # Update peer-specific download stats under lock
                with self.lock:
                    self.peer_download_stats[peer_id]['bytes_down_interval'] += dl_bytes
                duration = time.monotonic() - start_time
                self.logger.debug(f"[{thread_name}] Downloaded chunk {chunk_index} ({dl_bytes} bytes in {duration:.2f}s) from {peer_id[:8]} ({connected_protocol}).")
                return True # Chunk successfully downloaded and saved
            else:
                self.logger.error(f"[{thread_name}] Failed to save chunk {chunk_index} after receiving from {peer_id[:8]}.")
                return False # Saving failed

        except socket.timeout:
            self.logger.debug(f"[{thread_name}] Socket timeout during communication with {peer_id[:8]} for chunk {chunk_index} ({connected_protocol}).")
            return False
        except (ssl.SSLError, ConnectionError, BrokenPipeError, OSError) as e:
             # Consolidate common network errors
             self.logger.debug(f"[{thread_name}] Network error with {peer_id[:8]} for chunk {chunk_index} ({connected_protocol}): {type(e).__name__} - {e}")
             return False
        except Exception as e:
            # Catch any other unexpected errors during the process
            self.logger.error(f"[{thread_name}] Unexpected error downloading chunk {chunk_index} from {peer_id[:8]} ({connected_protocol}): {e}", exc_info=False) # Less verbose traceback for workers
            return False
        finally:
            # Ensure socket is closed
            if sock:
                try:
                    # Set linger option to 0 for quick close, discard unsent data
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                except Exception: pass # Ignore errors setting linger
                try:
                    sock.shutdown(socket.SHUT_RDWR) # Signal close intention
                except Exception: pass # Ignore errors if already closed
                try:
                    sock.close()
                except Exception: pass
        # Should not be reached normally if exceptions are handled
        return False


    def _receive_all(self, sock: socket.socket, length: int, timeout: float) -> bytes:
        """Helper function to reliably receive exactly 'length' bytes from a socket."""
        if length <= 0: return b''
        data = bytearray()
        bytes_left = length
        start_time = time.monotonic()
        # Use a short timeout for individual recv calls, but enforce overall timeout
        individual_timeout = max(0.1, min(timeout, 1.0)) # Short timeout, at least 0.1s

        while bytes_left > 0:
            # Check overall timeout
            if time.monotonic() - start_time > timeout:
                raise socket.timeout(f"Overall receive timeout ({timeout:.1f}s). Got {len(data)}/{length} bytes")

            try:
                sock.settimeout(individual_timeout) # Set short timeout for this recv call
                # Read smaller chunks to avoid blocking for too long on one recv
                chunk = sock.recv(min(bytes_left, 8192)) # Read up to 8KB
                if not chunk:
                    # Socket closed gracefully by the other end
                    raise ConnectionAbortedError(f"Socket closed by peer during receive. Got {len(data)}/{length}")
                data.extend(chunk)
                bytes_left -= len(chunk)
            except socket.timeout:
                # Expected if no data arrives within the short individual timeout
                continue # Continue loop and check overall timeout
            except ssl.SSLWantReadError:
                # Specific to non-blocking SSL sockets, wait briefly and retry
                time.sleep(0.01)
                continue
            except ssl.SSLWantWriteError:
                 # Should be rare on read, but handle possibility
                 time.sleep(0.01)
                 continue
            except (ssl.SSLError, ConnectionError, BrokenPipeError, OSError) as e:
                # Propagate significant network errors
                self.logger.debug(f"Network error during _receive_all: {e}")
                raise
            except Exception as e:
                # Propagate unexpected errors
                self.logger.error(f"Unexpected error during _receive_all: {e}", exc_info=True)
                raise
        # Return the complete data if loop finishes
        return bytes(data)

    def save_chunk(self, file_hash: str, chunk_info: Dict, data: bytes) -> bool:
        """Saves the downloaded chunk data to the correct offset in the temporary file."""
        chunk_index = chunk_info.get('index', -1)
        offset = chunk_info.get('offset', -1)
        expected_size = chunk_info.get('size', -1)

        # Basic validation
        if chunk_index < 0 or offset < 0 or expected_size < 0 or len(data) != expected_size:
            self.logger.error(f"Invalid data/metadata saving chunk {chunk_index}. Size:{len(data)}/{expected_size} Offset:{offset}")
            return False

        temp_path = None
        # Get temp_path safely under lock
        with self.lock:
            if file_hash not in self.downloads:
                 self.logger.warning(f"Download {file_hash[:8]} cancelled before chunk {chunk_index} could be saved.")
                 return False
            temp_path = self.downloads[file_hash].get('temp_path')

        if not temp_path:
            self.logger.error(f"Could not find temp path for download {file_hash[:8]} while saving chunk {chunk_index}.")
            return False

        try:
            # Perform file I/O (potential bottleneck, done outside main lock)
            # Ensure temp file still exists before opening
            if not os.path.exists(temp_path):
                 self.logger.error(f"Temporary file disappeared before save: '{temp_path}' Chunk:{chunk_index}")
                 return False

            # Open in read/write binary mode ('r+b')
            with open(temp_path, 'r+b') as f:
                lock_file(f) # Acquire file lock (best effort)
                try:
                    f.seek(offset) # Go to correct position
                    f.write(data) # Write chunk data
                    # Optional: Flush/fsync for robustness, but impacts performance
                    # f.flush(); os.fsync(f.fileno())
                finally:
                    unlock_file(f) # Release file lock

            # Update state under lock *after* successful write
            with self.lock:
                if file_hash in self.downloads: # Check again if download still active
                    # Mark chunk as available locally (important for sharing while downloading)
                    self.available_chunks.add(chunk_info['hash'])
                    self.chunk_sources.setdefault(chunk_info['hash'], set()).add(file_hash) # Mark this download as source
                    # Update download progress stats
                    self.downloads[file_hash]['bytes_since_last_calc'] += expected_size
                    self.downloads[file_hash]['downloaded_bytes'] += expected_size
                    # Note: Chunk status is updated by worker thread, not here.
                else:
                     # Download was cancelled during the save operation
                     self.logger.warning(f"Download {file_hash[:8]} cancelled during save IO for chunk {chunk_index}.")
                     return False # Indicate failure even though write might have happened
            return True # Chunk saved successfully

        except (IOError, OSError) as e:
            self.logger.error(f"File I/O error saving chunk {chunk_index} to '{os.path.basename(temp_path)}': {e}", exc_info=True)
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error saving chunk {chunk_index} ('{os.path.basename(temp_path)}'): {e}", exc_info=True)
            return False

    def finalize_download(self, file_hash: str, final_info: Optional[Dict]):
        """Completes download: renames temp file, verifies hash, potentially adds to shares."""
        # Check if final_info was actually provided (download might fail before completion)
        if not final_info:
            self.logger.debug(f"Finalize called for {file_hash[:8]} but no final info provided (likely failed/cancelled).")
            return

        temp_path = final_info.get('temp_path')
        final_path = final_info.get('save_path')
        expected_size = final_info.get('total_size')
        filename = final_info.get('filename')

        self.logger.info(f"Finalizing download: '{filename}' ({file_hash[:8]})")

        # Validate necessary info
        if not all([temp_path, final_path, filename]) or expected_size is None:
            self.logger.error(f"Missing critical info for finalization of {file_hash[:8]}. Cannot proceed.")
            return

        try:
            # Handle 0-byte files separately (no hash verification needed)
            if expected_size == 0:
                 # Ensure temp file exists (might be empty) before renaming/creating final
                 if os.path.exists(temp_path):
                     os.replace(temp_path, final_path) # Atomic rename
                 else:
                     # If temp somehow gone, just create empty final file
                     self.logger.warning(f"0-byte temp file missing for {file_hash[:8]}, creating empty final file.")
                     open(final_path, 'wb').close()
                 self.logger.info(f"Download complete (0 bytes): '{filename}' -> '{os.path.basename(final_path)}'")
            else: # Non-empty files
                # 1. Verify Temp File Size
                if not os.path.exists(temp_path) or os.path.getsize(temp_path) != expected_size:
                    raise ValueError(f"Temporary file size mismatch or missing: '{os.path.basename(temp_path)}'. Expected {expected_size}.")

                # 2. Verify Final Hash (CPU intensive, do before rename)
                self.logger.info(f"Verifying final hash for '{os.path.basename(temp_path)}'...")
                calculated_hash = self.calculate_file_hash(temp_path)
                if calculated_hash is None:
                     raise ValueError(f"Failed to calculate final hash for '{os.path.basename(temp_path)}'.")
                if calculated_hash != file_hash:
                    raise ValueError(f"Final hash verification failed! Expected {file_hash[:8]}, Got {calculated_hash[:8]}. Download corrupted?")
                self.logger.info(f"Final hash verified successfully for '{filename}'.")

                # 3. Rename Temp to Final File (Atomic on same filesystem)
                self.logger.debug(f"Renaming '{os.path.basename(temp_path)}' to '{os.path.basename(final_path)}'")
                os.replace(temp_path, final_path)
                self.logger.info(f"Download complete: '{filename}' saved to '{os.path.basename(final_path)}'")

            # 4. Share if downloaded into the designated shared directory
            final_abs_path = os.path.abspath(final_path)
            shared_abs_path = os.path.abspath(self.shared_dir_path)
            # Check if the final path starts with the shared directory path
            if final_abs_path.startswith(shared_abs_path + os.sep):
                self.logger.info(f"Downloaded file '{filename}' is in the shared directory. Adding to local shares...")
                # Add minimal info needed for sharing state (re-use chunk metadata if possible)
                with self.lock:
                     chunk_objects_for_share = final_info.get('chunk_objects', []) # Re-use chunk list
                     # Ensure the chunk list format is suitable for sharing state
                     self.shared_files[final_abs_path] = {
                         'filename': filename, 'hash': file_hash,
                         'chunks': chunk_objects_for_share, # Assuming format is compatible
                         'size': expected_size
                     }
                     # Ensure all chunks are marked as available (should be, but double-check)
                     for chunk_meta in chunk_objects_for_share:
                         ch = chunk_meta.get('hash')
                         if ch: self.available_chunks.add(ch)
                # Optionally trigger an update_chunks to tracker? share_file normally handles publish.
                # Since this is post-download, an update might be good practice.
                self.update_tracker_chunks() # Inform tracker we now have these chunks

        except (ValueError, OSError) as e:
             # Log failure and keep the temp file for inspection
             self.logger.error(f"Download finalization failed for '{filename}' ({file_hash[:8]}): {e}")
             if temp_path and os.path.exists(temp_path):
                 self.logger.error(f"Keeping potentially corrupted/failed temp file: '{temp_path}'")
        except Exception as e:
            # Catch any other unexpected errors during finalization
            self.logger.error(f"Unexpected error finalizing download '{filename}': {e}", exc_info=True)
            if temp_path and os.path.exists(temp_path):
                 self.logger.error(f"Keeping temp file due to unexpected finalization error: '{temp_path}'")

    def cancel_download(self, file_hash: str) -> bool:
        """
        Stops an active download, cleans up state, and removes the temp file.
        Returns True if the download was found and cancellation initiated, False otherwise.
        """
        self.logger.info(f"Received request to cancel download: {file_hash[:8]}")
        temp_path_to_remove = None
        cancelled = False

        with self.lock:
            if file_hash in self.downloads:
                info = self.downloads.pop(file_hash) # Remove from active downloads immediately
                cancelled = True
                temp_path_to_remove = info.get('temp_path')
                filename = info.get('filename', f'file_{file_hash[:8]}')
                self.logger.info(f"Removed download '{filename}' ({file_hash[:8]}) from active state.")

                # Clean up chunk sources if this download was the only provider
                for chunk_meta in info.get('chunk_objects', []):
                    ch = chunk_meta.get('hash')
                    if ch and ch in self.chunk_sources:
                        # Check if the file_hash we are cancelling is in the sources for this chunk
                        if file_hash in self.chunk_sources[ch]:
                            self.chunk_sources[ch].discard(file_hash)
                            # If no other file provides this chunk anymore, remove from chunk_sources
                            if not self.chunk_sources[ch]:
                                self.chunk_sources.pop(ch, None)
                                # Also remove from available_chunks if truly no longer available
                                self.available_chunks.discard(ch)
                                self.logger.debug(f"Chunk {ch[:6]} removed from sources/available due to download cancel.")

                # Signal any active workers? Daemon threads check self.running,
                # but more direct cancellation isn't straightforward without passing signals.
                # Removing the download state is the primary mechanism to stop workers
                # from saving data or starting new chunks for this download.
                # Workers might finish their current chunk attempt but won't proceed further.
                active_workers = info.get('active_workers', set())
                if active_workers:
                    self.logger.debug(f"Cancellation: {len(active_workers)} workers associated with {file_hash[:8]} will stop processing after current task.")

            else:
                self.logger.warning(f"Cannot cancel download {file_hash[:8]}: Not found in active downloads.")
                cancelled = False

        # Remove temp file outside the lock
        if temp_path_to_remove:
            if os.path.exists(temp_path_to_remove):
                self.logger.info(f"Attempting to remove temp file: {os.path.basename(temp_path_to_remove)}")
                try:
                    os.remove(temp_path_to_remove)
                    self.logger.info(f"Successfully removed temp file: {os.path.basename(temp_path_to_remove)}")
                except OSError as e:
                    self.logger.error(f"Failed to remove temp file '{os.path.basename(temp_path_to_remove)}' during cancellation: {e}")
            else:
                 self.logger.debug(f"Temp file '{os.path.basename(temp_path_to_remove)}' not found for removal during cancel.")

        return cancelled

    def send_to_tracker(self, message: Dict) -> Dict:
        """Sends a single JSON message to the tracker and returns the JSON response."""
        try:
            # Create a new connection for each request
            with socket.create_connection((self.tracker_host, self.tracker_port), timeout=BASE_TIMEOUT) as s:
                # Send message (Length-prefixed JSON)
                data = json.dumps(message).encode('utf-8')
                s.sendall(len(data).to_bytes(4, 'big') + data)

                # Receive response length (4 bytes)
                len_bytes = self._receive_all(s, 4, BASE_TIMEOUT)
                if len(len_bytes) != 4: raise ConnectionError("Tracker length receive failed.")
                response_len = int.from_bytes(len_bytes, 'big')

                # Basic validation of response length
                MAX_TRACKER_RESPONSE = 10 * 1024 * 1024 # 10 MB limit
                if not 0 <= response_len <= MAX_TRACKER_RESPONSE:
                    raise ConnectionError(f"Tracker sent invalid response length: {response_len}")

                # Receive response data
                response_data = b''
                if response_len > 0:
                    # Dynamic timeout based on expected length
                    response_timeout = max(BASE_TIMEOUT, int(response_len / (50*1024)) + 5) # Min ~50 KiB/s + base
                    response_data = self._receive_all(s, response_len, response_timeout)
                    if len(response_data) != response_len:
                        raise ConnectionError("Tracker response incomplete.")

                # Decode JSON response
                return json.loads(response_data.decode('utf-8')) if response_data else {}
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to decode tracker JSON response: {e}")
            raise ConnectionError(f"Tracker JSON decode error: {e}")
        except socket.timeout:
            self.logger.warning(f"Timeout connecting to tracker {self.tracker_host}:{self.tracker_port}")
            raise ConnectionError(f"Tracker timeout {self.tracker_host}:{self.tracker_port}")
        except ConnectionRefusedError:
            self.logger.error(f"Tracker connection refused at {self.tracker_host}:{self.tracker_port}")
            raise ConnectionError(f"Tracker connection refused {self.tracker_host}:{self.tracker_port}")
        except (ConnectionError, ConnectionResetError, BrokenPipeError, OSError) as e:
            # General network errors
            self.logger.error(f"Network error communicating with tracker: {e}")
            raise ConnectionError(f"Tracker connection error: {e}")
        except Exception as e:
            # Catch-all for other unexpected errors
            self.logger.error(f"Unexpected error communicating with tracker: {e}", exc_info=True)
            raise ConnectionError(f"Unexpected tracker error: {e}")

    def send_to_tracker_with_retry(self, message: Dict, retries: int = TRACKER_RETRIES) -> Dict:
        """Sends a message to the tracker with exponential backoff retry logic."""
        last_exception = None
        for attempt in range(max(1, retries)):
            try:
                # Attempt to send the message
                return self.send_to_tracker(message)
            except ConnectionError as e:
                # Handle expected connection errors
                last_exception = e
                self.logger.warning(f"Tracker comm failed (Attempt {attempt+1}/{retries}): {e}")
            except Exception as e:
                # Handle unexpected errors during communication
                last_exception = e
                self.logger.error(f"Unexpected tracker comm error (Attempt {attempt+1}/{retries}): {e}", exc_info=True)

            # If not the last attempt, wait and retry
            if attempt < retries - 1:
                delay = (1.5 ** attempt) + random.uniform(0.1, 0.5) # Exponential backoff
                self.logger.info(f"Retrying tracker communication in {delay:.1f}s...")
                time.sleep(delay)
            else:
                # Last attempt failed
                self.logger.error(f"Tracker unreachable after {retries} attempts: {last_exception}")
                return {'status': 'error', 'message': f'Tracker unavailable: {last_exception}'}
        # Fallback error message (shouldn't be reached if retries >= 1)
        return {'status': 'error', 'message': f'Tracker request failed after retries: {last_exception}'}

    def register_with_tracker(self):
        """Registers this peer with the tracker, sending initial chunk list."""
        self.logger.info(f"Registering with tracker {self.tracker_host}:{self.tracker_port}...")
        # Get current list of available chunks under lock
        with self.lock: initial_chunk_hashes = list(self.available_chunks)
        # Construct registration message
        message = {
            'type': 'register',
            'peer_id': self.peer_id,
            'ip': self.ip,
            'port': self.port,
            'tls_capable': self.use_tls,
            'initial_chunk_hashes': initial_chunk_hashes # Send chunks we have at startup
        }
        try:
            # Send message with retry logic
            response = self.send_to_tracker_with_retry(message)
            if response.get('status') == 'success':
                self.logger.info(f"Successfully registered with tracker. Peer ID: {self.peer_id[:8]}. Initial Chunks: {len(initial_chunk_hashes)}")
            else:
                # Log specific error from tracker if available
                self.logger.error(f"Tracker registration failed: {response.get('message', 'Unknown error')}")
        except Exception as e:
            # Catch errors from send_to_tracker_with_retry itself
            self.logger.critical(f"Could not register with tracker due to exception: {e}", exc_info=True)

    # --- START OF MODIFIED accept_connections ---
    def accept_connections(self):
        """
        Accepts incoming connections as plain TCP and passes them to a handler
        which will optionally negotiate/enforce TLS.
        """
        thread_name = threading.current_thread().name
        tls_status = 'ENABLED' if self.use_tls else 'DISABLED'
        # Log the effective policy
        allow_insec_str = str(self.allow_insecure_uploads_if_tls) if self.use_tls else 'N/A (TLS Disabled)'
        self.logger.info(f"[{thread_name}] Acceptor started (TLS: {tls_status}, Allow Insecure When TLS: {allow_insec_str}). Listening...")

        while self.running:
            server_sock = self.server_socket
            if not server_sock:
                if not self.running: break
                self.logger.warning(f"[{thread_name}] Server socket closed. Restarting in 5s...")
                time.sleep(5)
                self.server_socket = self.setup_server_socket()
                if not self.server_socket: # Check if restart failed
                    self.logger.error(f"[{thread_name}] Failed to restart server socket. Acceptor stopping.")
                    self.running = False # Stop the peer if socket cannot be setup
                    break
                continue

            try:
                server_sock.settimeout(1.0)
                try:
                    conn, addr = server_sock.accept() # Always accept plain TCP first
                except socket.timeout:
                    continue # Normal timeout, check self.running

                peer_ip, peer_port = addr
                self.logger.debug(f"[{thread_name}] Accepted PLAIN connection from {peer_ip}:{peer_port}. Starting handler...")
                conn.settimeout(BASE_TIMEOUT) # Timeout for initial operations within handler

                # Start the handler thread that will manage potential TLS upgrade/enforcement
                handler_name = f"PH-{peer_ip}-{peer_port}"
                handler_thread = threading.Thread(target=self.handle_peer_connection_negotiate, # Use the NEW handler
                                                  args=(conn, addr),
                                                  name=handler_name, daemon=True)
                handler_thread.start()

            except OSError as e:
                if not self.running: break # Expected if shutting down normally
                self.logger.error(f"[{thread_name}] OS error in accept loop: {e}. Resetting server socket.")
                # Close the problematic socket and signal for re-setup
                if server_sock:
                    try: server_sock.close()
                    except Exception: pass
                self.server_socket = None # Signal need for re-setup
                time.sleep(2) # Wait a bit before retrying setup
            except Exception as e:
                # Catch any other unexpected errors in the accept loop
                if self.running:
                    self.logger.error(f"[{thread_name}] Unexpected error in accept loop: {e}", exc_info=True)
                else:
                    break # Exit loop if not running
                time.sleep(2) # Pause before potentially retrying

        self.logger.info(f"[{thread_name}] Acceptor thread stopped.")
        # Final cleanup of the server socket on exit
        if self.server_socket:
             try:
                 self.server_socket.close()
                 self.logger.info("Server socket closed on acceptor stop.")
             except Exception: pass
             self.server_socket = None

    def handle_peer_connection(self, conn: socket.socket, addr: Tuple[str, int]):
        """Handles communication with a single connected peer."""
        peer_ip, peer_port = addr
        thread_name = threading.current_thread().name
        protocol = "TLS" if isinstance(conn, ssl.SSLSocket) else "TCP"
        requesting_peer_id = "Unknown" # Track peer ID once received
        self.logger.debug(f"[{thread_name}] Handling connection from {peer_ip}:{peer_port} ({protocol})")

        try:
            # Use context manager to ensure socket is closed automatically
            with conn:
                # Receive message header (Type Byte + 4 Length Bytes)
                header = self._receive_all(conn, 5, BASE_TIMEOUT)
                if len(header) != 5:
                    self.logger.debug(f"[{thread_name}] Failed to receive header from {peer_ip}:{peer_port}. Disconnected?")
                    return

                msg_type_byte, msg_len = header[0:1], int.from_bytes(header[1:5], 'big')

                # Validate message length
                MAX_PEER_MSG_SIZE = 1 * 1024 * 1024 # 1MB limit for JSON messages
                if not 0 <= msg_len <= MAX_PEER_MSG_SIZE:
                    self.logger.warning(f"[{thread_name}] Invalid message length ({msg_len}) received from {peer_ip}:{peer_port}. Closing.")
                    return

                # Receive message payload
                payload = b''
                if msg_len > 0:
                    # Calculate dynamic timeout for payload reception
                    payload_timeout = max(BASE_TIMEOUT, int(msg_len/(10*1024)) + 5) # Min ~10KiB/s + base
                    payload = self._receive_all(conn, msg_len, payload_timeout)
                    if len(payload) != msg_len:
                         self.logger.warning(f"[{thread_name}] Incomplete payload received from {peer_ip}:{peer_port} (got {len(payload)}/{msg_len}).")
                         return

                # Process message based on type byte
                if msg_type_byte == b'J': # JSON Message
                    try:
                        message = json.loads(payload.decode('utf-8'))
                        requesting_peer_id = message.get('peer_id', 'Unknown') # Get peer ID from message
                        self.logger.debug(f"[{thread_name}] Received JSON '{message.get('type', 'N/A')}' from {requesting_peer_id[:8]} ({peer_ip})")
                        # Route the decoded JSON message for processing
                        self.process_peer_json_message(conn, addr, message, requesting_peer_id)
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        self.logger.warning(f"[{thread_name}] Invalid JSON/UTF8 received from {peer_ip}:{peer_port}: {e}")
                    except Exception as e:
                        self.logger.error(f"[{thread_name}] Error processing JSON from {requesting_peer_id[:8]}: {e}", exc_info=True)
                # Add handlers for other message types (e.g., binary) here if needed
                # elif msg_type_byte == b'B': # Example for Binary
                #     self.process_peer_binary_message(conn, addr, payload)
                else:
                    # Unknown message type
                    self.logger.warning(f"[{thread_name}] Received unknown message type {msg_type_byte!r} from {peer_ip}:{peer_port}.")

        except socket.timeout:
            self.logger.debug(f"[{thread_name}] Socket timeout with {peer_ip}:{peer_port} ({protocol}).")
        except (ConnectionError, BrokenPipeError, ssl.SSLError) as e:
             # Log common network errors at DEBUG level
             self.logger.debug(f"[{thread_name}] Network error with {peer_ip}:{peer_port} ({protocol}): {type(e).__name__}")
        except OSError as e:
             # Log potentially more serious OS errors
             self.logger.warning(f"[{thread_name}] OS Network Error handling connection ({protocol}) {peer_ip}:{peer_port}: {e}")
        except Exception as e:
            # Log any other unexpected errors during connection handling
            self.logger.error(f"[{thread_name}] Unhandled error handling connection ({protocol}) {peer_ip}:{peer_port}: {e}", exc_info=False) # Less verbose TB for handlers
        finally:
            self.logger.debug(f"[{thread_name}] Finished handling connection from {peer_ip}:{peer_port}.")
            # Socket is closed automatically by the 'with conn:' statement

    def handle_peer_connection_negotiate(self, conn: socket.socket, addr: Tuple[str, int]):
        """
        Handles an incoming connection. Reads the first message and decides
        whether to proceed with plain TCP or attempt/enforce TLS based on server config.
        """
        peer_ip, peer_port = addr
        thread_name = threading.current_thread().name
        initial_protocol = "TCP"
        handler_socket = conn # Start with the plain socket
        final_protocol = initial_protocol # Will be updated if TLS succeeds
        connection_closed = False # Flag to prevent double closing

        try:
            # --- TLS Decision Point ---
            attempt_tls = False
            require_tls = False

            if self.use_tls and self.server_ssl_context:
                # Server has TLS capability. Check policy.
                if not self.allow_insecure_uploads_if_tls:
                    # Strict Mode: We MUST use TLS if available.
                    self.logger.debug(f"[{thread_name}] Strict TLS mode. Attempting TLS handshake with {peer_ip}:{peer_port}...")
                    attempt_tls = True
                    require_tls = True # Handshake MUST succeed
                else:
                    # Permissive Mode: Server *prefers* TLS but *allows* plain TCP.
                    # We will proceed with plain TCP and let the message processing happen.
                    # A sophisticated client *could* potentially send a STARTTLS command,
                    # but this implementation doesn't explicitly handle that.
                    self.logger.debug(f"[{thread_name}] Permissive TLS mode. Waiting for client request on plain socket {peer_ip}:{peer_port}...")
                    attempt_tls = False
                    require_tls = False
            else:
                # Server is not TLS enabled, proceed with plain TCP.
                self.logger.debug(f"[{thread_name}] TLS disabled locally. Proceeding plain TCP with {peer_ip}:{peer_port}.")
                attempt_tls = False
                require_tls = False

            # --- Attempt TLS Handshake (if required by strict mode) ---
            if attempt_tls:
                try:
                    # Wrap the existing socket server-side
                    # Note: Do not assign back to 'conn', use 'handler_socket'
                    handler_socket = self.server_ssl_context.wrap_socket(conn, server_side=True)
                    handler_socket.settimeout(BASE_TIMEOUT) # Handshake timeout
                    # Handshake happens implicitly on first read/write or explicitly:
                    # handler_socket.do_handshake() # Might be needed depending on context usage
                    final_protocol = "TLS"
                    self.logger.info(f"[{thread_name}] TLS handshake successful with {peer_ip}:{peer_port}.")
                except (ssl.SSLError, socket.timeout, ConnectionError, OSError, Exception) as ssl_err:
                    self.logger.warning(f"[{thread_name}] TLS handshake FAILED with {peer_ip}:{peer_port}: {ssl_err}")
                    # Since require_tls must be True if attempt_tls is True in this logic:
                    self.logger.warning(f"[{thread_name}] Closing connection due to failed required TLS handshake.")
                    # Close the ORIGINAL socket 'conn' as wrap failed
                    try: conn.close()
                    except Exception: pass
                    connection_closed = True # Mark as closed
                    return # Abort handling

            # --- Proceed to read and process messages using the final socket ---
            # Pass the final socket (plain 'conn' or TLS-wrapped 'handler_socket')
            self.process_message_stream(handler_socket, addr, final_protocol)

        except socket.timeout:
            self.logger.debug(f"[{thread_name}] Socket timeout with {peer_ip}:{peer_port} ({final_protocol}).")
        except ConnectionAbortedError:
             self.logger.debug(f"[{thread_name}] Connection aborted by peer {peer_ip}:{peer_port} ({final_protocol}).")
        except (ConnectionResetError, BrokenPipeError) as e:
             self.logger.debug(f"[{thread_name}] Connection error with peer {peer_ip}:{peer_port} ({final_protocol}): {type(e).__name__}")
        except ssl.SSLError as e:
             # Catch SSL errors that might happen *after* handshake during read/write
             self.logger.warning(f"[{thread_name}] SSL error during communication with {peer_ip}:{peer_port}: {e}")
        except OSError as e:
             # Catch lower-level OS errors
             self.logger.warning(f"[{thread_name}] OS Network Error handling connection ({final_protocol}) {peer_ip}:{peer_port}: {e}")
        except Exception as e:
            # Catch any other unexpected errors
            self.logger.error(f"[{thread_name}] Unhandled error handling connection ({final_protocol}) {peer_ip}:{peer_port}: {e}", exc_info=False) # Less verbose traceback
        finally:
             self.logger.debug(f"[{thread_name}] Finished handling connection ({final_protocol}) from {peer_ip}:{peer_port}.")
             # Ensure the final socket is closed if it wasn't already closed due to an error above
             if not connection_closed and handler_socket:
                 try:
                      # Set linger to 0 for quick close if possible
                      handler_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                 except Exception: pass
                 try:
                      handler_socket.shutdown(socket.SHUT_RDWR)
                 except Exception: pass
                 try:
                      handler_socket.close()
                 except Exception: pass

    def process_message_stream(self, sock: socket.socket, addr: Tuple[str, int], protocol: str):
        """Reads and processes one message from an established connection (plain or TLS)."""
        peer_ip, peer_port = addr
        thread_name = threading.current_thread().name
        requesting_peer_id = "Unknown" # Reset per connection

        # This function processes ONE message per connection attempt, as per original design.
        # For persistent connections, a `while self.running:` loop would go here.
        try:
            # Receive message header (Type Byte + 4 Length Bytes)
            header = self._receive_all(sock, 5, BASE_TIMEOUT)
            if len(header) != 5:
                # If header read fails, assume disconnect or bad client.
                if len(header) == 0: # Clean disconnect before sending anything
                     self.logger.debug(f"[{thread_name}] Connection closed by {peer_ip}:{peer_port} ({protocol}) before sending data.")
                else: # Partial header or unexpected data
                    self.logger.debug(f"[{thread_name}] Failed header read (got {len(header)} bytes) from {peer_ip}:{peer_port} ({protocol}). Disconnecting.")
                return # Exit processing for this connection

            msg_type_byte, msg_len = header[0:1], int.from_bytes(header[1:5], 'big')

            MAX_PEER_MSG_SIZE = 1 * 1024 * 1024
            if not 0 <= msg_len <= MAX_PEER_MSG_SIZE:
                self.logger.warning(f"[{thread_name}] Invalid msg len ({msg_len}) from {peer_ip}:{peer_port} ({protocol}). Closing.")
                # We might have already closed in negotiate, but try closing the final socket 'sock' just in case.
                # Error response cannot be sent reliably here.
                return

            payload = b''
            if msg_len > 0:
                # Use a potentially longer timeout for payload based on length
                payload_timeout = max(BASE_TIMEOUT, int(msg_len/(10*1024)) + 10) # Min ~10KiB/s + base
                payload = self._receive_all(sock, msg_len, payload_timeout)
                if len(payload) != msg_len:
                     self.logger.warning(f"[{thread_name}] Incomplete payload from {peer_ip}:{peer_port} ({protocol}). Got {len(payload)}/{msg_len}. Disconnecting.")
                     return # Incomplete message, cannot process reliably

            # Process message based on type byte
            if msg_type_byte == b'J': # JSON Message
                try:
                    message = json.loads(payload.decode('utf-8'))
                    # Get Peer ID AFTER decoding the message
                    requesting_peer_id = message.get('peer_id', 'Unknown')
                    log_prefix = f"Peer {requesting_peer_id[:8]}" if requesting_peer_id != 'Unknown' else f"Addr {peer_ip}"
                    self.logger.debug(f"[{thread_name}] Received JSON '{message.get('type', 'N/A')}' from {log_prefix} ({peer_ip}) ({protocol})")

                    # Route the decoded JSON message for processing, pass the final socket
                    self.process_peer_json_message(sock, addr, message, requesting_peer_id)

                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    self.logger.warning(f"[{thread_name}] Invalid JSON/UTF8 from {peer_ip}:{peer_port} ({protocol}): {e}")
                # Note: Exception during processing inside process_peer_json_message
                # will be logged there. This function's job is just to read and dispatch.
            # Add handlers for other message types if needed
            # elif msg_type_byte == b'B': ...
            else:
                self.logger.warning(f"[{thread_name}] Unknown message type {msg_type_byte!r} from {peer_ip}:{peer_port} ({protocol}).")

        except (socket.timeout, ConnectionAbortedError, ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError) as e:
             # These errors indicate the stream is broken, re-raise them to be caught by the caller
             raise e
        except Exception as e:
             # Catch unexpected errors during read/decode itself
             self.logger.error(f"[{thread_name}] Unexpected error processing stream from {peer_ip}:{peer_port} ({protocol}): {e}", exc_info=True)
             # Re-raise to ensure connection cleanup happens in the caller
             raise e

    def process_peer_json_message(self, sock: socket.socket, addr: Tuple[str, int], message: Dict, requesting_peer_id: str):
        """Routes incoming JSON messages from peers to appropriate handlers."""
        msg_type = message.get('type')
        thread_name = threading.current_thread().name
        # Determine protocol based on the socket type passed in
        protocol = "TLS" if isinstance(sock, ssl.SSLSocket) else "TCP"

        # Record interest from the requesting peer (used for choking decisions)
        if requesting_peer_id != "Unknown":
             # Update last_seen under lock
             with self.lock:
                 self.interested_peers[requesting_peer_id] = time.time()
                 # Also update the main peer record's last_seen if they are registered
                 if requesting_peer_id in self.peers:
                      self.peers[requesting_peer_id]['last_seen'] = time.time()

        # Route message based on 'type' field
        if msg_type == 'chunk_request':
            # Pass the final socket (plain or TLS) to the handler
            self.handle_chunk_request(sock, addr, message, requesting_peer_id)
        # --- Add other handlers here if needed, passing 'sock' ---
        # Example:
        # elif msg_type == 'have':
        #     self.handle_have_message(sock, addr, message, requesting_peer_id)
        else:
            self.logger.warning(f"[{thread_name}] Received unknown JSON message type '{msg_type}' from {requesting_peer_id[:8]} ({protocol}).")
            # Optionally send an error response back via 'sock'?
            # response = {'status': 'error', 'message': f'Unknown message type: {msg_type}'}
            # self._send_response(sock, response, f"Peer {requesting_peer_id[:8]}") # Requires _send_response helper

    def handle_chunk_request(self, conn: socket.socket, addr: Tuple[str, int], message: Dict, requesting_peer_id: str):
        """
        Handles a 'chunk_request' message from a peer. Sends data if available
        and peer is unchoked. Uses the provided socket (plain or TLS).
        """
        thread_name = threading.current_thread().name
        chunk_hash = message.get('chunk_hash')
        # Determine protocol based on the socket type passed in
        protocol = "TLS" if isinstance(conn, ssl.SSLSocket) else "TCP"

        # Validate request
        if not isinstance(chunk_hash, str) or len(chunk_hash) != 40 or requesting_peer_id == "Unknown":
            self.logger.warning(f"[{thread_name}] Invalid chunk_request ({protocol}) received: {message} from {addr[0]}:{addr[1]}")
            # Optionally send error response?
            # self._send_response(conn, {'status': 'error', 'message': 'Invalid chunk request'}, f"Addr {addr[0]}")
            return

        self.logger.debug(f"[{thread_name}] Received chunk request for {chunk_hash[:8]} from {requesting_peer_id[:8]} ({protocol}).")

        filepath = None
        chunk_metadata = None
        is_unchoked = False
        read_from_temp = False

        # --- Check Availability and Choking Status (Under Lock) ---
        with self.lock:
            # Check if the peer is registered (should be if they sent a valid peer_id)
            if requesting_peer_id not in self.peers:
                 self.logger.warning(f"[{thread_name}] Chunk request from unregistered peer {requesting_peer_id[:8]} ({addr[0]})? Ignoring.")
                 # Optionally send error
                 # self._send_response(conn, {'status': 'error', 'message': 'Peer not registered'}, f"Peer {requesting_peer_id[:8]}")
                 return

            # Check if we are choking this peer
            is_unchoked = requesting_peer_id in self.unchoked_upload_peers
            if not is_unchoked:
                self.logger.debug(f"[{thread_name}] IGNORING request for {chunk_hash[:6]} from {requesting_peer_id[:8]} - Peer is CHOKED ({protocol}).")
                # Don't send data, but don't necessarily close connection immediately.
                # Optionally send a DENY header? (e.g., type 'X')
                # header = b'X' + chunk_hash.encode('ascii') + (0).to_bytes(4, 'big')
                # try: conn.sendall(header)
                # except Exception: pass # Ignore send errors on denial
                return

            # --- Peer is UNCHOKED, proceed to find chunk ---
            self.logger.debug(f"[{thread_name}] Peer {requesting_peer_id[:8]} is UNCHOKED ({protocol}). Checking chunk {chunk_hash[:6]}...")

            # Check if we have the requested chunk
            if chunk_hash in self.available_chunks:
                file_hash_source = self.chunk_sources.get(chunk_hash)
                if file_hash_source:
                    # [ Logic to find filepath, chunk_metadata, read_from_temp remains the same ]
                    # ... (find path in self.shared_files or self.downloads) ...
                    found_in_shared = False
                    # Check shared files first
                    for f_hash_src in file_hash_source:
                        for fpath, finfo in self.shared_files.items():
                            if finfo.get('hash') == f_hash_src:
                                for chunk_meta in finfo.get('chunks', []):
                                    if chunk_meta.get('hash') == chunk_hash:
                                        filepath, chunk_metadata, read_from_temp = fpath, chunk_meta, False
                                        found_in_shared = True; break
                                if found_in_shared: break
                        if found_in_shared: break
                    # If not in shared, check active downloads (temp files)
                    if not found_in_shared:
                         for f_hash_src in file_hash_source:
                             if f_hash_src in self.downloads:
                                 dl_info = self.downloads[f_hash_src]
                                 for chunk_meta in dl_info.get('chunk_objects', []):
                                     # Check if chunk is downloaded and complete
                                     if chunk_meta.get('hash') == chunk_hash and chunk_meta.get('status') == 'complete':
                                         filepath, chunk_metadata, read_from_temp = dl_info.get('temp_path'), chunk_meta, True
                                         self.logger.debug(f"[{thread_name}] Found chunk {chunk_hash[:6]} in temp file of DL {f_hash_src[:6]}")
                                         break
                                 if filepath: break # Found in a download
            # Check if found and valid
            if not filepath or not chunk_metadata:
                self.logger.warning(f"[{thread_name}] Chunk {chunk_hash[:6]} requested by UNCHOKED peer {requesting_peer_id[:8]} ({protocol}) is available but NOT FOUND in state!")
                # Send denial? Type 'N' for Not Found?
                # header = b'N' + chunk_hash.encode('ascii') + (0).to_bytes(4, 'big')
                # try: conn.sendall(header)
                # except Exception: pass
                return

            offset = chunk_metadata.get('offset', -1)
            size = chunk_metadata.get('size', -1)
            if offset < 0 or size < 0:
                self.logger.error(f"[{thread_name}] Invalid metadata for chunk {chunk_hash[:6]} ({protocol}). Offset:{offset}, Size:{size}.")
                # Send denial? Type 'E' for Error?
                # header = b'E' + chunk_hash.encode('ascii') + (0).to_bytes(4, 'big')
                # try: conn.sendall(header)
                # except Exception: pass
                return
        # --- End Lock ---

        # --- Read and Send Data (Outside Lock) ---
        chunk_data = None
        try:
            if not os.path.exists(filepath):
                self.logger.warning(f"[{thread_name}] File disappeared before sending chunk: '{os.path.basename(filepath)}'. Chunk:{chunk_hash[:6]} to {requesting_peer_id[:8]} ({protocol})")
                # Send denial 'N'?
                return

            self.logger.debug(f"[{thread_name}] Reading chunk {chunk_metadata.get('index','?')} ({size}b) from '{os.path.basename(filepath)}' for {requesting_peer_id[:8]} ({protocol})...")
            with open(filepath, 'rb') as f:
                lock_file(f)
                try:
                    f.seek(offset)
                    chunk_data = f.read(size) # Read data into memory
                finally:
                    unlock_file(f)

            if chunk_data is None or len(chunk_data) != size:
                self.logger.error(f"[{thread_name}] Read incorrect size for chunk {chunk_hash[:6]} ({protocol}). Got {len(chunk_data) if chunk_data else 'None'}, expected {size}")
                # Send denial 'E'?
                return

            # Construct header: Type(1)=D + Hash(40) + Size(4)
            header = b'D' + chunk_hash.encode('ascii') + size.to_bytes(4,'big')
            self.logger.debug(f"[{thread_name}] Sending chunk {chunk_metadata.get('index','?')} header+data ({size} bytes) to {requesting_peer_id[:8]} ({protocol})...")

            # *** Use the passed socket (conn) which might be plain or TLS ***
            conn.sendall(header + chunk_data)

            # --- Update Stats (Under Lock) ---
            with self.lock:
                # Update upload rate TO this specific peer
                # Ensure defaultdict creates entry if peer disconnected during read/send
                self.peer_upload_stats.setdefault(requesting_peer_id, {'bytes_up_interval': 0, 'rate_bps': 0.0})['bytes_up_interval'] += size

            source_type = 'temp' if read_from_temp else 'shared'
            self.logger.info(f"[{thread_name}] SENT chunk {chunk_metadata.get('index','?')} ({chunk_hash[:6]}, {size}b, {source_type}) -> {requesting_peer_id[:8]} ({protocol}).")

        except (IOError, OSError) as e:
             # File reading errors
             self.logger.warning(f"[{thread_name}] IO/OS Error sending chunk {chunk_hash[:8]} to {requesting_peer_id[:8]} ({protocol}): {e}")
             # Cannot reliably send denial if read failed. Connection likely closed by finally block.
        except (ConnectionError, BrokenPipeError, ssl.SSLError, socket.timeout) as e:
             # Network errors during sendall
             self.logger.debug(f"[{thread_name}] Network error sending chunk {chunk_hash[:8]} to {requesting_peer_id[:8]} ({protocol}): {type(e).__name__} - {e}")
             # Connection is likely broken, no need to send denial.
        except Exception as e:
            # Unexpected errors during read/send
            self.logger.error(f"[{thread_name}] Unexpected error sending chunk {chunk_hash[:8]} to {requesting_peer_id[:8]} ({protocol}): {e}", exc_info=True)
            # Connection might still be open, but state is uncertain. Avoid sending denial.

    def recalculate_choking(self):
        """Periodically recalculates which peers to unchoke based on download rates FROM them."""
        now=time.time()
        time_elapsed = now - self.last_choke_recalc_time
        # Avoid recalculating too frequently or if interval is zero
        if time_elapsed < max(1.0, CHOKE_RECALC_INTERVAL): return

        self.logger.debug("--- Recalculating Choking ---")
        new_unchoked_peers = set()
        interested_peer_rates = [] # List of (rate_bps_from_peer, peer_id)

        with self.lock:
            current_interested_set = set(self.interested_peers.keys()) # Peers who want data from us

            # Calculate download rates FROM interested peers
            for peer_id in list(current_interested_set): # Iterate copy
                stats = self.peer_download_stats.get(peer_id, {'bytes_down_interval': 0, 'rate_bps': 0.0})
                bytes_down = stats.get('bytes_down_interval', 0)
                rate_bps = (bytes_down * 8) / time_elapsed # Calculate rate
                self.peer_download_stats[peer_id]['rate_bps'] = rate_bps # Store calculated rate
                self.peer_download_stats[peer_id]['bytes_down_interval'] = 0 # Reset interval counter
                interested_peer_rates.append((rate_bps, peer_id)) # Store rate and peer ID

            # Calculate upload rates TO all peers we tracked (for logging/stats)
            for peer_id, stats in self.peer_upload_stats.items():
                 bytes_up = stats.get('bytes_up_interval', 0)
                 rate_bps = (bytes_up * 8) / time_elapsed
                 stats['rate_bps'] = rate_bps
                 stats['bytes_up_interval'] = 0

            # Sort interested peers by download rate (descending) to prioritize fast peers
            interested_peer_rates.sort(key=lambda x: x[0], reverse=True)

            # Select top N peers for regular unchoking slots
            new_unchoked_peers.update(pid for rate, pid in interested_peer_rates[:MAX_UNCHOKED_UPLOADS])

            # Optimistic Unchoke logic
            if now - self.last_optimistic_unchoke_time >= OPTIMISTIC_UNCHOKE_INTERVAL:
                 # Consider only interested peers *not* already selected for rate-based unchoking
                 potential_optimistic = [pid for _rate, pid in interested_peer_rates if pid not in new_unchoked_peers]
                 if potential_optimistic:
                     self.optimistic_unchoke_peer = random.choice(potential_optimistic)
                     self.logger.debug(f"Optimistic Unchoke: Selected -> {self.optimistic_unchoke_peer[:8]}")
                 else:
                     self.optimistic_unchoke_peer = None # No candidates for optimistic unchoke
                 self.last_optimistic_unchoke_time = now

            # Add current optimistic unchoke peer to the set if valid and interested
            if self.optimistic_unchoke_peer and self.optimistic_unchoke_peer in current_interested_set:
                 new_unchoked_peers.add(self.optimistic_unchoke_peer)
            elif self.optimistic_unchoke_peer and self.optimistic_unchoke_peer not in current_interested_set:
                # Clear optimistic peer if they are no longer interested
                self.logger.debug(f"Optimistic unchoke peer {self.optimistic_unchoke_peer[:8]} lost interest.")
                self.optimistic_unchoke_peer = None

            # --- Update Choking State and Log Changes ---
            old_unchoked = self.unchoked_upload_peers
            became_choked = old_unchoked - new_unchoked_peers
            became_unchoked = new_unchoked_peers - old_unchoked

            # Only log if there's a change
            if became_choked or became_unchoked:
                choke_log = []
                if became_unchoked: choke_log.append(f"Unchoked:{[p[:5] for p in became_unchoked]}")
                if became_choked: choke_log.append(f"Choked:{[p[:5] for p in became_choked]}")
                self.logger.info(f"Choke Update: {', '.join(choke_log)}. Now Unchoked: {[p[:5] for p in new_unchoked_peers]}")

            # Update the definitive set of unchoked peers
            self.unchoked_upload_peers = new_unchoked_peers
            self.last_choke_recalc_time = now

            # --- Cleanup Old Interest Entries ---
            # Remove peers who haven't shown interest recently (e.g., 5 minutes)
            interest_timeout = 300
            expired_interest = [pid for pid, t in self.interested_peers.items() if now - t > interest_timeout]
            for pid in expired_interest:
                self.interested_peers.pop(pid, None)
                # Also clean up their stats if they are gone? Optional.
                # self.peer_download_stats.pop(pid, None)
                # self.peer_upload_stats.pop(pid, None)
            if expired_interest:
                self.logger.debug(f"Removed interest from {len(expired_interest)} inactive peer(s).")

        self.logger.debug("--- Finished Choking Recalculation ---")

    def shutdown(self):
        """Initiates graceful shutdown of the peer and its threads."""
        # Check if running first to avoid repeated shutdown logs
        if not getattr(self, 'running', True): # Check attribute existence before accessing
             # Use print if logger might be gone during complex shutdown scenarios
             print("Shutdown already in progress or completed.")
             return

        current_logger = getattr(self, 'logger', None) # Get logger safely

        if current_logger: current_logger.info("Initiating peer shutdown...")
        else: print("Initiating peer shutdown...")

        self.running = False # Signal all loops to stop

        # ... (rest of shutdown logic remains the same) ...

        if current_logger: current_logger.info("Peer shutdown sequence complete.")
        else: print("Peer shutdown sequence complete.")
        
    def check_stalled_downloads(self):
        """Identifies downloads with no progress and resets 'downloading' chunks to 'needed'."""
        STALLED_TIMEOUT = 4 * 60 # e.g., 4 minutes without progress
        now = time.time()
        downloads_to_reset_chunks = [] # List of (file_hash, chunk_index)

        with self.lock:
            # Iterate over a copy of keys to allow potential removal/modification
            for file_hash in list(self.downloads.keys()):
                 # Check if download still exists before accessing info
                 if file_hash not in self.downloads: continue
                 info = self.downloads[file_hash]

                 chunks = info.get('chunk_objects', [])
                 # Use last progress time (updated on successful chunk download)
                 last_progress = info.get('last_progress_time', info.get('start_time', 0))

                 # Check if download hasn't progressed recently
                 if now - last_progress > STALLED_TIMEOUT:
                      # Find chunks currently marked as 'downloading'
                      stuck_indices = [c.get('index') for c in chunks if c.get('status') == 'downloading']
                      if stuck_indices:
                          # If chunks are stuck in 'downloading', mark them for reset
                          self.logger.warning(f"Download {file_hash[:8]} ('{info.get('filename')}') appears stalled (> {STALLED_TIMEOUT}s). Resetting {len(stuck_indices)} downloading chunk(s).")
                          for idx in stuck_indices:
                              downloads_to_reset_chunks.append((file_hash, idx))
                          # Force a peer refresh for this download soon
                          info['last_peer_refresh'] = 0

            # Perform resets outside the main iteration loop
            if downloads_to_reset_chunks:
                 self.logger.info(f"Resetting {len(downloads_to_reset_chunks)} potentially stalled chunks...")
                 for fhash, cidx in downloads_to_reset_chunks:
                      # Check download still exists before modifying
                      if fhash in self.downloads:
                          try:
                              chunk = self.downloads[fhash]['chunk_objects'][cidx]
                              # Only reset if it's still 'downloading' (manager might have changed it)
                              if chunk.get('status') == 'downloading':
                                   chunk['status'] = 'needed'
                                   chunk['peer_attempts'] = defaultdict(int) # Reset attempts
                                   self.logger.debug(f"Reset chunk {cidx} for DL {fhash[:8]} to 'needed'.")
                          except (IndexError, KeyError, TypeError):
                              # Ignore if chunk/download vanished between check and reset
                              self.logger.warning(f"Chunk {cidx} or DL {fhash[:8]} vanished before stall reset.")
                              continue

    def cleanup_temp_files(self, download_dir: str):
        """Removes .tmp files in the download directory that are not associated with active downloads."""
        active_temp_paths = set()
        removed_count = 0
        # Get list of active temp paths under lock
        with self.lock:
            active_temp_paths = {os.path.abspath(info['temp_path'])
                                 for info in self.downloads.values() if 'temp_path' in info}

        try:
            if os.path.isdir(download_dir):
                 self.logger.debug(f"Running temp file cleanup in '{download_dir}'...")
                 for filename in os.listdir(download_dir):
                     if filename.endswith('.tmp'):
                         tmp_path = os.path.abspath(os.path.join(download_dir, filename))
                         # Check if this temp file belongs to an active download
                         if tmp_path not in active_temp_paths:
                             self.logger.info(f"Found orphaned temp file: '{filename}'. Attempting removal.")
                             try:
                                 os.remove(tmp_path)
                                 removed_count += 1
                             except OSError as e:
                                 self.logger.warning(f"Failed to remove orphaned temp file '{filename}': {e}")
        except OSError as e:
            self.logger.error(f"Error accessing download dir '{download_dir}' for cleanup: {e}")
        if removed_count > 0:
            self.logger.info(f"Temp file cleanup removed {removed_count} file(s).")
        else:
            self.logger.debug("Temp file cleanup found no orphaned files.")

    def shutdown(self):
        """Initiates graceful shutdown of the peer and its threads."""
        if not self.running:
            self.logger.info("Shutdown already in progress or completed.")
            return
        self.logger.info("Initiating peer shutdown...")
        self.running = False # Signal all loops to stop

        # Close server socket immediately to prevent new connections
        server_sock = self.server_socket
        self.server_socket = None # Prevent reuse by acceptor thread
        if server_sock:
            self.logger.debug("Closing server socket...")
            try:
                # Set linger to 0 for immediate close
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            except Exception: pass # Ignore errors setting linger
            try:
                server_sock.shutdown(socket.SHUT_RDWR) # Signal disconnect
            except OSError: pass # Ignore if already closed/not connected
            except Exception as e:
                self.logger.debug(f"Error shutting down server socket: {e}")
            try:
                server_sock.close()
                self.logger.info("Server socket closed.")
            except Exception as e:
                self.logger.debug(f"Error closing server socket: {e}")

        # Unregister from tracker (best effort, short timeout)
        try:
            self.logger.info("Unregistering from tracker...")
            # Use a shorter retry count for shutdown unregister
            self.send_to_tracker_with_retry({'type': 'unregister', 'peer_id': self.peer_id}, retries=1)
            self.logger.info("Unregister request sent to tracker.")
        except Exception as e:
            self.logger.warning(f"Failed to unregister from tracker during shutdown: {e}")

        # Give daemon threads a moment to potentially finish current tasks
        # (Acceptor/Maintenance/Workers will check self.running)
        self.logger.debug("Waiting briefly for threads to stop...")
        time.sleep(0.5) # Adjust as needed

        self.logger.info("Peer shutdown sequence complete.")
        # Note: Daemon threads will exit automatically when the main thread (e.g., Streamlit script) ends.

    # --- UI Helper Methods ---

    def get_sharing_status(self) -> Dict:
        """
        Returns a snapshot of the peer's sharing and choking status,
        formatted for UI display.
        """
        with self.lock:
            # Format shared files (keyed by file hash for UI)
            shared_files_by_hash = {}
            for path, info in self.shared_files.items():
                file_hash = info.get('hash')
                if file_hash:
                    shared_files_by_hash[file_hash] = {
                        'filename': info.get('filename', '?'),
                        'size': info.get('size', 0),
                        'chunks': len(info.get('chunks', [])), # Provide chunk count
                    }

            # Format choking information
            choking_info = {
                'unchoked_peers': list(self.unchoked_upload_peers), # Convert set to list
                'optimistic_unchoke': self.optimistic_unchoke_peer,
                'interested_peers': list(self.interested_peers.keys()), # List of interested peer IDs
                # Provide calculated rates directly
                'dl_stats': {pid: stats.get('rate_bps', 0.0) for pid, stats in self.peer_download_stats.items()},
                'ul_stats': {pid: stats.get('rate_bps', 0.0) for pid, stats in self.peer_upload_stats.items()}
            }

            return {
                "shared_files": shared_files_by_hash,
                "choking_info": choking_info,
            }

    def get_download_status(self) -> Dict[str, Dict]:
        """
        Returns a snapshot of active download statuses, including detailed
        chunk information, formatted for UI display.
        """
        status_snapshot = {}
        with self.lock:
            # Iterate over a copy of items in case finalize removes entry during iteration
            for file_hash, info in list(self.downloads.items()):
                try:
                    # Make a deep copy of chunk objects to avoid modifying state during UI access
                    # Although the lock protects, UI might hold reference longer. Be safe.
                    chunk_objects_copy = [chunk.copy() for chunk in info.get('chunk_objects', [])]

                    total_chunks = len(chunk_objects_copy)
                    status_counts = defaultdict(int)
                    completed_count = 0
                    for chunk in chunk_objects_copy:
                        status = chunk.get('status', 'unknown')
                        status_counts[status] += 1
                        if status == 'complete': completed_count += 1

                    # Calculate progress percentage
                    progress_percent = (completed_count / total_chunks) * 100 if total_chunks > 0 else (100.0 if info.get('total_size', -1) == 0 else 0.0)

                    active_workers = len(info.get('active_workers', set()))

                    # Determine overall download state
                    state = "UNKNOWN"
                    save_path = info.get('save_path')
                    if total_chunks == 0 and info.get('total_size', 0) == 0:
                         state = "COMPLETED" # 0-byte file
                    elif completed_count == total_chunks:
                        # Check if final file exists to differentiate between finalizing and completed
                         state = "COMPLETED" if (save_path and os.path.exists(save_path)) else "FINALIZING"
                    elif status_counts.get('failed', 0) > 0 and status_counts.get('downloading', 0) == 0 and status_counts.get('needed', 0) == 0:
                         state = "FAILED" # No more progress possible
                    elif status_counts.get('downloading', 0) > 0 or active_workers > 0:
                         state = "DOWNLOADING"
                    elif status_counts.get('needed', 0) > 0:
                         # Could be finding peers or stalled if no peers found recently
                         state = "FINDING_PEERS" # Default if needed chunks exist
                    else:
                         state = "PROCESSING" # Initial state or edge case

                    # Package status info for this download
                    status_snapshot[file_hash] = {
                        'filename': info.get('filename', '?'),
                        'total_size': info.get('total_size', 0),
                        'completed_chunks': completed_count,
                        'total_chunks': total_chunks,
                        'progress_percent': progress_percent, # Include calculated percentage
                        'state': state, # Overall state string
                        'current_speed_bps': info.get('current_speed_bps', 0.0), # Periodically calculated speed
                        'active_workers': active_workers,
                        'max_parallel': info.get('max_parallel', DEFAULT_MAX_PARALLEL_DOWNLOADS),
                        'status_counts': dict(status_counts), # Convert defaultdict for safety
                        'chunk_objects': chunk_objects_copy # Include copy of detailed chunk list
                    }
                except Exception as e:
                    # Log error but continue processing other downloads
                    self.logger.error(f"Error generating status for download {file_hash[:8]}: {e}", exc_info=False)

        return status_snapshot

# --- END OF peer.py (v2.3 - Streamlit Focused) ---