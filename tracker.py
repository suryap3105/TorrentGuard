# tracker.py (v7 Batch Logging with Source Peer Tracking)

import socket
import threading
import json
from collections import defaultdict
import logging
import sys
import time
import os

# --- Configuration for get_peers Batch Logging ---
# Log a summary every X seconds if get_peers requests occurred for a peer
GET_PEERS_BATCH_INTERVAL = 20.0 # Log summary approx every 20 seconds per peer
# --- End Configuration ---

class Tracker:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        # Data Structures:
        self.peers = {} # {peer_id: {'ip': str, 'port': int, 'tls_capable': bool, 'last_seen': float}}
        self.files = {} # {file_hash: {'filename': str, 'size': int, 'chunks': list[str]}}
        self.chunk_peers = defaultdict(set) # {chunk_hash: set(peer_id)}
        self.peer_chunks = defaultdict(set) # {peer_id: set(chunk_hash)}

        self.lock = threading.Lock() # Main lock for peers, files, chunks data
        self.running = True
        self.logger = self.setup_logging()

        # --- State for get_peers Batch Logging ---
        self.get_peers_batch_lock = threading.Lock() # Separate lock for batching state
        # Stores { peer_id: {'count': int, 'last_log_time': float, 'served_peers': set()} }
        # 'served_peers' will store unique peer IDs returned as sources during the interval
        self.get_peers_activity = defaultdict(
            lambda: {'count': 0, 'last_log_time': 0.0, 'served_peers': set()}
        )
        # --- End Batch Logging State ---


    def setup_logging(self):
        """Configure logging for the tracker."""
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "tracker.log")

        logger = logging.getLogger("Tracker")
        logger.setLevel(logging.INFO)

        if logger.hasHandlers():
            logger.handlers.clear()

        formatter = logging.Formatter('%(asctime)s [%(levelname)-7s] (%(threadName)-10s) %(message)s')

        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        return logger

    def start(self):
        """Binds the socket and starts listening for connections."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.host, self.port))
                s.listen()
                self.logger.info(f"Tracker started and listening on {self.host}:{self.port}")
                s.settimeout(1.0)

                while self.running:
                    try:
                        conn, addr = s.accept()
                        thread_name = f"Client-{addr[0]}-{addr[1]}"
                        threading.Thread(target=self.handle_client, args=(conn, addr), name=thread_name, daemon=True).start()
                    except socket.timeout:
                        continue
                    except OSError as e:
                        if self.running: self.logger.error(f"Socket accept error: {e}")
                        break
                    except Exception as e:
                        if self.running: self.logger.error(f"Unexpected error accepting connection: {e}", exc_info=True)
        except OSError as e:
            self.logger.critical(f"CRITICAL: Failed to bind tracker to {self.host}:{self.port} - {e}. Is the port in use?")
            self.running = False
        except Exception as e:
            self.logger.critical(f"CRITICAL: Tracker failed to start: {e}", exc_info=True)
            self.running = False

    def stop(self):
        """Signals the tracker to stop."""
        if self.running:
            self.logger.info("Stopping tracker...")
            self.running = False
            self._log_final_get_peers_batches()


    def _log_final_get_peers_batches(self):
        """Logs any pending get_peers counts and served peers before shutdown."""
        self.logger.info("Logging final get_peers batch summaries...")
        with self.get_peers_batch_lock:
            now = time.time()
            for peer_id, activity in list(self.get_peers_activity.items()):
                if activity['count'] > 0:
                     log_prefix = f"Peer {peer_id[:8]}"
                     served_count = len(activity.get('served_peers', set()))
                     self.logger.info(f"{log_prefix} handled {activity['count']} 'get_peers' request(s), finding {served_count} unique source(s) since last summary (final log).")
                     # Optionally clear: del self.get_peers_activity[peer_id]


    def run_maintenance(self, inactive_threshold_seconds=300):
        """Periodically removes inactive peers and cleans up old activity logs."""
        self.logger.info(f"Maintenance thread started. Peer timeout: {inactive_threshold_seconds}s.")
        last_activity_cleanup_time = time.time()

        while self.running:
            check_interval = max(15, inactive_threshold_seconds / 4)
            time.sleep(check_interval)
            if not self.running: break

            now = time.time()
            peers_removed_count = 0
            files_removed_count = 0

            # --- Peer Timeout Cleanup (Requires main lock) ---
            with self.lock:
                inactive_peer_ids = [
                    pid for pid, data in self.peers.items()
                    if now - data.get('last_seen', 0) > inactive_threshold_seconds
                ]

                if inactive_peer_ids:
                    self.logger.info(f"Maintenance: Found {len(inactive_peer_ids)} inactive peer(s). Starting cleanup...")
                    # We acquire the batch lock inside _remove_peer_and_cleanup
                    for peer_id in inactive_peer_ids:
                        # _remove_peer_and_cleanup needs the main lock, which we already hold here
                        removed_peer, removed_files = self._remove_peer_and_cleanup(peer_id)
                        if removed_peer: peers_removed_count += 1
                        files_removed_count += len(removed_files)
                    if peers_removed_count > 0 or files_removed_count > 0:
                        self.logger.info(f"Maintenance: Finished peer cleanup. Removed {peers_removed_count} peers, {files_removed_count} orphaned files.")

            # --- Cleanup Old get_peers_activity Entries (Requires batch lock) ---
            if now - last_activity_cleanup_time > inactive_threshold_seconds * 2:
                self.logger.debug("Maintenance: Cleaning up stale get_peers activity entries...")
                stale_cutoff = now - (inactive_threshold_seconds * 2)
                cleaned_count = 0
                with self.get_peers_batch_lock:
                    stale_peers = [
                        pid for pid, activity in self.get_peers_activity.items()
                        # Check last log time and count being zero (served_peers doesn't matter if count is zero)
                        if activity.get('last_log_time', 0) < stale_cutoff and activity.get('count', 0) == 0
                    ]
                    for pid in stale_peers:
                        del self.get_peers_activity[pid]
                        cleaned_count += 1
                if cleaned_count > 0:
                    self.logger.info(f"Maintenance: Cleaned up {cleaned_count} stale get_peers activity entries.")
                last_activity_cleanup_time = now

        self.logger.info("Maintenance thread stopped.")


    def _remove_peer_and_cleanup(self, peer_id: str) -> tuple[bool, list[str]]:
        """
        Removes a peer, its chunk associations, and its get_peers activity log.
        Checks for orphaned files.
        MUST be called within the main self.lock context.
        Returns: (peer_was_removed: bool, list_of_removed_file_hashes: list[str])
        """
        # --- Clean up get_peers activity (Requires separate lock) ---
        with self.get_peers_batch_lock:
            activity = self.get_peers_activity.pop(peer_id, None)
            if activity and activity.get('count', 0) > 0:
                 log_prefix = f"Peer {peer_id[:8]}"
                 served_count = len(activity.get('served_peers', set()))
                 self.logger.info(f"{log_prefix} handled {activity['count']} 'get_peers' request(s), finding {served_count} unique source(s) before removal (final log).")
        # --- End activity cleanup ---

        # --- Original Peer/File cleanup logic (Assumes self.lock is held) ---
        if peer_id not in self.peers:
            return False, []

        peer_info = self.peers.pop(peer_id)
        self.logger.info(f"Removing peer {peer_id[:8]} ({peer_info.get('ip', '?')}:{peer_info.get('port', '?')}).")

        chunks_peer_had = self.peer_chunks.pop(peer_id, set())
        if not chunks_peer_had:
             return True, []

        # Check for orphaned files/chunks
        removed_file_hashes = []
        for chunk_hash in chunks_peer_had:
            if chunk_hash in self.chunk_peers:
                self.chunk_peers[chunk_hash].discard(peer_id)
                if not self.chunk_peers[chunk_hash]:
                    self.logger.debug(f"Chunk {chunk_hash[:6]} is now unavailable.")
                    del self.chunk_peers[chunk_hash]
                    # Now check files associated with this orphaned chunk
                    for f_hash, f_info in list(self.files.items()):
                         if chunk_hash in f_info.get('chunks', []):
                             # Re-check if this file has *any* remaining sources
                             has_source = any(ch in self.chunk_peers for ch in f_info.get('chunks', []))
                             if not has_source and f_hash not in removed_file_hashes:
                                 removed_info = self.files.pop(f_hash, None)
                                 if removed_info:
                                     fname = removed_info.get('filename', 'Unknown')
                                     self.logger.info(f"Removing orphaned file metadata: '{fname}' ({f_hash[:8]})")
                                     removed_file_hashes.append(f_hash)


        # Final check for any other files that might be orphaned indirectly
        for f_hash, f_info in list(self.files.items()):
             if f_hash not in removed_file_hashes: # Avoid re-checking already removed files
                has_source = any(ch in self.chunk_peers for ch in f_info.get('chunks', []))
                if not has_source:
                     removed_info = self.files.pop(f_hash, None)
                     if removed_info:
                         fname = removed_info.get('filename', 'Unknown')
                         self.logger.info(f"Removing orphaned file metadata (secondary check): '{fname}' ({f_hash[:8]})")
                         removed_file_hashes.append(f_hash)

        return True, removed_file_hashes
        # --- End original Peer/File cleanup ---

    def handle_client(self, conn: socket.socket, addr: tuple):
        """Handles receiving, processing, and responding to a single client message."""
        peer_ip, peer_port = addr
        log_prefix = f"Client {peer_ip}:{peer_port} -"
        message_type = "N/A"
        message = None
        peer_id = 'Unknown'
        try:
            with conn:
                # 1. Read Message Length
                raw_length = conn.recv(4)
                if not raw_length or len(raw_length) < 4: return
                msg_length = int.from_bytes(raw_length, 'big')
                MAX_MSG_LEN = 5 * 1024 * 1024
                if not 0 < msg_length <= MAX_MSG_LEN:
                     self.logger.warning(f"{log_prefix} Invalid message length: {msg_length}. Closing.")
                     self._send_response(conn, {'status': 'error', 'message': 'Invalid message length'}, log_prefix)
                     return

                # 2. Read Message Data
                data = b''
                while len(data) < msg_length:
                    chunk = conn.recv(min(msg_length - len(data), 4096))
                    if not chunk:
                        self.logger.warning(f"{log_prefix} Connection closed prematurely receiving msg body (got {len(data)}/{msg_length}).")
                        return
                    data += chunk
                data_str = data.decode('utf-8')

                # 3. Process Message
                message = json.loads(data_str)
                message_type = message.get('type', 'N/A')
                peer_id = message.get('peer_id', 'Unknown')
                if peer_id != 'Unknown':
                    log_prefix = f"Peer {peer_id[:8]} ({peer_ip}:{peer_port}) -"

                # Log receipt (excluding get_peers, handled by batching)
                if message_type != 'get_peers':
                     self.logger.info(f"{log_prefix} Received '{message_type}'")

                response = self.process_message(message, addr)

                # 4. Send Response
                self._send_response(conn, response, log_prefix)

        except json.JSONDecodeError:
            self.logger.warning(f"{log_prefix} Invalid JSON received.")
            try: self._send_response(conn, {'status': 'error', 'message': 'Invalid JSON format'}, log_prefix)
            except Exception: pass
        except socket.timeout:
            self.logger.warning(f"{log_prefix} Socket timeout.")
        except UnicodeDecodeError:
             self.logger.warning(f"{log_prefix} Received non-UTF8 data.")
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as e:
             self.logger.info(f"{log_prefix} Connection closed by peer ({type(e).__name__}).")
        except Exception as e:
            self.logger.error(f"{log_prefix} Error handling client (MsgType: {message_type}): {e}", exc_info=True)
            try:
                self._send_response(conn, {'status': 'error', 'message': 'Internal tracker error'}, log_prefix)
            except Exception: pass

    def handle_list_peers(self, message: dict, addr: tuple) -> dict:
        """Handles a request for the list of all currently registered peers."""
        requesting_peer_id = message.get('peer_id') # ID of the peer asking
        peer_ip, peer_port = addr
        log_source = f"Peer {requesting_peer_id[:8]}" if requesting_peer_id else f"Addr {peer_ip}"
    
        # Optional: Log if peer_id is missing, but still proceed
        if not requesting_peer_id:
            self.logger.warning(f"list_peers request from {peer_ip}:{peer_port} missing 'peer_id'.")
    
        all_peers_list = []
        with self.lock: # Access self.peers safely
            for pid, data in self.peers.items():
                # Exclude the requesting peer from the list sent back to them
                if pid != requesting_peer_id:
                    # Construct the dictionary for the peer, using .get for safety
                    peer_info = {
                        'peer_id': pid,
                        'ip': data.get('ip'),
                        'port': data.get('port'),
                        'tls_capable': data.get('tls_capable', False) # Default to False if missing
                    }
                    all_peers_list.append(peer_info)
    
        self.logger.info(f"{log_source} requested full peer list. Returning {len(all_peers_list)} other peers.")
        return {'status': 'success', 'peers': all_peers_list}

    def _send_response(self, conn: socket.socket, response: dict, log_prefix: str):
        """Helper method to encode and send a JSON response with length prefix."""
        try:
            response_data = json.dumps(response).encode('utf-8')
            response_len_bytes = len(response_data).to_bytes(4, 'big')
            conn.sendall(response_len_bytes + response_data)
        except (socket.error, BrokenPipeError) as e:
            self.logger.warning(f"{log_prefix} Failed to send response: {e}")


    def process_message(self, message: dict, addr: tuple) -> dict:
        """Routes message to appropriate handler based on 'type'."""
        message_type = message.get('type')
        peer_ip, peer_port = addr
        peer_id = message.get('peer_id', 'Unknown')
        log_prefix = f"Peer {peer_id[:8]}" if peer_id != 'Unknown' else f"Client {peer_ip}:{peer_port}"

        # Map message types to their handler methods
        handler_map = {
            'register': self.handle_register,
            'publish': self.handle_publish,
            'list_files': self.handle_list_files,
            'get_file_info': self.handle_get_file_info,
            'get_peers': self.handle_get_peers,       # Handles requests for peers having specific chunks
            'list_peers': self.handle_list_peers,     # Handles requests for the full peer list (NEW)
            'update_chunks': self.handle_update_chunks,
            'unregister': self.handle_unregister
        }
        handler = handler_map.get(message_type)

        if handler:
            try:
                # Update Peer's last_seen timestamp for most message types
                # (excluding unregister where the peer is being removed)
                if peer_id != 'Unknown' and message_type not in ['unregister']:
                    with self.lock: # Lock needed to safely access/update self.peers
                        if peer_id in self.peers:
                            self.peers[peer_id]['last_seen'] = time.time()
                        # Optional: Log if peer is known but last_seen couldn't be updated?
                        # else:
                        #    self.logger.debug(f"Received message type '{message_type}' from {log_prefix}, but peer not currently in self.peers to update last_seen.")

                # Call the appropriate handler function
                return handler(message, addr)

            except Exception as e:
                # Log errors occurring within the specific handler
                self.logger.error(f"{log_prefix} Error in handler for '{message_type}': {e}", exc_info=True)
                return {'status': 'error', 'message': f'Error processing {message_type} request.'}
        else:
            # Handle cases where the message type is unknown
            self.logger.warning(f"{log_prefix} No handler found for message type '{message_type}'")
            return {'status': 'error', 'message': f'Unknown message type: {message_type}'}

    # --- Handlers ---

    # Keep handle_register, handle_publish, handle_list_files, handle_get_file_info, handle_list_peers, handle_update_chunks
    # identical to v6/v5 as their logging is already appropriate.

    def handle_register(self, message: dict, addr: tuple) -> dict:
        peer_id = message.get('peer_id')
        ip = message.get('ip')
        port = message.get('port')
        tls = message.get('tls_capable', False)
        initial_chunks = message.get('initial_chunk_hashes', [])
        if not all([peer_id, ip, isinstance(port, int)]):
             self.logger.warning(f"Invalid registration from {addr[0]}:{addr[1]}: Missing fields.")
             return {'status': 'error', 'message': 'Missing peer_id, ip, or port'}
        with self.lock:
            log_verb = "re-registered" if peer_id in self.peers else "registered"
            self.peers[peer_id] = {'ip': ip, 'port': port, 'tls_capable': tls, 'last_seen': time.time()}
            initial_chunks_set = set(initial_chunks) if isinstance(initial_chunks, list) else set()
            self.peer_chunks[peer_id] = initial_chunks_set
            for chunk_hash in initial_chunks_set:
                self.chunk_peers[chunk_hash].add(peer_id)
            self.logger.info(f"Peer {peer_id[:8]} ({ip}:{port}) {log_verb}. Chunks: {len(initial_chunks_set)}. TLS: {tls}")
        return {'status': 'success', 'message': f'Registered {peer_id[:8]} successfully'}

    def handle_publish(self, message: dict, addr: tuple) -> dict:
        peer_id = message.get('peer_id')
        file_hash = message.get('file_hash')
        filename = message.get('filename')
        chunk_hashes = message.get('chunk_hashes')
        size = message.get('size')
        if not all([peer_id, file_hash, filename, isinstance(chunk_hashes, list), isinstance(size, int)]):
            self.logger.warning(f"Invalid 'publish' from {peer_id or addr[0]}: Missing/invalid fields.")
            return {'status': 'error', 'message': 'Invalid publish message format.'}
        with self.lock:
            if peer_id not in self.peers:
                 self.logger.warning(f"Publish from unregistered peer {peer_id[:8]} ({addr[0]}).")
                 return {'status': 'error', 'message': 'Peer not registered.'}
            log_msg_verb = "re-published" if file_hash in self.files else "published"
            self.files[file_hash] = {'filename': filename, 'size': size, 'chunks': chunk_hashes}
            new_chunks_set = set(chunk_hashes)
            for chunk_hash in new_chunks_set:
                self.chunk_peers[chunk_hash].add(peer_id)
            self.peer_chunks[peer_id].update(new_chunks_set)
            self.logger.info(f"Peer {peer_id[:8]} {log_msg_verb} file '{filename}' ({file_hash[:8]}, {len(chunk_hashes)} chunks, {size} bytes).")
        return {'status': 'success', 'message': 'File published successfully.'}

    def handle_list_files(self, message: dict, addr: tuple) -> dict:
        requesting_peer_id = message.get('peer_id', 'Unknown')
        files_summary = {}
        with self.lock:
            for file_hash, info in self.files.items():
                 files_summary[file_hash] = {'filename': info.get('filename', 'unknown'), 'size': info.get('size', 0), 'chunks': len(info.get('chunks', []))}
        self.logger.info(f"Peer {requesting_peer_id[:8]} ({addr[0]}) requested file list ({len(files_summary)} files).")
        return {'status': 'success', 'files': files_summary}

    def handle_get_file_info(self, message: dict, addr: tuple) -> dict:
        file_hash = message.get('file_hash')
        requesting_peer_id = message.get('peer_id', 'Unknown')
        if not file_hash or len(file_hash) != 40:
            self.logger.warning(f"get_file_info from {requesting_peer_id[:8]} ({addr[0]}) invalid 'file_hash'.")
            return {'status': 'error', 'message': 'Missing or invalid file_hash'}
        with self.lock:
            file_info = self.files.get(file_hash)
        if file_info:
            self.logger.info(f"Peer {requesting_peer_id[:8]} successfully got info for file {file_hash[:8]}.")
            return {'status': 'success', 'filename': file_info.get('filename', 'unknown'), 'size': file_info.get('size', 0), 'chunks': file_info.get('chunks', [])}
        else:
            self.logger.info(f"Peer {requesting_peer_id[:8]} requested info for unknown file {file_hash[:8]}.")
            return {'status': 'error', 'message': 'File hash not found'}

    def handle_list_peers(self, message: dict, addr: tuple) -> dict:
        requesting_peer_id = message.get('peer_id')
        peer_ip, peer_port = addr
        log_source = f"Peer {requesting_peer_id[:8]}" if requesting_peer_id else f"Addr {peer_ip}"
        if not requesting_peer_id:
            self.logger.warning(f"list_peers request from {peer_ip}:{peer_port} missing 'peer_id'.")
        all_peers_list = []
        with self.lock:
            for pid, data in self.peers.items():
                if pid != requesting_peer_id: # Keep excluding self here
                    all_peers_list.append({'peer_id': pid, 'ip': data.get('ip'), 'port': data.get('port'), 'tls_capable': data.get('tls_capable', False)})
        self.logger.info(f"{log_source} requested peer list. Returning {len(all_peers_list)} peers.")
        return {'status': 'success', 'peers': all_peers_list}

    def handle_update_chunks(self, message: dict, addr: tuple) -> dict:
        peer_id = message.get('peer_id')
        available_chunk_hashes = message.get('available_chunk_hashes')
        if not peer_id or not isinstance(available_chunk_hashes, list):
             self.logger.warning(f"Invalid 'update_chunks' from {peer_id or addr[0]}.")
             return {'status': 'error', 'message': 'Invalid update_chunks message'}
        with self.lock:
            if peer_id not in self.peers:
                self.logger.warning(f"Chunk update from unknown peer {peer_id[:8]} ({addr[0]}). Ignoring.")
                return {'status': 'error', 'message': 'Peer not registered'}
            new_chunks_set = set(available_chunk_hashes)
            old_chunks_set = self.peer_chunks.get(peer_id, set())
            added_chunks = new_chunks_set - old_chunks_set
            removed_chunks = old_chunks_set - new_chunks_set
            if not added_chunks and not removed_chunks:
                 return {'status': 'success', 'message': 'Chunk list updated (no change)'}
            for chash in added_chunks: self.chunk_peers[chash].add(peer_id)
            for chash in removed_chunks: self.chunk_peers[chash].discard(peer_id) # Orphan check handled by _remove_peer
            self.peer_chunks[peer_id] = new_chunks_set
            self.logger.info(f"Peer {peer_id[:8]} updated chunks: Now has {len(new_chunks_set)}. (+{len(added_chunks)} / -{len(removed_chunks)})")
        return {'status': 'success', 'message': 'Chunk list updated'}

    # --- MODIFIED get_peers with Enhanced Batch Logging ---
    def handle_get_peers(self, message: dict, addr: tuple) -> dict:
        """
        Provides peers for a chunk. Logging is batched and includes counts of
        requests and unique source peers found during the interval.
        Includes requesting peer if they have the chunk.
        """
        chunk_hash = message.get('chunk_hash')
        requesting_peer_id = message.get('peer_id')
        peer_ip, peer_port = addr
        log_prefix = f"Peer {requesting_peer_id[:8]}" if requesting_peer_id else f"Addr {peer_ip}"

        if not chunk_hash or len(chunk_hash) != 40:
            self.logger.warning(f"{log_prefix} ({peer_ip}:{peer_port}) invalid 'chunk_hash' for get_peers.")
            return {'status': 'error', 'message': 'Missing or invalid chunk_hash'}

        if not requesting_peer_id:
             self.logger.warning(f"get_peers from {peer_ip}:{peer_port} missing 'peer_id'.")

        peers_list = []
        # --- Core Logic: Find peers (under main lock) ---
        with self.lock:
            peer_ids_with_chunk = self.chunk_peers.get(chunk_hash, set())
            for pid in peer_ids_with_chunk:
                if pid in self.peers: # Check if peer is still registered
                      peer_info = self.peers[pid]
                      peers_list.append({
                          'peer_id': pid,
                          'ip': peer_info.get('ip'),
                          'port': peer_info.get('port'),
                          'tls_capable': peer_info.get('tls_capable', False)
                      })
        # --- End Core Logic ---

        # --- Batch Logging Logic (under separate lock) ---
        if requesting_peer_id and requesting_peer_id != 'Unknown':
            with self.get_peers_batch_lock:
                activity = self.get_peers_activity[requesting_peer_id]
                activity['count'] += 1
                # Add the IDs of peers found in *this* response to the batch's set
                activity['served_peers'].update(p['peer_id'] for p in peers_list)

                now = time.time()
                if now - activity['last_log_time'] >= GET_PEERS_BATCH_INTERVAL:
                    if activity['count'] > 0:
                        batch_log_prefix = f"Peer {requesting_peer_id[:8]}"
                        served_count = len(activity.get('served_peers', set()))
                        # Log summary with request count AND unique source peer count
                        self.logger.info(f"{batch_log_prefix} handled {activity['count']} 'get_peers' request(s), finding {served_count} unique source(s) in the last ~{GET_PEERS_BATCH_INTERVAL:.0f}s.")
                        # Reset count AND served peers set for the next batch
                        activity['count'] = 0
                        activity['served_peers'].clear()
                    activity['last_log_time'] = now
        # --- End Batch Logging ---

        return {'status': 'success', 'peers': peers_list}


    def handle_unregister(self, message: dict, addr: tuple) -> dict:
        """Handles peer unregistration and triggers cleanup."""
        peer_id = message.get('peer_id')
        if not peer_id:
            self.logger.warning(f"Unregister request from {addr[0]} missing 'peer_id'.")
            return {'status': 'error', 'message': 'Missing peer_id for unregister'}

        # Need the main lock to modify peer/file data structures
        with self.lock:
             # _remove_peer_and_cleanup handles batch activity cleanup too
             removed_peer, removed_files = self._remove_peer_and_cleanup(peer_id)

        if removed_peer:
             # Peer removal log now happens inside _remove_peer_and_cleanup
             return {'status': 'success', 'message': 'Unregistered successfully'}
        else:
             self.logger.warning(f"Unregister request for unknown peer {peer_id[:8]}.")
             return {'status': 'error', 'message': 'Peer not found for unregister'}

# --- Main Execution ---
if __name__ == '__main__':
    tracker_host = os.getenv("TRACKER_HOST", "0.0.0.0")
    try:
        tracker_port = int(os.getenv("TRACKER_PORT", 5000))
    except ValueError:
        print("Warning: Invalid TRACKER_PORT env variable. Using default 5000.")
        tracker_port = 5000

    tracker = Tracker(host=tracker_host, port=tracker_port)

    maintenance_thread = threading.Thread(
        target=tracker.run_maintenance,
        args=(3*60,), # Check inactive peers every 10 minutes
        name="MaintenanceThread",
        daemon=True
    )
    maintenance_thread.start()

    try:
        tracker.start()
    except KeyboardInterrupt:
        print("\nCtrl+C received, stopping tracker...")
    except Exception as e:
        tracker.logger.critical(f"Tracker failed critically in main execution: {e}", exc_info=True)
    finally:
        tracker.stop() # Signals stop, attempts final batch log
        time.sleep(0.5) # Brief pause for threads
        tracker.logger.info("Tracker stopped.")
        print("Tracker shutdown complete.")