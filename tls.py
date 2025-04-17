# --- START OF MODIFIED vpn.py (Option 1: Harden TLS Settings) ---

import ssl
import socket
import os
import time
import logging
from typing import Optional
import ipaddress

# Try to import cryptography for cert generation
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Configuration
CERT_FILE = "peer_cert.pem"
KEY_FILE = "peer_key.pem"
# Use module-level logger
log = logging.getLogger(__name__)

# --- ADDED: Recommended strong cipher list ---
# Prioritizes TLS 1.3 ciphers if available, then strong TLS 1.2
MODERN_CIPHERS = (
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:" # TLS 1.3
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
)
# --- END ADDED ---

def ensure_self_signed_cert(peer_id: str, certs_dir: str) -> bool:
    """
    Ensures self-signed certificate and key files exist in the specified directory.
    Generates them if not. Uses peer_id in the filename.
    Returns True if files exist or were created successfully, False otherwise.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        log.warning("Cannot generate TLS cert: 'cryptography' library not available.")
        return False

    # Construct paths using the passed certs_dir and peer_id
    cert_path = os.path.join(certs_dir, f"{peer_id}_cert.pem")
    key_path = os.path.join(certs_dir, f"{peer_id}_key.pem")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        log.debug(f"Existing TLS certificate ({os.path.basename(cert_path)}) and key ({os.path.basename(key_path)}) found in {certs_dir}.")
        # Optional: Add validation (e.g., check expiry) here if needed
        return True

    log.info(f"Generating new self-signed TLS certificate ({os.path.basename(cert_path)}) and key ({os.path.basename(key_path)}) in {certs_dir}...")
    try:
        # Ensure certs directory exists before writing
        os.makedirs(certs_dir, exist_ok=True)

        # Generate private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # --- Determine Subject Alternative Name (SAN) entries ---
        san_entries = []
        ip_address_str_for_log = "skipped" # For logging purposes
        try:
            hostname = socket.getfqdn() # Get Fully Qualified Domain Name
            ip_address_str = socket.gethostbyname(hostname) # Resolve hostname to IP string
            san_entries.append(x509.DNSName(hostname)) # Add DNS name to SAN

            # --- FIX: Convert IP string to ipaddress object ---
            try:
                # Parse the IP string into an ipaddress object (IPv4Address or IPv6Address)
                ip_object = ipaddress.ip_address(ip_address_str)
                # Add the ipaddress object to SAN using x509.IPAddress
                san_entries.append(x509.IPAddress(ip_object))
                ip_address_str_for_log = ip_address_str # Store for logging if successful
            except ValueError as ip_err:
                # Handle cases where the resolved string isn't a valid IP (e.g., some DNS issues)
                log.warning(f"Could not parse resolved IP '{ip_address_str}' for SAN ({ip_err}). Skipping IP SAN.")
            # --- END FIX ---

            common_name = hostname # Use FQDN as Common Name if resolved
            log.debug(f"Using SAN: DNS={hostname}, IP={ip_address_str_for_log}")

        except (socket.gaierror, socket.herror, OSError) as e:
            # Fallback if hostname/IP resolution fails
            log.warning(f"Could not resolve hostname/IP for SAN ({e}). Using fallback CN.")
            # Create a plausible fallback Common Name and SAN DNS entry
            common_name = f"peer-{peer_id[:8]}.p2p.local"
            san_entries.append(x509.DNSName(common_name))


        # Define certificate subject and issuer (same for self-signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"XX"), # Placeholder country
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"DefaultState"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"DefaultCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"P2PNetworkNode"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name), # Use the determined Common Name
        ])

        # Build the certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number() # Generate a random serial number
        ).not_valid_before(
            datetime.utcnow() # Certificate is valid starting now
        ).not_valid_after(
            # Set validity period (e.g., 2 years)
            datetime.utcnow() + timedelta(days=730)
        ).add_extension(
            # Basic Constraints: Indicates this is not a CA certificate
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).add_extension(
            # Add the Subject Alternative Name extension
            x509.SubjectAlternativeName(san_entries),
            critical=False, # SAN is usually not critical
        ).sign(key, hashes.SHA256()) # Sign the certificate with the private key

        # --- Write files to disk ---
        # Write private key
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL, # Common legacy format
                encryption_algorithm=serialization.NoEncryption() # No password on key file
            ))
        # Set restrictive permissions on the key file (Linux/macOS primarily)
        try:
            os.chmod(key_path, 0o600) # Read/Write only for owner
        except OSError as perm_err:
            # Permissions might fail on some systems (e.g., Windows non-admin)
            log.warning(f"Could not set permissions on key file {key_path}: {perm_err}")


        # Write public certificate
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        log.info(f"Successfully generated self-signed certificate ({os.path.basename(cert_path)}) and key ({os.path.basename(key_path)}) in {certs_dir}.")
        return True # Indicate success

    except Exception as e:
        # Catch any other errors during generation
        log.error(f"Failed to generate self-signed certificate: {e}", exc_info=True)
        # Attempt to clean up potentially partial files on error
        try:
            if os.path.exists(key_path): os.remove(key_path)
            if os.path.exists(cert_path): os.remove(cert_path)
        except OSError as cleanup_err:
             log.error(f"Error cleaning up partial cert/key files: {cleanup_err}")
        return False # Indicate failure


def create_server_context(certs_dir: str, peer_id: str) -> Optional[ssl.SSLContext]:
    """
    Creates an SSL context for the server side, loading the specific peer's
    cert and key from certs_dir.
    MODIFIED: Sets minimum TLS version and restricts ciphers.
    """
    # --- Construct paths using certs_dir and peer_id ---
    cert_path = os.path.join(certs_dir, f"{peer_id}_cert.pem")
    key_path = os.path.join(certs_dir, f"{peer_id}_key.pem")

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
         log.error(f"Server SSL context creation failed: Cert ({os.path.basename(cert_path)}) or Key ({os.path.basename(key_path)}) not found in {certs_dir}.")
         return None
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path) # Use constructed paths

        # --- MODIFICATIONS FOR OPTION 1 ---
        try:
            # Require TLS 1.2 or higher (Python 3.7+ needed for TLSVersion enum)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            log.warning("Could not set minimum_version (requires Python 3.7+). Relying on default.")
            # For older Python, might need options like:
            # context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        try:
            # Use strong cipher list
            context.set_ciphers(MODERN_CIPHERS)
        except ssl.SSLError as cipher_err:
            log.error(f"Failed to set modern ciphers: {cipher_err}. Using system defaults.")
        # --- END MODIFICATIONS ---

        log.info("Server SSL context created successfully (TLSv1.2+, Modern Ciphers).")
        return context
    except ssl.SSLError as e:
        log.error(f"Error loading SSL cert/key for server context from {certs_dir}: {e}")
        return None
    except Exception as e:
        log.error(f"Unexpected error creating server SSL context: {e}", exc_info=True)
        return None

def create_client_context(certs_dir: Optional[str] = None) -> Optional[ssl.SSLContext]:
    """
    Creates an SSL context for the client side.
    WARNING: Disables certificate verification for self-signed cert compatibility.
    MODIFIED: Sets minimum TLS version and restricts ciphers.
              Optionally loads CA certs from certs_dir if provided (but verification is off).
    """
    try:
        # Purpose.SERVER_AUTH means we expect to verify a server cert (though we disable it)
        # Use create_default_context OR supply cafile/capath if verifying
        # Using PROTOCOL_TLS_CLIENT allows more control, especially when not verifying default CAs
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # !!! --- SECURITY WARNING REMAINS --- !!!
        context.check_hostname = False      # Don't verify hostname matches cert CN/SAN
        context.verify_mode = ssl.CERT_NONE # Trust *any* certificate presented by server
        # !!! --- End Security Warning ---

        # --- MODIFICATIONS FOR OPTION 1 ---
        try:
            # Require TLS 1.2 or higher
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            log.warning("Could not set minimum_version (requires Python 3.7+). Relying on default.")
            # context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        try:
            # Use strong cipher list
            context.set_ciphers(MODERN_CIPHERS)
        except ssl.SSLError as cipher_err:
             log.error(f"Failed to set modern ciphers for client: {cipher_err}. Using system defaults.")
        # --- END MODIFICATIONS ---

        # Optionally load custom CA certs if verification were enabled
        # if certs_dir and os.path.isdir(certs_dir) and context.verify_mode != ssl.CERT_NONE:
        #     try:
        #         context.load_verify_locations(capath=certs_dir)
        #         log.info(f"Loaded custom CA certs from {certs_dir} for client context.")
        #     except Exception as ca_err:
        #         log.error(f"Failed to load CA certs from {certs_dir}: {ca_err}")

        log.warning("Client SSL context created (TLSv1.2+, Modern Ciphers) - CERT VERIFICATION DISABLED.")
        return context
    except Exception as e:
        log.error(f"Unexpected error creating client SSL context: {e}", exc_info=True)
        return None

def receive_all_secure(ssock: ssl.SSLSocket, length: int, timeout: float) -> bytes:
    """
    Helper to receive exactly 'length' bytes from an SSL socket.
    Simplified blocking implementation with timeout.
    (No changes needed in this function for Option 1)
    """
    if length < 0: raise ValueError("Length cannot be negative")
    if length == 0: return b''

    data = bytearray()
    bytes_left = length
    start_time = time.monotonic()

    original_timeout = ssock.gettimeout()
    try:
        # Short timeout for individual calls to avoid indefinite block on SSLWantRead/Write
        # But still honor the overall timeout
        individual_timeout = max(0.05, min(timeout / 10, 0.5))

        while bytes_left > 0:
            # Check overall timeout first
            if time.monotonic() - start_time > timeout:
                 log.warning(f"SSL receive overall timeout ({timeout}s). Got {len(data)}/{length} bytes.")
                 raise socket.timeout(f"SSL receive overall timeout. Expected {length}, got {len(data)}")

            try:
                ssock.settimeout(individual_timeout) # Set short timeout for this attempt
                chunk_size = min(bytes_left, 16384) # Read in reasonable chunks
                chunk = ssock.recv(chunk_size)
                if not chunk:
                    log.warning(f"SSL socket closed during receive. Expected {length}, got {len(data)}.")
                    raise ConnectionAbortedError(f"SSL socket closed. Expected {length}, got {len(data)}.")

                data.extend(chunk)
                bytes_left -= len(chunk)

            except ssl.SSLWantReadError:
                # Need to wait for socket to become readable (underlying SSL ops)
                # Proper way is select(), but time.sleep is simpler for blocking code
                time.sleep(0.01) # Small sleep and retry
                continue
            except ssl.SSLWantWriteError:
                 # Need to wait for socket to become writable (underlying SSL ops)
                 time.sleep(0.01) # Small sleep and retry
                 continue
            except socket.timeout:
                 # Timeout on individual recv call - check overall timeout and continue if OK
                 if time.monotonic() - start_time > timeout:
                      raise # Re-raise if overall timeout exceeded
                 else:
                      continue # Continue waiting if overall time permits
            # Other exceptions (OSError, SSLError, ConnectionAbortedError) will propagate up

    finally:
        # Restore original socket timeout
        try:
            ssock.settimeout(original_timeout)
        except Exception: pass # Ignore errors setting timeout back

    # Check if we received the full amount after the loop (in case of ConnectionAbortedError)
    if len(data) != length:
         # This path might be taken if ConnectionAbortedError was raised and caught above
         log.warning(f"SSL receive ended prematurely. Expected {length}, got {len(data)}.")
         # Let caller handle potentially incomplete data

    return bytes(data)

# --- END OF MODIFIED vpn.py ---