# TorrentGuard

1. This is a secure P2P file sharing system in Python that uses a tracker for peer discovery and TLS for encrypted communication. It supports chunk-based transfers, self-download, automatic certificate generation, and real-time progress tracking—making it ideal for decentralized and secure file sharing.

2. Objectives

- Develop a decentralized P2P file sharing system.
- Implement secure TLS communication between peers.
- Enable peers to self-download shared files.
- Provide reliable chunk verification and file integrity checks.
- Create a responsive command-line interface (CLI).

3. System Architecture
The system is divided into the following key components:

- Peer Node: Handles file sharing, chunk transmission, and reception.
- Tracker Server: Maintains metadata about shared files and peer locations.
- Chunk Manager: Manages file splitting, chunk storage, and validation.
- CLI Interface: Allows users to interact with the system (share/download files, monitor progress).

4. Key Features

- TLS Encryption: Secure communication using automatically generated self-signed certificates.
- Self-Download Support: A peer can share and immediately download its own file.
- Chunk-Based Transfer: Files are split into fixed-size chunks for efficient transfer and parallelism.
- Real-Time Progress Tracking: Displays live download statistics including speed and chunk count.
- Automatic Resume & Retry: Supports retrying failed chunks and resuming incomplete downloads.
- Peer Verification: Hash-based integrity checks for each chunk and the final assembled file.

5. Implementation Details

- Written in Python using standard libraries such as socket, threading, ssl, os, json, and cryptography.
- Peer communication is secured using TLS with self-signed certificates generated at runtime.
- Files are split into 256KB chunks and transferred individually.
- A local tracker stores file hashes, chunk metadata, and peer lists.
- CLI supports file sharing, downloading, and displaying peer status.

6. How Self-Download Works
When a file is shared by a peer, the system immediately registers it with the tracker. If download_after_share is enabled, the same peer initiates a download of the shared file, fetching chunks from itself. This validates sharing integrity and simulates seeding behavior even without other peers.

7. Security Considerations

- TLS ensures all peer connections are encrypted.
- Each chunk and the final file are verified using SHA-1 hashes.
- Self-signed certificates provide basic identity validation for encrypted traffic.

8. Testing and Results
The system was tested on a local network with multiple peers. File sharing and downloads completed successfully with consistent hash matches. Self-download worked reliably and helped validate shared data.

9. Conclusion

This project demonstrates a lightweight yet secure approach to peer-to-peer file sharing. It effectively combines decentralized communication with encrypted transfer, real-time progress tracking, and self-validation.

10. Future Improvements

- Implement GUI for better user experience.
- Add support for peer reputation and trust scoring.
- Introduce compression and deduplication mechanisms.
- Extend to support IPv6 and NAT traversal for broader network compatibility.

11. References

Python Documentation (https://docs.python.org/3/)

OpenSSL & TLS (https://www.openssl.org/)

Cryptography Python Library (https://cryptography.io/)

P2P Design Concepts and BitTorrent Protocol


