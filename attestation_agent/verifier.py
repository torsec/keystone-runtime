#!/usr/bin/env python3

# Simple Remote Attestation Verifier
# Used to test and verify attestation reports from Keystone enclaves
#
# Usage: python3 verifier.py

import socket
import struct
import time
import json
import base64
import os
from datetime import datetime

# Configuration
VERIFIER_HOST = '0.0.0.0'  # Listen on all interfaces
VERIFIER_PORT = 8087  # Verifier listens on host port 8087
BUFFER_SIZE = 8192  # Increased buffer size for certs and reports
ATTESTATION_INTERVAL = 15  # seconds
NONCE_LEN = 20  # Length of the nonce in bytes
UUID_LEN = 36 # Length of the UUID string
TARGET_UUID = "123e4567-e89b-12d3-a456-426614174000" # For testing purposes, we use a fixed UUID

class Command:
    PERFORM_ATTESTATION = 0x01
    GET_DICE_CERT_CHAIN = 0x02

class SimpleAttestationVerifier:
    def __init__(self):
        self.running = True
        self.expected_nonce = None

    def parse_dice_cert_chain(self, json_str):
        """Parse the DICE certificate chain from a JSON string."""
        try:
            report = json.loads(json_str)
            
            print("[VERIFIER] ---------- DICE Certificate Chain ----------")
            cert_chain_obj = report.get('dice_cert_chain', {})
            
            if not cert_chain_obj or not isinstance(cert_chain_obj, dict):
                print("[VERIFIER] Certificate chain is empty or not a valid object")
                return False

            for cert_name, cert_obj in cert_chain_obj.items():
                # Handle the UUID field
                if cert_name == 'uuid_b64':
                    uuid = base64.b64decode(cert_obj).rstrip(b'\x00').decode('utf-8')
                    print(f"  [UUID]")
                    print(f"    UUID: {uuid}")
                    continue

                if not isinstance(cert_obj, dict):
                    print(f"    - Item '{cert_name}' is not a valid certificate object.")
                    continue

                cert_b64 = cert_obj.get('cert_b64', '')
                length = cert_obj.get('length', 0)
                cert_data_full = base64.b64decode(cert_b64)
                
                cert_data = cert_data_full[:length]
                
                print(f"  [{cert_name.upper()} Certificate]")
                print(f"    Length: {length} bytes")
                print(f"    Data (hex): 0x{cert_data.hex()}")

                # In a real implementation, you would verify the certificate chain here, and save the valid LAK public keys in a DB

            return True
        except (json.JSONDecodeError, TypeError, KeyError, base64.binascii.Error) as e:
            print(f"[VERIFIER] Error processing certificate chain: {e}")
            print(f"[VERIFIER] Received raw data: {json_str}")
            return False


    def parse_attestation_report(self, json_str):
        """Parse the attestation report from a JSON string."""
        try:
            report = json.loads(json_str)

            print("[VERIFIER] ----- Attestation Report -----")
            
            enclave = report.get('enclave', {})
            print("  [Enclave]")
            print(f"    Hash        : {base64.b64decode(enclave.get('hash_b64', '')).hex()}")
            print(f"    Signature   : {base64.b64decode(enclave.get('signature_b64', '')).hex()}")
            print(f"    UUID        : {base64.b64decode(enclave.get('uuid_b64', '')).rstrip(b'\\x00').decode('utf-8')}")

            sm = report.get('sm', {})
            print("  [Security Monitor]")
            print(f"    Hash        : {base64.b64decode(sm.get('hash_b64', '')).hex()}")
            print(f"    Public Key  : {base64.b64decode(sm.get('public_key_b64', '')).hex()}")
            print(f"    Signature   : {base64.b64decode(sm.get('signature_b64', '')).hex()}")

            print(f" Device PubKey  : {base64.b64decode(report.get('dev_public_key_b64', '')).hex()}")
            
            received_nonce = base64.b64decode(report.get('nonce_b64', ''))
            print(f"    Nonce       : {received_nonce.hex()}")
            print()

            # --- Nonce Verification ---
            if self.expected_nonce and received_nonce == self.expected_nonce:
                print("[VERIFIER] Nonce verification PASSED")
            else:
                print(f"[VERIFIER] Nonce verification FAILED. Expected: {self.expected_nonce.hex() if self.expected_nonce else 'None'}")

            # --- Signature Verification ---
            # In a real implementation, you would verify the signatures. For instance, the verifier should verify that the enclave's signature is valid
            # using the LAK public key and knowing that the original message is (enclave_hash || nonce)

            return True

        except (json.JSONDecodeError, TypeError, KeyError, base64.binascii.Error) as e:
            print(f"[VERIFIER] Error processing report: {e}")
            print(f"[VERIFIER] Received raw data: {json_str}")
            return False

    def _send_command(self, sock, command, payload):
        """Sends a command with JSON payload."""
        try:
            json_payload = json.dumps(payload).encode('utf-8')
            message = struct.pack(f'<BI', command, len(json_payload)) + json_payload
            sock.sendall(message)
            return True
        except Exception as e:
            print(f"[VERIFIER] Failed to send command 0x{command:02x}: {e}")
            return False

    def send_get_cert_chain_command(self, client_sock):
        """Send the command to retrieve the DICE certificate chain."""
        payload = {"uuid_b64": base64.b64encode(TARGET_UUID.encode('utf-8')).decode('utf-8')}
        print(f"[VERIFIER] Sending command to get DICE certificate chain for UUID: {TARGET_UUID}")

        return self._send_command(client_sock, Command.GET_DICE_CERT_CHAIN, payload)

    def send_attestation_command(self, client_sock):
        """Generate a nonce and send the attestation command to the agent"""
        nonce = os.urandom(NONCE_LEN)
        self.expected_nonce = nonce

        payload = {
            "nonce_b64": base64.b64encode(nonce).decode('utf-8'),
            "uuid_b64": base64.b64encode(TARGET_UUID.encode('utf-8')).decode('utf-8')
        }
        print(f"[VERIFIER] Sending attestation command for UUID: {TARGET_UUID}")

        return self._send_command(client_sock, Command.PERFORM_ATTESTATION, payload)
        
    def recv_all(self, sock, n):
        """Helper function to receive 'n' bytes from a socket."""
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def handle_client(self, client_sock, client_addr):
        """Handle a single client connection."""
        print(f"[VERIFIER] Agent connected: {client_addr}")
        print("-" * 80)
        
        try:
            # Step 1: Get the DICE certificate chain
            if not self.send_get_cert_chain_command(client_sock):
                return

            len_data = self.recv_all(client_sock, 4)
            if not len_data:
                print(f"[VERIFIER] Agent {client_addr} disconnected before sending cert chain.")
                return
            
            cert_len = struct.unpack('<I', len_data)[0]
            cert_data = self.recv_all(client_sock, cert_len)
            if not cert_data:
                print(f"[VERIFIER] Agent {client_addr} disconnected while sending cert chain.")
                return
            
            self.parse_dice_cert_chain(cert_data.decode('utf-8'))
            print("-" * 80)

            # Step 2: Periodically request runtime attestation
            print(f"[VERIFIER] Starting automatic attestation every {ATTESTATION_INTERVAL} seconds")
            print("[VERIFIER] Press Ctrl+C to stop")
            print("-" * 80)

            report_count = 0
            last_attestation = 0
            client_sock.settimeout(1.0)

            while self.running:
                current_time = time.time()
                
                if current_time - last_attestation >= ATTESTATION_INTERVAL:
                    if not self.send_attestation_command(client_sock):
                        break
                    last_attestation = current_time
                
                try:
                    len_data = self.recv_all(client_sock, 4)
                    if not len_data: continue

                    report_len = struct.unpack('<I', len_data)[0]
                    report_data = self.recv_all(client_sock, report_len)
                    if not report_data:
                        print(f"[VERIFIER] Agent {client_addr} disconnected while sending report")
                        break
                    
                    report_count += 1
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    print(f"\n[VERIFIER] [{timestamp}] Attestation Report #{report_count} from {client_addr}")
                    self.parse_attestation_report(report_data.decode('utf-8'))
                    print("-" * 80)
                    print("-" * 80)
                    print("-" * 80)
                        
                except socket.timeout:
                    continue
                except (ConnectionResetError):
                    print(f"[VERIFIER] Connection reset by {client_addr}")
                    break
                    
        except Exception as e:
            print(f"[VERIFIER] Error handling agent {client_addr}: {e}")
        finally:
            client_sock.close()
            print(f"[VERIFIER] Agent disconnected: {client_addr}")

    def start(self):
        """Start the verifier server"""
        print(f"[VERIFIER] Starting Verifier...")
        print(f"[VERIFIER] Listening on {VERIFIER_HOST}:{VERIFIER_PORT}")
        print()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind((VERIFIER_HOST, VERIFIER_PORT))
            sock.listen(1)
            print(f"[VERIFIER] Waiting for agent connection...")
            
            while self.running:
                try:
                    client_sock, client_addr = sock.accept()
                    self.handle_client(client_sock, client_addr)
                    if self.running:
                        print(f"[VERIFIER] Waiting for new agent connection...")
                except KeyboardInterrupt:
                    self.running = False
                    break
                except Exception as e:
                    if self.running:
                        print(f"[VERIFIER] Error accepting connection: {e}")
                        time.sleep(1)
                        
        except Exception as e:
            print(f"[VERIFIER] Server Error: {e}")
        finally:
            print("\n[VERIFIER] Shutting down...")
            sock.close()
            print("[VERIFIER] Server stopped")

def main():
    verifier = SimpleAttestationVerifier()
    verifier.start()

if __name__ == "__main__":
    main()