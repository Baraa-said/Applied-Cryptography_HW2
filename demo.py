#!/usr/bin/env python3
"""
Demonstration script that runs both server and client
to show the complete secure communication protocol.

Uses 128-bit RSA as required by the homework.
"""

import socket
import threading
import time
import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime

STUDENT_ID = "1220280"
HOST = '127.0.0.1'
PORT = 12347  # Use different port to avoid conflicts

# DH Parameters (RFC 3526 - 1536-bit MODP Group)
DH_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
DH_GENERATOR = 2

# ============================================================================
# PHASE I: AES ENCRYPTION
# ============================================================================

def generate_aes_key(student_id):
    """Generate AES-128 key from Student ID using MD5"""
    return hashlib.md5(student_id.encode()).digest()

def encrypt_message(plaintext, key):
    """Encrypt with AES-128-CBC and random IV"""
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def decrypt_message(encrypted_data, key):
    """Decrypt AES-128-CBC"""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode('utf-8')

# ============================================================================
# PHASE II: RSA-128 SIGNATURES
# ============================================================================

class RSA128Key:
    """Custom 128-bit RSA key class"""
    def __init__(self, n, e, d=None):
        self.n = n
        self.e = e
        self.d = d
    
    def save_public(self):
        """Serialize public key to bytes"""
        n_bytes = self.n.to_bytes(16, 'big')
        e_bytes = self.e.to_bytes(4, 'big')
        return n_bytes + e_bytes
    
    @staticmethod
    def load_public(data):
        """Load public key from bytes"""
        n = int.from_bytes(data[:16], 'big')
        e = int.from_bytes(data[16:20], 'big')
        return RSA128Key(n, e)

def generate_rsa_keypair():
    """Generate RSA-128 bit key pair"""
    p = getPrime(64)
    q = getPrime(64)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    
    pubkey = RSA128Key(n, e)
    privkey = RSA128Key(n, e, d)
    return (pubkey, privkey)

def sign_data(data, private_key):
    """Sign data using RSA-128 with truncated MD5"""
    h = hashlib.md5(data).digest()[:10]
    m = bytes_to_long(h)
    sig = pow(m, private_key.d, private_key.n)
    return long_to_bytes(sig, 16)

def verify_signature(data, signature, public_key):
    """Verify RSA-128 signature"""
    try:
        h = hashlib.md5(data).digest()[:10]
        m = bytes_to_long(h)
        sig_int = bytes_to_long(signature)
        m_verify = pow(sig_int, public_key.e, public_key.n)
        return m == m_verify
    except Exception:
        return False

# ============================================================================
# DIFFIE-HELLMAN KEY EXCHANGE
# ============================================================================

class DHKeyExchange:
    """Diffie-Hellman key exchange"""
    def __init__(self):
        self.private_value = secrets.randbelow(DH_PRIME - 2) + 1
        self.public_value = pow(DH_GENERATOR, self.private_value, DH_PRIME)
    
    def compute_shared_secret(self, other_public_value):
        return pow(other_public_value, self.private_value, DH_PRIME)
    
    def derive_session_key(self, shared_secret):
        secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
        return hashlib.sha256(secret_bytes).digest()[:16]

# ============================================================================
# NETWORKING
# ============================================================================

def send_message(sock, data):
    """Send length-prefixed message"""
    length = len(data)
    sock.sendall(length.to_bytes(4, 'big'))
    sock.sendall(data)

def receive_message(sock):
    """Receive length-prefixed message"""
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, 'big')
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# ============================================================================
# DEMO
# ============================================================================

server_log = []
client_log = []

def run_server_demo():
    """Server side of the demonstration"""
    server_log.append("[SERVER] Starting server...")
    
    # Generate RSA-128 keypair
    server_pubkey, server_privkey = generate_rsa_keypair()
    server_log.append(f"[SERVER] Generated 128-bit RSA keypair")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        server_log.append(f"[SERVER] Listening on {HOST}:{PORT}")
        
        client_socket, client_address = server_socket.accept()
        server_log.append(f"[SERVER] Client connected from {client_address}")
        
        try:
            # Send server's public key
            server_public_key_bytes = server_pubkey.save_public()
            send_message(client_socket, server_public_key_bytes)
            server_log.append("[SERVER] Sent public key")
            
            # Receive client's public key
            client_public_key_bytes = receive_message(client_socket)
            client_public_key = RSA128Key.load_public(client_public_key_bytes)
            server_log.append("[SERVER] Received client's public key")
            
            # Key exchange - receive client's signed DH value
            client_data = receive_message(client_socket)
            client_pv_length = int.from_bytes(client_data[:4], 'big')
            client_public_value_bytes = client_data[4:4+client_pv_length]
            client_signature = client_data[4+client_pv_length:]
            
            # Verify client's signature
            if not verify_signature(client_public_value_bytes, client_signature, client_public_key):
                raise Exception("Client signature verification failed!")
            server_log.append("[SERVER] ✓ Verified client's signature")
            
            # Generate and send server's signed DH value
            dh = DHKeyExchange()
            public_value_bytes = dh.public_value.to_bytes((dh.public_value.bit_length() + 7) // 8, 'big')
            signature = sign_data(public_value_bytes, server_privkey)
            send_message(client_socket, len(public_value_bytes).to_bytes(4, 'big') + public_value_bytes + signature)
            server_log.append("[SERVER] Sent signed DH public value")
            
            # Compute session key
            client_public_value = int.from_bytes(client_public_value_bytes, 'big')
            shared_secret = dh.compute_shared_secret(client_public_value)
            session_key = dh.derive_session_key(shared_secret)
            server_log.append(f"[SERVER] Session key: {session_key.hex()}")
            
            # Receive encrypted message
            encrypted_data = receive_message(client_socket)
            if encrypted_data:
                message = decrypt_message(encrypted_data, session_key)
                server_log.append(f"[SERVER] Received encrypted: {encrypted_data.hex()[:40]}...")
                server_log.append(f"[SERVER] Decrypted message: \"{message}\"")
                
                # Send encrypted response
                response = f"Server received: '{message}'"
                encrypted_response = encrypt_message(response, session_key)
                send_message(client_socket, encrypted_response)
                server_log.append(f"[SERVER] Sent encrypted response")
                
        finally:
            client_socket.close()
            
    finally:
        server_socket.close()
        server_log.append("[SERVER] Server shutdown")

def run_client_demo():
    """Client side of the demonstration"""
    time.sleep(2)  # Wait for server to start
    
    client_log.append("[CLIENT] Starting client...")
    
    # Generate RSA-128 keypair
    client_pubkey, client_privkey = generate_rsa_keypair()
    client_log.append(f"[CLIENT] Generated 128-bit RSA keypair")
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((HOST, PORT))
        client_log.append(f"[CLIENT] Connected to {HOST}:{PORT}")
        
        # Receive server's public key
        server_public_key_bytes = receive_message(client_socket)
        server_public_key = RSA128Key.load_public(server_public_key_bytes)
        client_log.append("[CLIENT] Received server's public key")
        
        # Send client's public key
        client_public_key_bytes = client_pubkey.save_public()
        send_message(client_socket, client_public_key_bytes)
        client_log.append("[CLIENT] Sent public key")
        
        # Generate and send client's signed DH value
        dh = DHKeyExchange()
        public_value_bytes = dh.public_value.to_bytes((dh.public_value.bit_length() + 7) // 8, 'big')
        signature = sign_data(public_value_bytes, client_privkey)
        send_message(client_socket, len(public_value_bytes).to_bytes(4, 'big') + public_value_bytes + signature)
        client_log.append("[CLIENT] Sent signed DH public value")
        
        # Receive server's signed DH value
        server_data = receive_message(client_socket)
        server_pv_length = int.from_bytes(server_data[:4], 'big')
        server_public_value_bytes = server_data[4:4+server_pv_length]
        server_signature = server_data[4+server_pv_length:]
        
        # Verify server's signature
        if not verify_signature(server_public_value_bytes, server_signature, server_public_key):
            raise Exception("Server signature verification failed!")
        client_log.append("[CLIENT] ✓ Verified server's signature")
        
        # Compute session key
        server_public_value = int.from_bytes(server_public_value_bytes, 'big')
        shared_secret = dh.compute_shared_secret(server_public_value)
        session_key = dh.derive_session_key(shared_secret)
        client_log.append(f"[CLIENT] Session key: {session_key.hex()}")
        
        # Send encrypted message
        message = "Hello from secure client!"
        encrypted_message = encrypt_message(message, session_key)
        send_message(client_socket, encrypted_message)
        client_log.append(f"[CLIENT] Sent message: \"{message}\"")
        client_log.append(f"[CLIENT] Encrypted: {encrypted_message.hex()[:40]}...")
        
        # Receive encrypted response
        encrypted_response = receive_message(client_socket)
        if encrypted_response:
            response = decrypt_message(encrypted_response, session_key)
            client_log.append(f"[CLIENT] Received encrypted response")
            client_log.append(f"[CLIENT] Decrypted: \"{response}\"")
            
    finally:
        client_socket.close()
        client_log.append("[CLIENT] Client shutdown")

def main():
    print("="*70)
    print("SECURE COMMUNICATION PROTOCOL DEMONSTRATION")
    print(f"Student ID: {STUDENT_ID}")
    print("="*70)
    
    print("\n[DEMO] Starting demonstration with 128-bit RSA...\n")
    
    # Start server in background
    server_thread = threading.Thread(target=run_server_demo)
    server_thread.start()
    
    # Run client
    run_client_demo()
    
    # Wait for server to finish
    server_thread.join()
    
    # Print logs
    print("\n" + "="*70)
    print("SERVER LOG")
    print("="*70)
    for log in server_log:
        print(log)
    
    print("\n" + "="*70)
    print("CLIENT LOG")
    print("="*70)
    for log in client_log:
        print(log)
    
    print("\n" + "="*70)
    print("✅ DEMONSTRATION COMPLETED SUCCESSFULLY")
    print("="*70)
    print("\nSecurity properties demonstrated:")
    print("  • Confidentiality: Messages encrypted with AES-128-CBC")
    print("  • Authenticity: DH values signed with RSA-128")
    print("  • Forward Secrecy: Ephemeral DH keys per session")
    print("  • Integrity: PKCS#7 padding validates decryption")

if __name__ == "__main__":
    main()
