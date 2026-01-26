#!/usr/bin/env python3
"""
ENCS4320 Applied Cryptography - Secure Communication Server
Student ID: 1220280

This server implements:
- Phase I: AES-128-CBC encryption with PKCS#7 padding
- Phase II: RSA-128 bit signatures + Diffie-Hellman key exchange
"""

import hashlib
import socket
import secrets
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
import custom_aes

# Configuration
STUDENT_ID = "1220280"
HOST = '127.0.0.1'
PORT = 12345

# Diffie-Hellman parameters (RFC 3526 - 1536-bit MODP Group)
DH_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
DH_GENERATOR = 2

# ============================================================================
# PHASE I: AES ENCRYPTION FUNCTIONS
# ============================================================================

def generate_aes_key(student_id):
    """Generate AES-128 key from Student ID using MD5 (16 bytes)"""
    return hashlib.md5(student_id.encode()).digest()

def generate_reference_iv(student_id):
    """Generate reference IV from Student ID using SHA256 (first 16 bytes)"""
    return hashlib.sha256(student_id.encode()).digest()[:16]

def encrypt_message(plaintext, key):
    """Encrypt message using AES-128-CBC with PKCS#7 padding and random IV"""
    iv = secrets.token_bytes(16)  # Fresh random IV for each message
    ciphertext = custom_aes.aes_encrypt_cbc(plaintext.encode('utf-8'), key, iv)
    return iv + ciphertext  # IV is prepended to ciphertext

def decrypt_message(encrypted_data, key):
    """Decrypt AES-128-CBC encrypted message"""
    iv = encrypted_data[:16]  # Extract IV from first 16 bytes
    ciphertext = encrypted_data[16:]
    plaintext = custom_aes.aes_decrypt_cbc(ciphertext, key, iv)
    return plaintext.decode('utf-8')

# ============================================================================
# PHASE II: RSA-128 SIGNATURES AND DIFFIE-HELLMAN KEY EXCHANGE
# ============================================================================

class RSA128Key:
    """Custom 128-bit RSA key class"""
    def __init__(self, n, e, d=None):
        self.n = n
        self.e = e
        self.d = d  # Private key component (None for public key)
    
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
    """Generate RSA-128 bit key pair for digital signatures"""
    # Generate two 64-bit primes for 128-bit modulus
    p = getPrime(64)
    q = getPrime(64)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    
    pubkey = RSA128Key(n, e)
    privkey = RSA128Key(n, e, d)
    print(f"[RSA] Generated 128-bit key pair (n={n.bit_length()} bits)")
    return (pubkey, privkey)

def sign_data(data, private_key):
    """Sign data using RSA-128 private key with truncated MD5 hash"""
    # Use MD5 hash truncated to 10 bytes (80 bits) to fit in 128-bit RSA
    h = hashlib.md5(data).digest()[:10]
    m = bytes_to_long(h)
    # RSA signature: s = m^d mod n
    sig = pow(m, private_key.d, private_key.n)
    return long_to_bytes(sig, 16)  # 16 bytes = 128 bits

def verify_signature(data, signature, public_key):
    """Verify RSA-128 signature using public key"""
    try:
        # Compute expected hash
        h = hashlib.md5(data).digest()[:10]
        m = bytes_to_long(h)
        # RSA verify: m' = s^e mod n
        sig_int = bytes_to_long(signature)
        m_verify = pow(sig_int, public_key.e, public_key.n)
        return m == m_verify
    except Exception:
        return False

class DHKeyExchange:
    """Diffie-Hellman key exchange for Perfect Forward Secrecy"""
    
    def __init__(self):
        # Generate random private value (ephemeral - new each session)
        self.private_value = secrets.randbelow(DH_PRIME - 2) + 1
        # Compute public value: g^private mod p
        self.public_value = pow(DH_GENERATOR, self.private_value, DH_PRIME)
        print(f"[DH] Generated DH values")
    
    def compute_shared_secret(self, other_public_value):
        """Compute shared secret: (other_public)^private mod p"""
        shared_secret = pow(other_public_value, self.private_value, DH_PRIME)
        return shared_secret
    
    def derive_session_key(self, shared_secret):
        """Derive AES-128 session key: SHA256(shared_secret)[0:16]"""
        secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
        session_key = hashlib.sha256(secret_bytes).digest()[:16]
        return session_key

# ============================================================================
# NETWORKING FUNCTIONS
# ============================================================================

def send_message(sock, data):
    """Send message with 4-byte length prefix"""
    length = len(data)
    sock.sendall(length.to_bytes(4, 'big'))
    sock.sendall(data)
    print(f"[NET] Sent {length} bytes")

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
    print(f"[NET] Received {length} bytes")
    return data

def perform_key_exchange_server(sock, rsa_keypair, client_public_key):
    print("\n[SERVER] Starting key exchange...")
    dh = DHKeyExchange()
    
    client_data = receive_message(sock)
    if not client_data:
        raise Exception("Failed to receive client's DH public value")
    
    client_pv_length = int.from_bytes(client_data[:4], 'big')
    client_public_value_bytes = client_data[4:4+client_pv_length]
    client_signature = client_data[4+client_pv_length:]
    
    if not verify_signature(client_public_value_bytes, client_signature, client_public_key):
        raise Exception("Client signature verification failed!")
    print(f"[SERVER] Verified client's signature ✓")
    
    public_value_bytes = dh.public_value.to_bytes((dh.public_value.bit_length() + 7) // 8, 'big')
    signature = sign_data(public_value_bytes, rsa_keypair)
    print(f"[SERVER] Signed DH public value")
    
    send_message(sock, len(public_value_bytes).to_bytes(4, 'big') + public_value_bytes + signature)
    print(f"[SERVER] Sent signed DH public value to client")
    
    client_public_value = int.from_bytes(client_public_value_bytes, 'big')
    shared_secret = dh.compute_shared_secret(client_public_value)
    session_key = dh.derive_session_key(shared_secret)
    print(f"[SERVER] Key exchange completed!")
    print(f"[SERVER] Session key: {session_key.hex()}")
    
    return session_key

def run_server():
    print("\n" + "="*60)
    print(f"SECURE SERVER - Student ID: {STUDENT_ID}")
    print("="*60)
    
    print("\n[SERVER] Generating RSA keypair...")
    server_pubkey, server_privkey = generate_rsa_keypair()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"\n[SERVER] Listening on {HOST}:{PORT}")
        print("[SERVER] Waiting for client connection...")
        
        client_socket, client_address = server_socket.accept()
        print(f"[SERVER] Client connected from {client_address}")
        
        try:
            server_public_key_bytes = server_pubkey.save_public()
            send_message(client_socket, server_public_key_bytes)
            print("[SERVER] Sent public key to client")
            
            client_public_key_bytes = receive_message(client_socket)
            if not client_public_key_bytes:
                print("[SERVER] Error: Client disconnected")
                return
            client_public_key = RSA128Key.load_public(client_public_key_bytes)
            print("[SERVER] Received client's public key")
            
            session_key = perform_key_exchange_server(client_socket, server_privkey, client_public_key)
            
            print("\n" + "="*60)
            print("SECURE CHANNEL ESTABLISHED")
            print("="*60)
            
            print("\n[SERVER] Ready to receive encrypted messages...")
            while True:
                encrypted_data = receive_message(client_socket)
                if not encrypted_data:
                    print("[SERVER] Client disconnected")
                    break
                
                try:
                    message = decrypt_message(encrypted_data, session_key)
                    print(f"\n[SERVER] Encrypted: {encrypted_data.hex()[:40]}...")
                    print(f"[SERVER] Decrypted: {message}")
                    
                    if message.lower() == 'exit':
                        print("[SERVER] Client requested exit")
                        break
                    
                    response = f"Server received: '{message}'"
                    encrypted_response = encrypt_message(response, session_key)
                    send_message(client_socket, encrypted_response)
                    
                except Exception as e:
                    print(f"[SERVER] Error: {e}")
                    break
                    
        finally:
            client_socket.close()
            
    finally:
        server_socket.close()
        print("\n[SERVER] Server shutdown")

if __name__ == "__main__":
    run_server()
