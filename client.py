#!/usr/bin/env python3
"""
ENCS4320 Applied Cryptography - Secure Communication Client
Student ID: 1220280

This client implements:
- Phase I: AES-128-CBC encryption with PKCS#7 padding
- Phase II: RSA-128 bit signatures + Diffie-Hellman key exchange
"""

import hashlib
import socket
import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime

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
    iv = get_random_bytes(16)  # Fresh random IV for each message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext  # IV is prepended to ciphertext

def decrypt_message(encrypted_data, key):
    """Decrypt AES-128-CBC encrypted message"""
    iv = encrypted_data[:16]  # Extract IV from first 16 bytes
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
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

def perform_key_exchange_client(sock, rsa_keypair, server_public_key):
    print("\n[CLIENT] Starting key exchange...")
    dh = DHKeyExchange()
    
    public_value_bytes = dh.public_value.to_bytes((dh.public_value.bit_length() + 7) // 8, 'big')
    signature = sign_data(public_value_bytes, rsa_keypair)
    print(f"[CLIENT] Signed DH public value")
    
    send_message(sock, len(public_value_bytes).to_bytes(4, 'big') + public_value_bytes + signature)
    print(f"[CLIENT] Sent signed DH public value to server")
    
    server_data = receive_message(sock)
    if not server_data:
        raise Exception("Failed to receive server's DH public value")
    
    server_pv_length = int.from_bytes(server_data[:4], 'big')
    server_public_value_bytes = server_data[4:4+server_pv_length]
    server_signature = server_data[4+server_pv_length:]
    
    if not verify_signature(server_public_value_bytes, server_signature, server_public_key):
        raise Exception("Server signature verification failed!")
    print(f"[CLIENT] Verified server's signature ✓")
    
    server_public_value = int.from_bytes(server_public_value_bytes, 'big')
    shared_secret = dh.compute_shared_secret(server_public_value)
    session_key = dh.derive_session_key(shared_secret)
    print(f"[CLIENT] Key exchange completed!")
    print(f"[CLIENT] Session key: {session_key.hex()}")
    
    return session_key

def run_client():
    print("\n" + "="*60)
    print(f"SECURE CLIENT - Student ID: {STUDENT_ID}")
    print("="*60)
    
    print("\n[CLIENT] Generating RSA keypair...")
    client_pubkey, client_privkey = generate_rsa_keypair()
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        print(f"\n[CLIENT] Connecting to {HOST}:{PORT}...")
        client_socket.connect((HOST, PORT))
        print("[CLIENT] Connected to server")
        
        server_public_key_bytes = receive_message(client_socket)
        server_public_key = RSA128Key.load_public(server_public_key_bytes)
        print("[CLIENT] Received server's public key")
        
        client_public_key_bytes = client_pubkey.save_public()
        send_message(client_socket, client_public_key_bytes)
        print("[CLIENT] Sent public key to server")
        
        session_key = perform_key_exchange_client(client_socket, client_privkey, server_public_key)
        
        print("\n" + "="*60)
        print("SECURE CHANNEL ESTABLISHED")
        print("="*60)
        
        print("\n[CLIENT] You can now send encrypted messages.")
        print("[CLIENT] Type 'exit' to quit.\n")
        
        while True:
            message = input("Enter message: ")
            
            encrypted_message = encrypt_message(message, session_key)
            send_message(client_socket, encrypted_message)
            print(f"[CLIENT] Encrypted: {encrypted_message.hex()[:40]}...")
            
            if message.lower() == 'exit':
                print("[CLIENT] Exiting...")
                break
            
            encrypted_response = receive_message(client_socket)
            if encrypted_response:
                response = decrypt_message(encrypted_response, session_key)
                print(f"[CLIENT] Response: {response}\n")
            else:
                print("[CLIENT] Server disconnected")
                break
                
    finally:
        client_socket.close()
        print("\n[CLIENT] Client shutdown")

if __name__ == "__main__":
    run_client()
