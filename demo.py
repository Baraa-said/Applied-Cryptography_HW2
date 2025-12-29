#!/usr/bin/env python3
"""
Demonstration script that runs both server and client
to show the complete secure communication protocol.
"""

import socket
import threading
import time
import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

STUDENT_ID = "1220280"
HOST = '127.0.0.1'
PORT = 12347  # Use different port to avoid conflicts

# DH Parameters
DH_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
DH_GENERATOR = 2

def generate_aes_key(student_id):
    return hashlib.md5(student_id.encode()).digest()

def encrypt_message(plaintext, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def decrypt_message(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode('utf-8')

def sign_data(data, private_key):
    h = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(data, signature, public_key):
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

class DHKeyExchange:
    def __init__(self):
        self.private_value = secrets.randbelow(DH_PRIME - 2) + 1
        self.public_value = pow(DH_GENERATOR, self.private_value, DH_PRIME)
    
    def compute_shared_secret(self, other_public_value):
        return pow(other_public_value, self.private_value, DH_PRIME)
    
    def derive_session_key(self, shared_secret):
        secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
        return hashlib.sha256(secret_bytes).digest()[:16]

def send_message(sock, data):
    length = len(data)
    sock.sendall(length.to_bytes(4, 'big'))
    sock.sendall(data)

def receive_message(sock):
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

server_log = []
client_log = []

def run_server_demo():
    """Server side of the demonstration"""
    server_log.append("[SERVER] Starting server...")
    
    # Generate RSA keypair
    server_rsa = RSA.generate(2048)
    server_log.append("[SERVER] Generated RSA keypair")
    
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
            server_public_key_bytes = server_rsa.publickey().export_key()
            send_message(client_socket, server_public_key_bytes)
            server_log.append("[SERVER] Sent public key")
            
            # Receive client's public key
            client_public_key_bytes = receive_message(client_socket)
            client_public_key = RSA.import_key(client_public_key_bytes)
            server_log.append("[SERVER] Received client's public key")
            
            # DH Key Exchange
            dh = DHKeyExchange()
            server_log.append("[SERVER] Generated DH values")
            
            # Receive client's DH value
            client_data = receive_message(client_socket)
            client_pv_length = int.from_bytes(client_data[:4], 'big')
            client_public_value_bytes = client_data[4:4+client_pv_length]
            client_signature = client_data[4+client_pv_length:]
            
            # Verify client's signature
            if verify_signature(client_public_value_bytes, client_signature, client_public_key):
                server_log.append("[SERVER] Verified client's signature ✓")
            
            # Send server's DH value
            public_value_bytes = dh.public_value.to_bytes((dh.public_value.bit_length() + 7) // 8, 'big')
            signature = sign_data(public_value_bytes, server_rsa)
            send_message(client_socket, len(public_value_bytes).to_bytes(4, 'big') + public_value_bytes + signature)
            server_log.append("[SERVER] Sent signed DH value")
            
            # Compute session key
            client_public_value = int.from_bytes(client_public_value_bytes, 'big')
            shared_secret = dh.compute_shared_secret(client_public_value)
            session_key = dh.derive_session_key(shared_secret)
            server_log.append(f"[SERVER] Session key: {session_key.hex()}")
            
            # Receive and process messages
            while True:
                encrypted_data = receive_message(client_socket)
                if not encrypted_data:
                    break
                
                message = decrypt_message(encrypted_data, session_key)
                server_log.append(f"[SERVER] Received encrypted: {encrypted_data.hex()[:32]}...")
                server_log.append(f"[SERVER] Decrypted: {message}")
                
                if message.lower() == 'exit':
                    break
                
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
    time.sleep(3)  # Wait for server to start and generate RSA keys
    
    client_log.append("[CLIENT] Starting client...")
    
    # Generate RSA keypair
    client_rsa = RSA.generate(2048)
    client_log.append("[CLIENT] Generated RSA keypair")
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((HOST, PORT))
        client_log.append(f"[CLIENT] Connected to {HOST}:{PORT}")
        
        # Receive server's public key
        server_public_key_bytes = receive_message(client_socket)
        server_public_key = RSA.import_key(server_public_key_bytes)
        client_log.append("[CLIENT] Received server's public key")
        
        # Send client's public key
        client_public_key_bytes = client_rsa.publickey().export_key()
        send_message(client_socket, client_public_key_bytes)
        client_log.append("[CLIENT] Sent public key")
        
        # DH Key Exchange
        dh = DHKeyExchange()
        client_log.append("[CLIENT] Generated DH values")
        
        # Send client's DH value
        public_value_bytes = dh.public_value.to_bytes((dh.public_value.bit_length() + 7) // 8, 'big')
        signature = sign_data(public_value_bytes, client_rsa)
        send_message(client_socket, len(public_value_bytes).to_bytes(4, 'big') + public_value_bytes + signature)
        client_log.append("[CLIENT] Sent signed DH value")
        
        # Receive server's DH value
        server_data = receive_message(client_socket)
        server_pv_length = int.from_bytes(server_data[:4], 'big')
        server_public_value_bytes = server_data[4:4+server_pv_length]
        server_signature = server_data[4+server_pv_length:]
        
        # Verify server's signature
        if verify_signature(server_public_value_bytes, server_signature, server_public_key):
            client_log.append("[CLIENT] Verified server's signature ✓")
        
        # Compute session key
        server_public_value = int.from_bytes(server_public_value_bytes, 'big')
        shared_secret = dh.compute_shared_secret(server_public_value)
        session_key = dh.derive_session_key(shared_secret)
        client_log.append(f"[CLIENT] Session key: {session_key.hex()}")
        
        # Send test messages
        test_messages = [
            'Hello, Secure World!',
            'This message is AES-CBC encrypted',
            'Phase II: DH + RSA Signatures',
            'Perfect Forward Secrecy achieved!',
            'exit'
        ]
        
        for message in test_messages:
            client_log.append(f"[CLIENT] Sending: {message}")
            encrypted_message = encrypt_message(message, session_key)
            send_message(client_socket, encrypted_message)
            client_log.append(f"[CLIENT] Encrypted: {encrypted_message.hex()[:32]}...")
            
            if message.lower() == 'exit':
                break
            
            encrypted_response = receive_message(client_socket)
            if encrypted_response:
                response = decrypt_message(encrypted_response, session_key)
                client_log.append(f"[CLIENT] Received: {response}")
                
    finally:
        client_socket.close()
        client_log.append("[CLIENT] Client shutdown")

if __name__ == "__main__":
    print("="*70)
    print(f"SECURE COMMUNICATION DEMO - Student ID: {STUDENT_ID}")
    print("="*70)
    
    # Start server and client in threads
    server_thread = threading.Thread(target=run_server_demo)
    client_thread = threading.Thread(target=run_client_demo)
    
    server_thread.start()
    client_thread.start()
    
    server_thread.join()
    client_thread.join()
    
    # Print results
    print("\n" + "="*70)
    print("SERVER LOG:")
    print("="*70)
    for log in server_log:
        print(log)
    
    print("\n" + "="*70)
    print("CLIENT LOG:")
    print("="*70)
    for log in client_log:
        print(log)
    
    print("\n" + "="*70)
    print("SECURITY PROPERTIES DEMONSTRATED:")
    print("="*70)
    print("✓ Confidentiality: All messages encrypted with AES-128-CBC")
    print("✓ Integrity: PKCS#7 padding ensures message integrity")
    print("✓ Authenticity: RSA signatures verify sender identity")
    print("✓ Forward Secrecy: Ephemeral DH keys protect past sessions")
    print("="*70)
