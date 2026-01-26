import hashlib
import socket
import secrets
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
import custom_aes

STUDENT_ID = "1220280"

def generate_aes_key(student_id):
    key = hashlib.md5(student_id.encode()).digest()
    print(f"[CRYPTO] Generated AES Key (hex): {key.hex()}")
    return key

def generate_reference_iv(student_id):
    iv = hashlib.sha256(student_id.encode()).digest()[:16]
    print(f"[CRYPTO] Reference IV (hex): {iv.hex()}")
    return iv

def encrypt_message(plaintext, key):
    iv = secrets.token_bytes(16)
    ciphertext = custom_aes.aes_encrypt_cbc(plaintext.encode('utf-8'), key, iv)
    return iv + ciphertext

def decrypt_message(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    plaintext = custom_aes.aes_decrypt_cbc(ciphertext, key, iv)
    return plaintext.decode('utf-8')

# ============================================================================
# PHASE II: RSA-128 SIGNATURES
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
    print(f"[RSA] Public key (n={n}, e={e})")
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
        print("m: ",m)
        print("m_verify: ",m_verify)
        return m == m_verify
    except Exception:
        return False

DH_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
DH_GENERATOR = 2

class DHKeyExchange:
    def __init__(self):
        self.private_value = secrets.randbelow(DH_PRIME - 2) + 1
        self.public_value = pow(DH_GENERATOR, self.private_value, DH_PRIME)
        print(f"[DH] Generated private value")
        print(f"[DH] Computed public value: {self.public_value}")
    
    def compute_shared_secret(self, other_public_value):
        shared_secret = pow(other_public_value, self.private_value, DH_PRIME)
        print(f"[DH] Computed shared secret")
        return shared_secret
    
    def derive_session_key(self, shared_secret):
        secret_bytes = shared_secret.to_bytes(
            (shared_secret.bit_length() + 7) // 8, 
            'big'
        )
        session_key = hashlib.sha256(secret_bytes).digest()[:16]
        print(f"[DH] Derived session key: {session_key.hex()}")
        return session_key

def test_phase1_encryption():
    print("\n" + "="*60)
    print("TESTING PHASE I: AES ENCRYPTION")
    print("="*60)
    
    key = generate_aes_key(STUDENT_ID)
    message = "Hello, this is a secure message!"
    print(f"\n[TEST] Original message: {message}")
    
    encrypted = encrypt_message(message, key)
    print(f"[TEST] Encrypted (hex): {encrypted.hex()}")
    print(f"[TEST] Length: {len(encrypted)} bytes (16 IV + {len(encrypted)-16} ciphertext)")
    
    decrypted = decrypt_message(encrypted, key)
    print(f"[TEST] Decrypted message: {decrypted}")
    if message == decrypted:
        print("[TEST] ✓ SUCCESS: Encryption/Decryption working!")
    else:
        print("[TEST] ✗ FAILED: Messages don't match!")
    


    print("\n[TEST] encrypte with different IV")
    encrypted2 = encrypt_message(message, key)
    print("Ciphertext 1: ",encrypted.hex())
    print("Ciphertext 2: ",encrypted2.hex())
    if encrypted != encrypted2:
        
        print("[TEST] ✓ SUCCESS: Different IVs produce different ciphertexts!")
    else:
        print("[TEST] ✗ WARNING: Same ciphertext - IV might not be random!")


    print("\n[TEST] encrypte with same IV")
    iv=generate_reference_iv(STUDENT_ID)
    plaintext1="Hello, this is a secure message!"
    encrypted3=iv+custom_aes.aes_encrypt_cbc(plaintext1.encode('utf-8'), key, iv)
    encrypted4=iv+custom_aes.aes_encrypt_cbc(plaintext1.encode('utf-8'), key, iv)
    print("Ciphertext 1: ",encrypted3.hex())
    print("Ciphertext 2: ",encrypted4.hex())
    if encrypted3==encrypted4:
        print("[TEST] Same IVs produce same ciphertext")
    else:
        print("[TEST] Same IVs produce different ciphertext")


    

def test_phase2_signatures():
    print("\n" + "="*60)
    print("TESTING PHASE II: RSA SIGNATURES")
    print("="*60)
    
    pubkey, privkey = generate_rsa_keypair()
    data = b"Test message for signing"
    print(f"\n[TEST] Data to sign: {data}")
    
    signature = sign_data(data, privkey)
    print(f"[TEST] Signature (hex): {signature.hex()}")
    
    if verify_signature(data, signature, pubkey):
        print("[TEST] ✓ SUCCESS: Signature verified with correct key!")
    else:
        print("[TEST] ✗ FAILED: Signature verification failed!")
    
    wrong_data = b"Different message"
    if not verify_signature(wrong_data, signature, pubkey):
        print("[TEST] ✓ SUCCESS: Signature rejected for wrong data!")
    else:
        print("[TEST] ✗ FAILED: Signature verified wrong data!")

def test_phase2_dh():
    print("\n" + "="*60)
    print("TESTING PHASE II: DIFFIE-HELLMAN KEY EXCHANGE")
    print("="*60)
    
    print("\n[TEST] Party A generating DH values...")
    dh_a = DHKeyExchange()
    
    print("\n[TEST] Party B generating DH values...")
    dh_b = DHKeyExchange()
    
    print("\n[TEST] Computing shared secrets...")
    secret_a = dh_a.compute_shared_secret(dh_b.public_value)
    secret_b = dh_b.compute_shared_secret(dh_a.public_value)
    
    if secret_a == secret_b:
        print("[TEST] ✓ SUCCESS: Both parties computed same shared secret!")
        
        key_a = dh_a.derive_session_key(secret_a)
        key_b = dh_b.derive_session_key(secret_b)
        
        if key_a == key_b:
            print("[TEST] ✓ SUCCESS: Both parties derived same session key!")
        else:
            print("[TEST] ✗ FAILED: Session keys don't match!")
    else:
        print("[TEST] ✗ FAILED: Shared secrets don't match!")

def send_message(sock, data):
    length = len(data)
    sock.sendall(length.to_bytes(4, 'big'))
    sock.sendall(data)
    print(f"[NET] Sent {length} bytes")

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
    
    print(f"[NET] Received {length} bytes")
    return data

def serialize_public_key(rsa_pubkey):
    """Serialize RSA-128 public key to bytes"""
    return rsa_pubkey.save_public()

def deserialize_public_key(key_bytes):
    """Deserialize RSA-128 public key from bytes"""
    return RSA128Key.load_public(key_bytes)

def perform_key_exchange_client(sock, rsa_keypair, server_public_key):
    print("\n[CLIENT] Starting key exchange...")
    
    dh = DHKeyExchange()
    
    public_value_bytes = dh.public_value.to_bytes(
        (dh.public_value.bit_length() + 7) // 8, 'big'
    )
    
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
    print(f"[CLIENT] Key exchange completed successfully!")
    
    return session_key

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
    
    public_value_bytes = dh.public_value.to_bytes(
        (dh.public_value.bit_length() + 7) // 8, 'big'
    )
    signature = sign_data(public_value_bytes, rsa_keypair)
    print(f"[SERVER] Signed DH public value")
    
    send_message(sock, len(public_value_bytes).to_bytes(4, 'big') + public_value_bytes + signature)
    print(f"[SERVER] Sent signed DH public value to client")
    
    client_public_value = int.from_bytes(client_public_value_bytes, 'big')
    
    shared_secret = dh.compute_shared_secret(client_public_value)
    
    session_key = dh.derive_session_key(shared_secret)
    print(f"[SERVER] Key exchange completed successfully!")
    
    return session_key

HOST = '127.0.0.1'
PORT = 12345

def run_server():
    print("\n" + "="*60)
    print("STARTING SERVER")
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
            server_public_key_bytes = serialize_public_key(server_pubkey)
            send_message(client_socket, server_public_key_bytes)
            print("[SERVER] Sent public key to client")
            
            client_public_key_bytes = receive_message(client_socket)
            if not client_public_key_bytes:
                print("[SERVER] Error: Client disconnected before sending public key")
                return
            client_public_key = deserialize_public_key(client_public_key_bytes)
            print("[SERVER] Received client's public key")
            
            session_key = perform_key_exchange_server(
                client_socket, server_privkey, client_public_key
            )
            
            print("\n" + "="*60)
            print("KEY EXCHANGE COMPLETE - SECURE CHANNEL ESTABLISHED")
            print(f"Session Key: {session_key.hex()}")
            print("="*60)
            
            print("\n[SERVER] Ready to receive encrypted messages...")
            while True:
                encrypted_data = receive_message(client_socket)
                if not encrypted_data:
                    print("[SERVER] Client disconnected")
                    break
                
                try:
                    message = decrypt_message(encrypted_data, session_key)
                    print(f"\n[SERVER] Received (encrypted): {encrypted_data.hex()[:64]}...")
                    print(f"[SERVER] Decrypted message: {message}")
                    
                    if message.lower() == 'exit':
                        print("[SERVER] Client requested exit")
                        break
                    
                    response = f"Server received: '{message}'"
                    encrypted_response = encrypt_message(response, session_key)
                    send_message(client_socket, encrypted_response)
                    print(f"[SERVER] Sent encrypted response")
                    
                except Exception as e:
                    print(f"[SERVER] Decryption error: {e}")
                    break
                    
        finally:
            client_socket.close()
            
    finally:
        server_socket.close()
        print("\n[SERVER] Server shutdown")

def run_client():
    print("\n" + "="*60)
    print("STARTING CLIENT")
    print("="*60)
    
    print("\n[CLIENT] Generating RSA keypair...")
    client_pubkey, client_privkey = generate_rsa_keypair()
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        print(f"\n[CLIENT] Connecting to {HOST}:{PORT}...")
        client_socket.connect((HOST, PORT))
        print("[CLIENT] Connected to server")
        
        server_public_key_bytes = receive_message(client_socket)
        server_public_key = deserialize_public_key(server_public_key_bytes)
        print("[CLIENT] Received server's public key")
        
        client_public_key_bytes = serialize_public_key(client_pubkey)
        send_message(client_socket, client_public_key_bytes)
        print("[CLIENT] Sent public key to server")
        
        session_key = perform_key_exchange_client(
            client_socket, client_privkey, server_public_key
        )
        
        print("\n" + "="*60)
        print("KEY EXCHANGE COMPLETE - SECURE CHANNEL ESTABLISHED")
        print(f"Session Key: {session_key.hex()}")
        print("="*60)
        
        print("\n[CLIENT] You can now send encrypted messages.")
        print("[CLIENT] Type 'exit' to quit.\n")
        
        while True:
            message = input("Enter message: ")
            
            encrypted_message = encrypt_message(message, session_key)
            send_message(client_socket, encrypted_message)
            print(f"[CLIENT] Sent encrypted: {encrypted_message.hex()[:64]}...")
            
            if message.lower() == 'exit':
                print("[CLIENT] Exiting...")
                break
            
            encrypted_response = receive_message(client_socket)
            if encrypted_response:
                response = decrypt_message(encrypted_response, session_key)
                print(f"[CLIENT] Received (encrypted): {encrypted_response.hex()[:64]}...")
                print(f"[CLIENT] Decrypted response: {response}\n")
            else:
                print("[CLIENT] Server disconnected")
                break
                
    finally:
        client_socket.close()
        print("\n[CLIENT] Client shutdown")

if __name__ == "__main__":
    import sys
    
    print("\n" + "="*60)
    print(f"SECURE COMMUNICATION PROJECT - Student ID: {STUDENT_ID}")
    print("="*60)
    
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        
        if mode == "server":
            run_server()
        elif mode == "client":
            run_client()
        elif mode == "test":
            test_phase1_encryption()
            test_phase2_signatures()
            test_phase2_dh()
            print("\n" + "="*60)
            print("ALL TESTS COMPLETED SUCCESSFULLY")
            print("="*60)
        else:
            print(f"Unknown mode: {mode}")
            print("Usage: python code.py [test|server|client]")
    else:
        test_phase1_encryption()
        test_phase2_signatures()
        test_phase2_dh()
        
        print("\n" + "="*60)
        print("TESTS COMPLETED")
        print("="*60)
        print("\nUsage:")
        print("  python code.py test    - Run cryptographic tests")
        print("  python code.py server  - Start server (run first)")
        print("  python code.py client  - Start client (run after server)")
        print("\nSteps to test secure communication:")
        print("1. Open Terminal 1: python code.py server")
        print("2. Open Terminal 2: python code.py client")
        print("3. Type messages in client to send to server")
        print("4. Use Wireshark to capture traffic on localhost")
        print("5. Verify all traffic is encrypted (no plaintext visible)")
