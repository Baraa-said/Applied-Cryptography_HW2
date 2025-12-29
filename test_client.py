#!/usr/bin/env python3
"""Test client script to demonstrate secure communication"""

import socket
import sys
sys.path.insert(0, '/Users/mac/Documents/Cryptography/Applied-Cryptography_HW2')
from code import *

print('\n' + '='*60)
print(f'SECURE COMMUNICATION PROJECT - Student ID: {STUDENT_ID}')
print('='*60)

print('\n' + '='*60)
print('STARTING CLIENT')
print('='*60)

# Generate client's RSA keypair
print('\n[CLIENT] Generating RSA keypair...')
client_rsa = generate_rsa_keypair()

# Create socket and connect
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    print(f'\n[CLIENT] Connecting to 127.0.0.1:12345...')
    client_socket.connect(('127.0.0.1', 12345))
    print('[CLIENT] Connected to server')
    
    # Exchange RSA public keys
    server_public_key_bytes = receive_message(client_socket)
    server_public_key = deserialize_public_key(server_public_key_bytes)
    print('[CLIENT] Received servers public key')
    
    client_public_key_bytes = serialize_public_key(client_rsa.publickey())
    send_message(client_socket, client_public_key_bytes)
    print('[CLIENT] Sent public key to server')
    
    # Perform Phase II key exchange
    session_key = perform_key_exchange_client(client_socket, client_rsa, server_public_key)
    
    print('\n' + '='*60)
    print('KEY EXCHANGE COMPLETE - SECURE CHANNEL ESTABLISHED')
    print(f'Session Key: {session_key.hex()}')
    print('='*60)
    
    # Send test messages
    test_messages = [
        'Hello, Secure World!', 
        'This message is encrypted with AES-CBC', 
        'Testing Phase II key exchange with Diffie-Hellman',
        'Perfect Forward Secrecy is achieved!',
        'exit'
    ]
    
    for message in test_messages:
        print(f'\n[CLIENT] Sending: {message}')
        encrypted_message = encrypt_message(message, session_key)
        send_message(client_socket, encrypted_message)
        print(f'[CLIENT] Sent encrypted: {encrypted_message.hex()[:64]}...')
        
        if message.lower() == 'exit':
            print('[CLIENT] Exiting...')
            break
        
        encrypted_response = receive_message(client_socket)
        if encrypted_response:
            response = decrypt_message(encrypted_response, session_key)
            print(f'[CLIENT] Received encrypted: {encrypted_response.hex()[:64]}...')
            print(f'[CLIENT] Decrypted response: {response}')

finally:
    client_socket.close()
    print('\n[CLIENT] Client shutdown')
    print('\n' + '='*60)
    print('DEMONSTRATION COMPLETE')
    print('='*60)
