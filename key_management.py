from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone
import uuid
import time

# List to store keys and their metadata
keys = []

# Function to generate a new RSA key and store it with a unique KID and expiration time
def generate_rsa_key():
    # Generate a new private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Derive the public key from the generated private key
    public_key = private_key.public_key()
  
    # Serialize the public key to PEM format for easy storage and sharing
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Create a unique Key ID (KID) using UUID
    kid = str(uuid.uuid4())
    # Set the expiration time for the key (1 hour from now)
    expiry = time.time() + 3600  # Key expires in 1 hour
  
    # Store the private key, public key, and metadata in the keys list
    keys.append({
        'kid': kid,                     # Unique Key ID
        'key': private_key,            # Store the private key for JWT signing
        'public_key_pem': public_key_pem.decode('utf-8'),  # Store the public key as a string
        'exp': expiry                   # Store the expiration timestamp
    })

    # Print out the generated key details
    print(f"Generated Key:\n KID: {kid}\n Public Key:\n {public_key_pem.decode('utf-8')}\n Expiration: {expiry}")

# Function to get all unexpired public keys
def get_public_keys():
    public_keys = []  # List to store unexpired public keys
    for key in keys:
        # Check if the key has not expired
        if key['exp'] > time.time():
            public_keys.append({
                'kid': key['kid'],      # Unique Key ID
                'kty': 'RSA',           # Key type
                'use': 'sig',           # Key usage (signature)
                'n': key['public_key_pem']  # Public key in PEM format
            })
    return public_keys  # Return the list of unexpired public keys

# Function to get the private key by its KID
def get_key(kid):
    # Iterate through the keys to find the one with the specified KID
    for key in keys:
        if key['kid'] == kid:
            return key  # Return the key if found
    return None  # Return None if the key is not found

# Function to get an expired key (if any)
def get_expired_key():
    # Iterate through the keys to find any expired keys
    for key in keys:
        if key['exp'] <= time.time():  # Check if the key is expired
            return key['kid'], key  # Return the KID and the expired key
    return None, None  # Return None if no expired key is found

# Generate an initial RSA key at the start of the application
generate_rsa_key()
