from flask import Flask, jsonify, request
import jwt
import time
import uuid
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

# Global list to store RSA keys and their metadata
keys = []

def generate_rsa_key():
    # Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()  # Derive the public key from the private key
    
    # Create a key entry with metadata
    key_entry = {
        'kid': str(uuid.uuid4()),  # Generate a unique Key ID (KID)
        'key': private_key,  # Store the private key for signing
        'public_key_pem': public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'),  # Serialize public key to PEM format
        'exp': time.time() + 3600  # Set expiration time (1 hour from now)
    }
    keys.append(key_entry)  # Add the key entry to the global list
    return key_entry  # Return the generated key entry

# Generate an initial RSA key at startup
generate_rsa_key()

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    # Construct a list of unexpired keys for the JWKS endpoint
    unexpired_keys = [
        {
            'kid': key['kid'],  # Key ID
            'kty': 'RSA',  # Key type
            'use': 'sig',  # Key usage (signature)
            'n': key['public_key_pem'].split('-----BEGIN PUBLIC KEY-----')[1].split('-----END PUBLIC KEY-----')[0],  # Base64-encoded modulus
            'e': 'AQAB'  # This assumes the public exponent is always 65537 (0x10001)
        }
        for key in keys if key['exp'] > time.time()  # Filter for unexpired keys
    ]
    return jsonify({'keys': unexpired_keys}), 200  # Return the keys in JSON format

@app.route('/auth', methods=['POST'])
def auth():
    # Check if the request wants an expired key
    expired = request.args.get('expired', 'false').lower() == 'true'
    
    if expired:
        # Find an expired key if requested
        expired_key = next((key for key in keys if key['exp'] < time.time()), None)
        if not expired_key:
            return jsonify({'error': 'No expired key available'}), 400  # Return error if no expired key is found
        private_key = expired_key['key']  # Use the private key from the expired key
        expiry_time = datetime.now(timezone.utc) - timedelta(minutes=30)  # Set an expired expiry time
        kid = expired_key['kid']  # Use the KID from the expired key
    else:
        # Generate a new RSA key for valid authentication
        key_entry = generate_rsa_key()
        private_key = key_entry['key']  # Get the private key from the new key entry
        expiry_time = datetime.now(timezone.utc) + timedelta(minutes=30)  # Set valid expiry time
        kid = key_entry['kid']  # Get the KID from the new key

    # Create the payload for the JWT
    payload = {
        'sub': '1234567890',  # Subject (user identifier)
        'name': 'John Doe',  # Name claim
        'iat': datetime.now(timezone.utc),  # Issued at timestamp
        'exp': expiry_time  # Expiration time for the token
    }

    # Encode the JWT using the private key
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': kid})
    return jsonify({'token': token}), 200  # Return the JWT in the response

# Run the application on port 8080
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)
