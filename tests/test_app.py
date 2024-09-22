import pytest
import uuid
import time
from datetime import datetime, timezone
import jwt  # Import the JWT library for decoding tokens

from app import app, keys, generate_rsa_key  # Import your app and key management functions

@pytest.fixture
def client():
    # Set up the test client for the Flask application
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_jwks_endpoint(client):
    # Generate keys for testing
    generate_rsa_key()
    
    # Request the JWKS endpoint
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200  # Ensure the request is successful
    jwks_keys = response.get_json().get('keys')
    
    # Ensure there is at least one key returned
    assert len(jwks_keys) > 0

def test_auth_with_valid_key(client):
    # Test authentication with a valid key
    response = client.post('/auth')
    assert response.status_code == 200  # Check for successful response
    token = response.get_json().get('token')
    assert token is not None  # Ensure a valid JWT is returned

def test_auth_with_expired_key(client):
    # Generate a valid RSA key
    valid_key = generate_rsa_key()
    keys.append(valid_key)  # Store the valid key

    # Create an expired key
    expired_key = {
        'kid': str(uuid.uuid4()),  # Unique key ID
        'key': valid_key['key'],
        'public_key_pem': valid_key['public_key_pem'],
        'exp': time.time() - 3600  # Set expiration time in the past
    }
    keys.append(expired_key)  # Store the expired key

    # Request a token with the expired key
    response = client.post('/auth?expired=true')
    assert response.status_code == 200  # Expect successful response
    token = response.get_json().get('token')
    assert token is not None  # Ensure a valid JWT is returned

    # Check that the token is expired when we try to decode it
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, expired_key['public_key_pem'], algorithms=['RS256'])

def test_auth_with_no_expired_key(client):
    keys.clear()  # Clear the keys list to ensure it's empty

    # Attempt to issue a JWT using an expired key when none exists
    response = client.post('/auth?expired=true')
    assert response.status_code == 400  # Expect a bad request response
    error_message = response.get_json().get('error')
    assert error_message == 'No expired key available'  # Check error message

def test_auth_without_body(client):
    # Attempt to authenticate without providing a request body
    response = client.post('/auth')
    
    # Check the response status code and content
    assert response.status_code == 200  # Expecting a successful response
    token = response.get_json().get('token')
    assert token is not None  # Ensure a valid JWT is returned

def test_successful_authentication(client):
    # Test a successful authentication with user credentials
    response = client.post('/auth', json={"username": "testuser", "password": "testpass"})
    assert response.status_code == 200  # Check for successful response
    assert "token" in response.get_json()  # Ensure token is returned

def test_jwt_issued_on_successful_auth(client):
    # Test that a valid JWT is issued upon successful authentication
    response = client.post('/auth', json={"username": "testuser", "password": "testpass"})
    token = response.get_json()["token"]
    
    # Decode the token to check its claims
    decoded_payload = jwt.decode(token, options={"verify_signature": False})  # Not verifying the signature here for simplicity
    assert "exp" in decoded_payload  # Ensure expiration claim exists
    assert "iat" in decoded_payload  # Ensure issued-at claim exists

def test_no_expired_key_available(client):
    # Attempt to issue a JWT with no expired keys available
    response = client.post('/auth?expired=true')
    assert response.status_code == 400  # Expect a bad request response
    assert response.get_json()["error"] == "No expired key available"  # Check error message

if __name__ == '__main__':
    pytest.main()  # Run the tests if this script is executed
