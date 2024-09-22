# JWKS Server

## Overview
This project implements a RESTful JWKS server that provides public keys with unique identifiers (kid) for verifying JSON Web Tokens (JWTs). It includes key expiry for enhanced security and handles the issuance of JWTs with expired keys based on a query parameter.

## Endpoints
- `/.well-known/jwks.json`: Serves public keys in JWKS format.
- `/auth`: Returns a signed JWT on a POST request.

## Requirements
- Python 3.8+
- Flask
- cryptography
- PyJWT
- pytest
- requests

## Setup
1. Create a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3. Runt the key generation:
    ```bash
    python3 key_management.py
    ```

4. Run the server:
    ```bash
    python3 app.py
    ```

## Testing Coverage
Run the test suite using pytest:
 Before running your tests, make sure your terminal is in the jwks_server directory
```bash
pip install --upgrade pytest pytest-cov
export PYTHONPATH=$(pwd)
pytest --cov=app tests/
```
## Testing
```bash
pytest -W ignore tests/test_app.py
```

