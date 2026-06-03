import os
import urllib.request
import urllib.parse
import urllib.error
import json
import base64
import time
import uuid

# Global SDK state for serverless mode
_mission_token = None
_session_key = None
_public_jwk = None
_worker_host = None
_fido_id = None
_is_serverless = False

def init(task: str, delegation_token: str = None, env_var: str = None, daemon_url: str = "http://localhost:18787", is_serverless: bool = None):
    """
    Registers the active agent task session.
    In standard mode: Contacts the local sidecar daemon.
    In serverless mode (default on Vercel): Performs direct handshake with the Edge Worker.
    """
    global _mission_token, _session_key, _public_jwk, _worker_host, _fido_id, _is_serverless

    if is_serverless is None:
        is_serverless = os.getenv("VERCEL") == "1"

    _is_serverless = is_serverless

    # 1. Resolve delegation token
    if env_var:
        delegation_token = os.getenv(env_var)
        if not delegation_token:
            raise ValueError(f"Environment variable '{env_var}' is empty or not set.")
    elif not delegation_token:
        delegation_token = os.getenv("INDRA_DELEGATION_TOKEN")
        
    if not delegation_token:
        raise ValueError("INDRA_DELEGATION_TOKEN must be provided or set as an environment variable.")

    if not is_serverless:
        # Standard sidecar/daemon registration
        pid = os.getpid()
        params = {
            "pid": str(pid),
            "task": task,
            "idToken": delegation_token
        }
        query_string = urllib.parse.urlencode(params)
        url = f"{daemon_url.rstrip('/')}/register-agent-session?{query_string}"
        
        try:
            req = urllib.request.Request(url, method="POST")
            with urllib.request.urlopen(req) as response:
                status = response.status
                body = response.read().decode('utf-8')
                if status == 200:
                    print(f"[*] Indra SDK: Registered session for PID {pid} (Task: '{task}')")
                else:
                    raise RuntimeError(f"Registration failed with status {status}: {body}")
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8')
            raise RuntimeError(f"Failed to connect to Indra Sidecar: HTTP {e.code} {e.reason} - Body: {body}")
        except Exception as e:
            raise RuntimeError(f"Failed to connect to Indra Sidecar at {daemon_url}: {e}")
    else:
        # Serverless direct handshake with Edge Worker
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import padding, ec

        worker_host = os.getenv("INDRA_WORKER_HOST") or "indra-edge-platform.dan-hollinger.workers.dev"
        _worker_host = worker_host

        private_key_pem = os.getenv("INDRA_ANCHOR_KEY_PEM")
        if not private_key_pem:
            raise ValueError("INDRA_ANCHOR_KEY_PEM must be set in serverless mode.")

        # Load the trust anchor RSA key
        try:
            rsa_private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None
            )
        except Exception as e:
            raise ValueError(f"Failed to parse INDRA_ANCHOR_KEY_PEM: {e}")

        # Generate ephemeral EC P-256 session key
        ec_private_key = ec.generate_private_key(ec.SECP256R1())
        ec_public_key = ec_private_key.public_key()

        # Build public JWK
        numbers = ec_public_key.public_numbers()
        x_bytes = numbers.x.to_bytes(32, byteorder='big')
        y_bytes = numbers.y.to_bytes(32, byteorder='big')
        x_b64 = base64.urlsafe_b64encode(x_bytes).decode('utf-8').rstrip('=')
        y_b64 = base64.urlsafe_b64encode(y_bytes).decode('utf-8').rstrip('=')
        public_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64
        }
        _public_jwk = public_jwk
        _session_key = ec_private_key

        # Derive FIDO ID from RSA public key DER bytes
        pub_bytes = rsa_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashes.Hash(hashes.SHA256())
        digest.update(pub_bytes)
        hash_bytes = digest.finalize()
        fido_id = f"indra_fido_{hash_bytes[:8].hex()}"
        _fido_id = fido_id

        # Sign handshake payload: missionName|fidoID|idToken|publicJwk
        jwk_bytes = json.dumps(public_jwk, separators=(',', ':')).encode('utf-8')
        data_to_sign = f"{task}|{fido_id}|{delegation_token}|{jwk_bytes.decode('utf-8')}".encode('utf-8')

        signature = rsa_private_key.sign(
            data_to_sign,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Execute direct handshake call
        payload = {
            "fidoKey": base64.b64encode(pub_bytes).decode('utf-8'),
            "mission": task,
            "templateId": "default_agent_mission",
            "idToken": delegation_token,
            "publicJwk": public_jwk,
            "signature": base64.b64encode(signature).decode('utf-8')
        }

        url = f"https://{worker_host}/api/mission/start"
        if worker_host.startswith("localhost:") or worker_host.startswith("127.0.0.1:"):
            url = f"http://{worker_host}/api/mission/start"

        req_body = json.dumps(payload).encode('utf-8')
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }
        
        try:
            req = urllib.request.Request(url, data=req_body, headers=headers, method="POST")
            with urllib.request.urlopen(req) as response:
                body = response.read().decode('utf-8')
                result = json.loads(body)
                if response.status == 200 and result.get("success"):
                    _mission_token = result.get("missionToken")
                    print(f"[*] Indra SDK: Direct Edge handshake successful! Mission Token: {_mission_token[:8]}...")
                else:
                    raise RuntimeError(f"Handshake failed: {body}")
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8')
            raise RuntimeError(f"Handshake denied by Edge: HTTP {e.code} {e.reason} - Body: {body}")
        except Exception as e:
            raise RuntimeError(f"Failed direct handshake with Edge Worker at {url}: {e}")

def request(method: str, url: str, headers: dict = None, data: bytes = None, **kwargs):
    """
    Routes an outbound HTTP request transparently through the Indra Edge Proxy (Serverless Mode).
    Attaches the required X-Indra-Mission-Token, X-Indra-Source-Machine, and signed DPoP proof.
    """
    global _mission_token, _session_key, _public_jwk, _worker_host, _fido_id, _is_serverless

    if not _is_serverless:
        # Standard mode redirects to loopback proxy without adding headers manually
        raise RuntimeError("Indra SDK: request() is only supported in Serverless/PaaS mode. In standard mode, use standard HTTP libraries with proxy environment variables.")

    if not _mission_token:
        raise RuntimeError("Indra SDK: Session not initialized. Call init() first.")

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    if headers is None:
        headers = {}
    else:
        headers = dict(headers)

    # Set User-Agent if not already present to prevent Cloudflare BIC blocks (Error 1010)
    has_user_agent = False
    for k in headers.keys():
        if k.lower() == 'user-agent':
            has_user_agent = True
            break
    if not has_user_agent:
        headers['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

    # 1. Generate DPoP JWT Proof
    dpop_header = {
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": _public_jwk
    }
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(dpop_header, separators=(',', ':')).encode('utf-8')
    ).decode('utf-8').rstrip('=')

    dpop_payload = {
        "jti": str(uuid.uuid4()),
        "htm": method.upper(),
        "htu": url,
        "iat": int(time.time())
    }
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(dpop_payload, separators=(',', ':')).encode('utf-8')
    ).decode('utf-8').rstrip('=')

    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')

    # Sign using ECDSA (SHA-256)
    signature_der = _session_key.sign(
        signing_input,
        ec.ECDSA(hashes.SHA256())
    )

    # Decode ASN.1 DER to raw r || s (64 bytes)
    r, s = decode_dss_signature(signature_der)
    raw_signature = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
    signature_b64 = base64.urlsafe_b64encode(raw_signature).decode('utf-8').rstrip('=')

    dpop_jwt = f"{header_b64}.{payload_b64}.{signature_b64}"

    # 2. Inject headers
    headers['X-Indra-Mission-Token'] = _mission_token
    headers['X-Indra-Source-Machine'] = _fido_id
    headers['DPoP'] = dpop_jwt

    # 3. Route via Edge Worker proxy path
    proxy_url = f"https://{_worker_host}/proxy/{url}"
    if _worker_host.startswith("localhost:") or _worker_host.startswith("127.0.0.1:"):
        proxy_url = f"http://{_worker_host}/proxy/{url}"

    req = urllib.request.Request(proxy_url, data=data, headers=headers, method=method.upper())
    return urllib.request.urlopen(req, **kwargs)

def close(daemon_url: str = "http://localhost:18787"):
    """
    Terminates the active agent session.
    In standard mode: Deregisters from the local sidecar.
    In serverless mode: Sends a signed revocation request directly to the Edge Worker.
    """
    global _mission_token, _session_key, _public_jwk, _worker_host, _fido_id, _is_serverless

    if not _is_serverless:
        pid = os.getpid()
        url = f"{daemon_url.rstrip('/')}/unregister-agent-session?pid={pid}"
        try:
            req = urllib.request.Request(url, method="POST")
            with urllib.request.urlopen(req) as response:
                if response.status == 200:
                    print(f"[*] Indra SDK: Unregistered session for PID {pid}")
                else:
                    print(f"[!] Indra SDK: Unregistration failed: {response.read().decode('utf-8')}")
        except Exception as e:
            print(f"[!] Indra SDK: Failed to connect to sidecar for unregistration: {e}")
    else:
        if not _mission_token:
            return

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        method = "POST"
        url = f"https://{_worker_host}/api/mission/stop"
        if _worker_host.startswith("localhost:") or _worker_host.startswith("127.0.0.1:"):
            url = f"http://{_worker_host}/api/mission/stop"

        dpop_header = {
            "alg": "ES256",
            "typ": "dpop+jwt",
            "jwk": _public_jwk
        }
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(dpop_header, separators=(',', ':')).encode('utf-8')
        ).decode('utf-8').rstrip('=')

        dpop_payload = {
            "jti": str(uuid.uuid4()),
            "htm": method,
            "htu": url,
            "iat": int(time.time())
        }
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(dpop_payload, separators=(',', ':')).encode('utf-8')
        ).decode('utf-8').rstrip('=')

        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')

        signature_der = _session_key.sign(
            signing_input,
            ec.ECDSA(hashes.SHA256())
        )

        r, s = decode_dss_signature(signature_der)
        raw_signature = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
        signature_b64 = base64.urlsafe_b64encode(raw_signature).decode('utf-8').rstrip('=')

        dpop_jwt = f"{header_b64}.{payload_b64}.{signature_b64}"

        headers = {
            "X-Indra-Mission-Token": _mission_token,
            "X-Indra-Source-Machine": _fido_id,
            "DPoP": dpop_jwt,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }

        try:
            req = urllib.request.Request(url, headers=headers, method=method)
            with urllib.request.urlopen(req) as response:
                if response.status == 200:
                    print(f"[*] Indra SDK: Ephemeral session terminated successfully on the Edge.")
                    _mission_token = None
                else:
                    print(f"[!] Indra SDK: Session termination returned status {response.status}")
        except Exception as e:
            print(f"[!] Indra SDK: Ephemeral session termination failed: {e}")

