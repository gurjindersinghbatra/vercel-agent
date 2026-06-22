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
_patched = False
_proxy_pool = None

import threading
import contextlib
_local = threading.local()

@contextlib.contextmanager
def bypass_interceptor():
    old = getattr(_local, "in_interceptor", False)
    _local.in_interceptor = True
    try:
        yield
    finally:
        _local.in_interceptor = old


def init(task: str, delegation_token: str = None, env_var: str = None, daemon_url: str = "http://localhost:18787", is_serverless: bool = None, oidc_token: str = None):
    """
    Registers the active agent task session.
    In standard mode: Contacts the local sidecar daemon.
    In serverless mode (default on Vercel): Performs direct handshake with the Edge Worker.
    """
    global _mission_token, _session_key, _public_jwk, _worker_host, _fido_id, _is_serverless

    if is_serverless is None:
        is_serverless = os.getenv("VERCEL") == "1"

    _is_serverless = is_serverless

    if not is_serverless:
        # 1. Resolve delegation token
        if env_var:
            delegation_token = os.getenv(env_var)
            if not delegation_token:
                raise ValueError(f"Environment variable '{env_var}' is empty or not set.")
        elif not delegation_token:
            delegation_token = os.getenv("INDRA_DELEGATION_TOKEN")
            
        if not delegation_token:
            raise ValueError("INDRA_DELEGATION_TOKEN must be provided or set as an environment variable.")

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

        # Check for passwordless Vercel OIDC token
        if not oidc_token:
            oidc_token = os.getenv("VERCEL_OIDC_TOKEN")
        if oidc_token:
            del_token = os.getenv(env_var or "INDRA_DELEGATION_TOKEN")
            if not del_token:
                raise ValueError(f"Environment variable '{env_var or 'INDRA_DELEGATION_TOKEN'}' is empty or not set. Delegation token is required.")
            # Parse token payload to resolve project ID
            try:
                parts = oidc_token.split('.')
                payload_part = parts[1]
                payload_part += '=' * (-len(payload_part) % 4)
                jwt_payload = json.loads(base64.urlsafe_b64decode(payload_part).decode('utf-8'))
                project_id = jwt_payload.get("project_id") or jwt_payload.get("projectId") or jwt_payload.get("project") or ""
            except Exception:
                project_id = ""
            
            # For serverless OIDC, the edge handles validation via the token and creates a workload derived identity
            _fido_id = f"workload_vercel_{project_id}"
            
            payload = {
                "fidoKey": "",
                "mission": task,
                "templateId": "default_agent_mission",
                "idToken": oidc_token,
                "delegationToken": del_token,
                "publicJwk": public_jwk,
                "signature": ""
            }
        else:
            # Fallback to key-based serverless mode
            if env_var:
                delegation_token = os.getenv(env_var)
                if not delegation_token:
                    raise ValueError(f"Environment variable '{env_var}' is empty or not set.")
            elif not delegation_token:
                delegation_token = os.getenv("INDRA_DELEGATION_TOKEN")
                
            if not delegation_token:
                raise ValueError("INDRA_DELEGATION_TOKEN must be provided or set as an environment variable in key-based serverless mode.")

            private_key_pem = os.getenv("INDRA_ANCHOR_KEY_PEM")
            if not private_key_pem:
                raise ValueError("INDRA_ANCHOR_KEY_PEM must be set in key-based serverless mode.")

            # Load the trust anchor RSA key
            try:
                rsa_private_key = serialization.load_pem_private_key(
                    private_key_pem.encode('utf-8'),
                    password=None
                )
            except Exception as e:
                raise ValueError(f"Failed to parse INDRA_ANCHOR_KEY_PEM: {e}")

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
                    _patch_http_clients()
                else:
                    raise RuntimeError(f"Handshake failed: {body}")
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8')
            raise RuntimeError(f"Handshake denied by Edge: HTTP {e.code} {e.reason} - Body: {body}")
        except Exception as e:
            raise RuntimeError(f"Failed direct handshake with Edge Worker at {url}: {e}")

def _prepare_proxied_request(method: str, url: str, headers: dict = None):
    """
    Generates proxy URL and signs the request headers (DPoP, mission token, etc.).
    Returns (proxy_url, updated_headers).
    """
    global _mission_token, _session_key, _public_jwk, _worker_host, _fido_id

    if not _mission_token:
        raise RuntimeError("Indra SDK: Session not initialized. Call init() first.")

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    if headers is None:
        headers = {}
    else:
        headers = dict(headers)

    # Set User-Agent if not already present to prevent Cloudflare BIC blocks
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

    return proxy_url, headers


def request(method: str, url: str, headers: dict = None, data: bytes = None, **kwargs):
    """
    Routes an outbound HTTP request transparently through the Indra Edge Proxy (Serverless Mode).
    Attaches the required X-Indra-Mission-Token, X-Indra-Source-Machine, and signed DPoP proof.
    """
    global _is_serverless

    if not _is_serverless:
        # Standard mode redirects to loopback proxy without adding headers manually
        raise RuntimeError("Indra SDK: request() is only supported in Serverless/PaaS mode. In standard mode, use standard HTTP libraries with proxy environment variables.")

    proxy_url, proxy_headers = _prepare_proxied_request(method, url, headers)

    with bypass_interceptor():
        req = urllib.request.Request(proxy_url, data=data, headers=proxy_headers, method=method.upper())
        return urllib.request.urlopen(req, **kwargs)


def _is_indra_host(url_str):
    global _worker_host
    if not _worker_host:
        return False
    worker_clean = _worker_host.replace("http://", "").replace("https://", "").split(":")[0].lower()
    return worker_clean in url_str.lower()


def _patch_http_clients():
    global _patched
    if _patched:
        return
    _patched = True

    # --- 1. urllib.request.urlopen Patch ---
    import urllib.request
    import socket
    original_urlopen = urllib.request.urlopen

    def patched_urlopen(url, data=None, *args, **kwargs):
        if not _is_serverless or getattr(_local, "in_interceptor", False):
            return original_urlopen(url, data=data, *args, **kwargs)

        import urllib.request
        url_str = url.full_url if isinstance(url, urllib.request.Request) else url
        if _is_indra_host(url_str):
            return original_urlopen(url, data=data, *args, **kwargs)

        if isinstance(url, urllib.request.Request):
            original_url = url.full_url
            method = url.get_method()
            headers = {k: v for k, v in url.header_items()}
            # Construct DPoP and proxy URL
            proxy_url, proxy_headers = _prepare_proxied_request(method, original_url, headers)
            # Create a new Request object
            new_req = urllib.request.Request(
                proxy_url,
                data=url.data,
                headers=proxy_headers,
                origin_req_host=url.origin_req_host,
                unverifiable=url.unverifiable,
                method=method
            )
            with bypass_interceptor():
                return original_urlopen(new_req, data=None, *args, **kwargs)
        else:
            # url is a string
            method = "POST" if data is not None else "GET"
            proxy_url, proxy_headers = _prepare_proxied_request(method, url, {})
            new_req = urllib.request.Request(proxy_url, data=data, headers=proxy_headers, method=method)
            with bypass_interceptor():
                return original_urlopen(new_req, data=None, *args, **kwargs)

    urllib.request.urlopen = patched_urlopen

    # --- 2. urllib3 ConnectionPool.urlopen Patch ---
    try:
        import urllib3.connectionpool
        original_urllib3_urlopen = urllib3.connectionpool.HTTPConnectionPool.urlopen

        def patched_urllib3_urlopen(self, method, url, body=None, headers=None, **kwargs):
            if not _is_serverless or getattr(_local, "in_interceptor", False):
                return original_urllib3_urlopen(self, method, url, body=body, headers=headers, **kwargs)

            # Reconstruct original URL
            scheme = self.scheme
            host = self.host
            port = self.port
            
            # Bypass if self.host is worker host
            if _is_indra_host(host):
                return original_urllib3_urlopen(self, method, url, body=body, headers=headers, **kwargs)

            # Reconstruct full URL
            if url.startswith("http://") or url.startswith("https://"):
                original_url = url
            else:
                port_part = ""
                if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
                    if port is not None:
                        port_part = f":{port}"
                original_url = f"{scheme}://{host}{port_part}{url}"

            # Bypass if full URL is worker host
            if _is_indra_host(original_url):
                return original_urllib3_urlopen(self, method, url, body=body, headers=headers, **kwargs)

            # Prepare proxied request headers and URL
            proxy_url, proxy_headers = _prepare_proxied_request(method, original_url, headers)

            # Delegate to connection pool of _worker_host
            import urllib.parse
            parsed_proxy = urllib.parse.urlparse(proxy_url)
            proxy_scheme = parsed_proxy.scheme
            proxy_netloc = parsed_proxy.netloc
            proxy_path = parsed_proxy.path
            if parsed_proxy.query:
                proxy_path += f"?{parsed_proxy.query}"

            # Retrieve connection pool for the proxy
            global _proxy_pool
            if _proxy_pool is None:
                _proxy_pool = urllib3.connection_from_url(f"{proxy_scheme}://{proxy_netloc}")
            proxy_pool = _proxy_pool

            with bypass_interceptor():
                return original_urllib3_urlopen(proxy_pool, method, proxy_path, body=body, headers=proxy_headers, **kwargs)

        urllib3.connectionpool.HTTPConnectionPool.urlopen = patched_urllib3_urlopen
    except ImportError:
        pass

    # --- 3. httpx Patch ---
    try:
        import httpx
        original_httpx_send = httpx.Client.send
        original_httpx_async_send = httpx.AsyncClient.send

        def patched_httpx_send(self, request, **kwargs):
            if not _is_serverless or getattr(_local, "in_interceptor", False):
                return original_httpx_send(self, request, **kwargs)

            original_url = str(request.url)
            if _is_indra_host(original_url):
                return original_httpx_send(self, request, **kwargs)

            method = request.method
            headers = dict(request.headers)

            proxy_url, proxy_headers = _prepare_proxied_request(method, original_url, headers)

            # Mutate request object to point to proxy
            request.url = httpx.URL(proxy_url)
            request.headers.clear()
            for k, v in proxy_headers.items():
                request.headers[k] = v

            with bypass_interceptor():
                return original_httpx_send(self, request, **kwargs)

        async def patched_httpx_async_send(self, request, **kwargs):
            if not _is_serverless or getattr(_local, "in_interceptor", False):
                return await original_httpx_async_send(self, request, **kwargs)

            original_url = str(request.url)
            if _is_indra_host(original_url):
                return await original_httpx_async_send(self, request, **kwargs)

            method = request.method
            headers = dict(request.headers)

            proxy_url, proxy_headers = _prepare_proxied_request(method, original_url, headers)

            request.url = httpx.URL(proxy_url)
            request.headers.clear()
            for k, v in proxy_headers.items():
                request.headers[k] = v

            with bypass_interceptor():
                return await original_httpx_async_send(self, request, **kwargs)

        httpx.Client.send = patched_httpx_send
        httpx.AsyncClient.send = patched_httpx_async_send
    except ImportError:
        pass


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
            with bypass_interceptor():
                with urllib.request.urlopen(req) as response:
                    if response.status == 200:
                        print(f"[*] Indra SDK: Ephemeral session terminated successfully on the Edge.")
                        _mission_token = None
                    else:
                        print(f"[!] Indra SDK: Session termination returned status {response.status}")
        except Exception as e:
            print(f"[!] Indra SDK: Ephemeral session termination failed: {e}")

