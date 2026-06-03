import json
import os
import sys
import urllib.error
from flask import Flask, jsonify

# Add parent directory to sys.path so we can import indra_sdk
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import indra_sdk

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
    <head>
        <title>Indra Vercel Agent</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: #0f172a; color: white; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
            .card { background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.05); padding: 40px; border-radius: 16px; text-align: center; max-width: 400px; width: 100%; box-sizing: border-box; }
            h1 { color: #818cf8; margin-top: 0; font-size: 1.8rem; }
            p { color: #94a3b8; font-size: 0.95rem; line-height: 1.5; margin-bottom: 24px; }
            a { display: inline-block; background: #818cf8; color: white; text-decoration: none; padding: 12px 24px; border-radius: 8px; font-weight: bold; transition: background 0.2s; font-size: 0.9rem; }
            a:hover { background: #6366f1; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Indra Agent</h1>
            <p>The Vercel serverless agent is ready. Click below to run the agent mission securely via the Edge Worker.</p>
            <a href="/api/agent">Run Agent Mission</a>
        </div>
    </body>
    </html>
    """

@app.route('/api/agent', methods=['GET', 'POST'])
def run_agent():
    try:
        # 1. Initialize Indra SDK in serverless mode
        # It automatically resolves:
        # - INDRA_DELEGATION_TOKEN from env
        # - INDRA_ANCHOR_KEY_PEM from env
        # - INDRA_WORKER_HOST from env
        # - VERCEL=1 from env (which triggers is_serverless=True)
        indra_sdk.init(
            task="Vercel Agent Stripe Audit",
            is_serverless=True
        )

        # 2. Make outbound proxy requests using the SDK
        url = "https://api.stripe.com/v1/charges"
        print(f"[AGENT] Executing secure proxy request to {url}")
        
        response = indra_sdk.request("GET", url)
        status_code = response.status
        body = response.read().decode('utf-8')

        try:
            data = json.loads(body)
        except:
            data = body

        return jsonify({
            'success': status_code == 200,
            'status': status_code,
            'data': data
        }), status_code

    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        try:
            body = json.loads(body)
        except:
            pass
        return jsonify({
            'success': False,
            'error': f"HTTP {e.code}: {e.reason}",
            'body': body
        }), e.code
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[AGENT-ERROR] {error_trace}")
        return jsonify({
            'success': False,
            'error': str(e),
            'trace': error_trace
        }), 500
    finally:
        try:
            indra_sdk.close()
        except Exception as close_err:
            print(f"[AGENT-ERROR] Failed to close agent session: {close_err}")
