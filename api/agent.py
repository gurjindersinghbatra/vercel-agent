import json
import os
import sys
from flask import Flask, jsonify

# Add parent directory to sys.path so we can import indra_sdk
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import indra_sdk

app = Flask(__name__)

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

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[AGENT-ERROR] {error_trace}")
        return jsonify({
            'success': False,
            'error': str(e),
            'trace': error_trace
        }), 500
