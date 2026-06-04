import json
import os
import sys
import urllib.request
import urllib.error
from flask import Flask, jsonify, request as flask_request

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
    prompt = flask_request.values.get("prompt", "Make stripe charges of $100")
    logs = []
    
    try:
        # 1. Initialize Indra SDK in serverless mode
        # It automatically resolves:
        # - INDRA_DELEGATION_TOKEN from env
        # - INDRA_ANCHOR_KEY_PEM from env
        # - INDRA_WORKER_HOST from env
        # - VERCEL=1 from env (which triggers is_serverless=True)
        indra_sdk.init(
            task=f"Stripe Charge Agent: {prompt}",
            is_serverless=True
        )
        logs.append("[Indra] Session initialized securely on the Edge.")

        openai_key = os.getenv("OPENAI_API_KEY")
        stripe_key = os.getenv("STRIPE_API_KEY") or "sk_test_mock_stripe_key"

        tool_call_args = None

        # 2. Call the LLM (OpenAI) to parse the request
        if openai_key:
            logs.append("[LLM] Prompting OpenAI GPT-4o via Indra Edge Proxy...")
            headers = {
                "Authorization": f"Bearer {openai_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": prompt}],
                "tools": [{
                    "type": "function",
                    "function": {
                        "name": "create_stripe_charge",
                        "description": "Create a Stripe charge for a specific amount in USD",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "amount": {"type": "number"}
                            },
                            "required": ["amount"]
                        }
                    }
                }]
            }
            
            # This outbound request to OpenAI is transparently proxy-routed and governed by Indra
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                data=json.dumps(payload).encode('utf-8'),
                method="POST"
            )
            with urllib.request.urlopen(req) as resp:
                if resp.status == 200:
                    result = json.loads(resp.read().decode('utf-8'))
                    tool_calls = result["choices"][0]["message"].get("tool_calls")
                    if tool_calls:
                        for tc in tool_calls:
                            if tc["function"]["name"] == "create_stripe_charge":
                                tool_call_args = json.loads(tc["function"]["arguments"])
                                logs.append(f"[LLM] OpenAI returned tool call: create_stripe_charge with args: {tool_call_args}")
                    else:
                        logs.append(f"[LLM] Response: {result['choices'][0]['message']['content']}")
                else:
                    logs.append(f"[Error] OpenAI call failed: {resp.status}")
        else:
            # Mock LLM parsing fallback if no OpenAI API key is configured
            logs.append("[LLM] (Mock Mode) No OPENAI_API_KEY found. Simulating LLM tool-calling response...")
            if "charge" in prompt.lower() and "100" in prompt.lower():
                tool_call_args = {"amount": 100}
                logs.append(f"[LLM] Simulated tool call: create_stripe_charge with args: {tool_call_args}")

        # 3. Execute the Stripe charge if the tool call was triggered
        charge_result = None
        if tool_call_args:
            amount = tool_call_args.get("amount", 100)
            logs.append(f"[Stripe] Initiating Stripe charge of ${amount} via Indra Edge Proxy...")

            headers = {
                "Authorization": f"Bearer {stripe_key}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            # Form-encode the payload for Stripe's API
            payload = {
                "amount": int(amount * 100), # cents
                "currency": "usd",
                "source": "tok_visa"
            }
            
            # This call to Stripe is audited, logged, and matched against OPA policy on the Edge.
            # If the user's Delegation Token does not grant `stripe:write` permission, 
            # the Edge Platform will block the request and return a 403 Forbidden.
            req = urllib.request.Request(
                "https://api.stripe.com/v1/charges",
                headers=headers,
                data=urllib.parse.urlencode(payload).encode('utf-8'),
                method="POST"
            )
            with urllib.request.urlopen(req) as resp:
                status = resp.status
                body = resp.read().decode('utf-8')
            
            if status == 200:
                charge_result = json.loads(body)
                logs.append(f"[Stripe] Success! Charge created: {charge_result.get('id')}")
            else:
                logs.append(f"[Error] Stripe request returned status {status}: {body}")
        else:
            logs.append("[Stripe] No Stripe charge requested by the LLM.")

        return jsonify({
            'success': True,
            'prompt': prompt,
            'logs': logs,
            'charge': charge_result
        })

    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        try:
            body = json.loads(body)
        except:
            pass
        logs.append(f"[Error] HTTP {e.code}: {e.reason}")
        return jsonify({
            'success': False,
            'logs': logs,
            'error': f"HTTP {e.code}: {e.reason}",
            'body': body
        }), e.code
    except Exception as e:
        logs.append(f"[Error] Exception: {str(e)}")
        return jsonify({
            'success': False,
            'logs': logs,
            'error': str(e)
        })
    finally:
        try:
            indra_sdk.close()
            logs.append("[Indra] Session securely closed.")
        except Exception as close_err:
            print(f"[AGENT-ERROR] Failed to close agent session: {close_err}")
