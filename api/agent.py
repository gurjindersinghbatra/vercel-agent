import json
import os
import sys
import urllib.request
import urllib.error
import urllib.parse
from flask import Flask, jsonify, request as flask_request

# Add parent directory to sys.path so we can import indra_sdk
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import indra_sdk

app = Flask(__name__)

@app.route('/')
def index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Indra Agent Security Governance Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-main: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.75);
            --card-border: rgba(255, 255, 255, 0.08);
            --accent-indigo: #6366f1;
            --accent-emerald: #10b981;
            --accent-rose: #f43f5e;
            --accent-amber: #f59e0b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-main);
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(244, 63, 94, 0.1) 0px, transparent 50%),
                radial-gradient(at 50% 50%, rgba(16, 185, 129, 0.05) 0px, transparent 50%);
            color: var(--text-primary);
            margin: 0;
            padding: 40px 20px;
            min-height: 100vh;
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .container {
            max-width: 1000px;
            width: 100%;
        }

        header {
            text-align: center;
            margin-bottom: 40px;
        }

        .logo-badge {
            display: inline-flex;
            align-items: center;
            background: linear-gradient(135deg, var(--accent-indigo), #4f46e5);
            color: white;
            padding: 6px 16px;
            border-radius: 9999px;
            font-weight: 600;
            font-size: 0.85rem;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            box-shadow: 0 4px 20px rgba(99, 102, 241, 0.4);
            margin-bottom: 16px;
        }

        h1 {
            font-size: 2.2rem;
            font-weight: 700;
            margin: 0 0 8px 0;
            background: linear-gradient(to right, #ffffff, #cbd5e1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .subtitle {
            color: var(--text-secondary);
            font-size: 1.05rem;
            max-width: 600px;
            margin: 0 auto;
            line-height: 1.6;
        }

        /* Token Info Panel */
        .info-panel {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 16px 24px;
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            backdrop-filter: blur(12px);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
        }

        .info-left {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .info-icon {
            width: 8px;
            height: 8px;
            background-color: var(--accent-emerald);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--accent-emerald);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        .info-title {
            font-weight: 600;
            font-size: 0.95rem;
        }

        .info-scopes {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 4px 10px;
            border-radius: 6px;
            font-family: 'Fira Code', monospace;
            font-size: 0.8rem;
            color: #a5b4fc;
        }

        /* Grid for Tests */
        .test-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 24px;
            margin-bottom: 30px;
        }

        @media (max-width: 992px) {
            .test-grid {
                grid-template-columns: 1fr;
            }
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 30px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            position: relative;
            overflow: hidden;
            backdrop-filter: blur(12px);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }

        .card:hover {
            transform: translateY(-2px);
            border-color: rgba(255, 255, 255, 0.15);
        }

        .card.positive {
            border-top: 4px solid var(--accent-emerald);
        }

        .card.negative {
            border-top: 4px solid var(--accent-rose);
        }

        .card-header {
            margin-bottom: 20px;
        }

        .card-tag {
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 4px 8px;
            border-radius: 4px;
            display: inline-block;
            margin-bottom: 12px;
        }

        .card.positive .card-tag {
            background: rgba(16, 185, 129, 0.1);
            color: var(--accent-emerald);
        }

        .card.negative .card-tag {
            background: rgba(244, 63, 94, 0.1);
            color: var(--accent-rose);
        }

        .card-title {
            font-size: 1.3rem;
            font-weight: 600;
            margin: 0 0 10px 0;
        }

        .card-desc {
            color: var(--text-secondary);
            font-size: 0.9rem;
            line-height: 1.5;
            margin-bottom: 20px;
        }

        .task-spec {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 24px;
            font-size: 0.85rem;
        }

        .task-spec-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }

        .task-spec-row:last-child {
            margin-bottom: 0;
        }

        .task-label {
            color: var(--text-secondary);
            font-weight: 500;
        }

        .task-val {
            font-family: 'Fira Code', monospace;
            color: var(--text-primary);
        }

        .task-val.task-text {
            font-family: inherit;
            font-style: italic;
            color: #e2e8f0;
        }

        .btn {
            border: none;
            padding: 14px 24px;
            border-radius: 10px;
            font-weight: 600;
            font-size: 0.95rem;
            cursor: pointer;
            transition: all 0.2s;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .btn-positive {
            background: var(--accent-emerald);
            color: #052e16;
        }

        .btn-positive:hover {
            background: #059669;
            box-shadow: 0 0 20px rgba(16, 185, 129, 0.4);
        }

        .btn-negative {
            background: var(--accent-rose);
            color: #4c0519;
        }

        .btn-negative:hover {
            background: #e11d48;
            box-shadow: 0 0 20px rgba(244, 63, 94, 0.4);
        }

        /* Console styling */
        .console-container {
            background: #05070c;
            border: 1px solid var(--card-border);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 20px 50px rgba(0,0,0,0.5);
        }

        .console-header {
            background: #0c0e17;
            padding: 12px 18px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .console-dots {
            display: flex;
            gap: 6px;
        }

        .dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }

        .dot-red { background: #ff5f56; }
        .dot-yellow { background: #ffbd2e; }
        .dot-green { background: #27c93f; }

        .console-title {
            font-family: 'Fira Code', monospace;
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.15em;
        }

        .console-status {
            font-size: 0.75rem;
            font-family: 'Fira Code', monospace;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .status-indicator {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background-color: var(--text-secondary);
        }

        .status-indicator.running {
            background-color: var(--accent-amber);
            box-shadow: 0 0 8px var(--accent-amber);
            animation: pulse-amber 1s infinite alternate;
        }

        @keyframes pulse-amber {
            0% { opacity: 0.4; }
            100% { opacity: 1; }
        }

        .console-body {
            padding: 20px;
            height: 350px;
            overflow-y: auto;
            font-family: 'Fira Code', 'Courier New', Courier, monospace;
            font-size: 0.85rem;
            line-height: 1.6;
            color: #e2e8f0;
        }

        .log-line {
            margin-bottom: 8px;
            word-break: break-all;
            opacity: 0;
            transform: translateY(4px);
            animation: slideIn 0.2s forwards;
        }

        @keyframes slideIn {
            to { opacity: 1; transform: translateY(0); }
        }

        .log-time {
            color: #475569;
            margin-right: 8px;
            user-select: none;
        }

        /* Color classes for logs */
        .log-indra { color: #818cf8; }
        .log-agent { color: #f472b6; }
        .log-llm { color: #c084fc; }
        .log-stripe { color: #38bdf8; }
        .log-success { color: var(--accent-emerald); font-weight: 500; }
        .log-error { color: var(--accent-rose); font-weight: 500; }
        .log-alert { 
            color: #fff;
            background-color: #f43f5e; 
            padding: 4px 10px; 
            border-radius: 4px; 
            font-weight: 600; 
            display: inline-block;
            margin: 4px 0;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .log-reason {
            border-left: 2px solid var(--accent-rose);
            padding-left: 12px;
            color: #fda4af;
            margin-top: 6px;
            margin-bottom: 6px;
            margin-left: 10px;
            font-style: italic;
        }

        .empty-log {
            color: #475569;
            text-align: center;
            margin-top: 130px;
            font-style: italic;
        }

        /* Footer */
        footer {
            text-align: center;
            margin-top: 40px;
            color: #475569;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-badge">Indra Security</div>
            <h1>Zero-Trust Agent Governance</h1>
            <p class="subtitle">Demonstrating semantic security policy checks on AI agents via Cloudflare Edge Worker.</p>
        </header>

        <div class="info-panel">
            <div class="info-left">
                <div class="info-icon"></div>
                <div class="info-title">Active Operator Session</div>
            </div>
            <div>
                Authorized Scopes: <span class="info-scopes">stripe:write, instagram:write, admin</span>
            </div>
        </div>

        <div class="test-grid">
            <!-- Positive Test Card -->
            <div class="card positive">
                <div class="card-header">
                    <div class="card-tag">Aligned Task</div>
                    <h2 class="card-title">Positive Test Case</h2>
                    <p class="card-desc">The agent is given a task that matches the target action. The semantic firewall verifies the alignment and permits the request.</p>
                </div>
                
                <div>
                    <div class="task-spec">
                        <div class="task-spec-row">
                            <span class="task-label">Assigned Task:</span>
                            <span class="task-val task-text">"Make stripe charges of $100"</span>
                        </div>
                        <div class="task-spec-row">
                            <span class="task-label">Action Attempted:</span>
                            <span class="task-val">POST /v1/charges</span>
                        </div>
                        <div class="task-spec-row">
                            <span class="task-label">Expected Output:</span>
                            <span class="task-val" style="color: var(--accent-emerald)">200 Allowed / 401 Auth</span>
                        </div>
                    </div>
                    
                    <button class="btn btn-positive" onclick="runTest('positive')">
                        <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M5 13l4 4L19 7"></path></svg>
                        Run Positive Test
                    </button>
                </div>
            </div>

            <!-- Negative Test Card -->
            <div class="card negative">
                <div class="card-header">
                    <div class="card-tag" style="background: rgba(244, 63, 94, 0.1); color: var(--accent-rose)">Misaligned Task</div>
                    <h2 class="card-title">Negative Test Case</h2>
                    <p class="card-desc">The agent is tasked with posting an ad but attempts an unauthorized Stripe payment. The firewall catches it and blocks the request.</p>
                </div>
                
                <div>
                    <div class="task-spec">
                        <div class="task-spec-row">
                            <span class="task-label">Assigned Task:</span>
                            <span class="task-val task-text">"Post a new ad to Instagram"</span>
                        </div>
                        <div class="task-spec-row">
                            <span class="task-label">Action Attempted:</span>
                            <span class="task-val">POST /v1/charges</span>
                        </div>
                        <div class="task-spec-row">
                            <span class="task-label">Expected Output:</span>
                            <span class="task-val" style="color: var(--accent-rose)">403 Blocked</span>
                        </div>
                    </div>
                    
                    <button class="btn btn-negative" onclick="runTest('negative')">
                        <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                        Run Negative Test
                    </button>
                </div>
            </div>

            <!-- Revocation Loop Test Card -->
            <div class="card negative" style="border-top: 4px solid var(--accent-amber)">
                <div class="card-header">
                    <div class="card-tag" style="background: rgba(245, 158, 11, 0.1); color: var(--accent-amber)">Revocation Test</div>
                    <h2 class="card-title">Revocation Loop Test</h2>
                    <p class="card-desc">The agent runs a loop making a Stripe charge every 10 seconds. Revoking the mission from the Edge Dashboard should instantly block subsequent calls.</p>
                </div>
                
                <div>
                    <div class="task-spec">
                        <div class="task-spec-row">
                            <span class="task-label">Assigned Task:</span>
                            <span class="task-val task-text">"Make stripe charges of $100"</span>
                        </div>
                        <div class="task-spec-row">
                            <span class="task-label">Action Attempted:</span>
                            <span class="task-val">Loop: POST /v1/charges</span>
                        </div>
                        <div class="task-spec-row">
                            <span class="task-label">Expected Output:</span>
                            <span class="task-val" style="color: var(--accent-rose)">403 after Revocation</span>
                        </div>
                    </div>
                    
                    <button class="btn" style="background: var(--accent-amber); color: #451a03;" onclick="runTest('revocation')">
                        <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path><line x1="12" y1="2" x2="12" y2="12"></line></svg>
                        Run Revocation Test
                    </button>
                </div>
            </div>
        </div>

        <!-- Terminal Console -->
        <div class="console-container">
            <div class="console-header">
                <div class="console-dots">
                    <div class="dot dot-red"></div>
                    <div class="dot dot-yellow"></div>
                    <div class="dot dot-green"></div>
                </div>
                <div class="console-title">Agent Execution Console</div>
                <div class="console-status">
                    <div id="status-dot" class="status-indicator"></div>
                    <span id="status-text">IDLE</span>
                </div>
            </div>
            <div class="console-body" id="console-body">
                <div class="empty-log" id="empty-log">Click one of the buttons above to run the security simulation...</div>
            </div>
        </div>

        <footer>
            Indra Zero-Trust Web Agent Platform &bull; Powered by Cloudflare Workers AI
        </footer>
    </div>

    <script>
        function getTimestamp() {
            const now = new Date();
            return now.toTimeString().split(' ')[0];
        }

        function appendLog(text, cssClass = '') {
            const body = document.getElementById('console-body');
            const empty = document.getElementById('empty-log');
            if (empty) empty.remove();

            const line = document.createElement('div');
            line.className = 'log-line';
            
            const timeSpan = document.createElement('span');
            timeSpan.className = 'log-time';
            timeSpan.innerText = `[${getTimestamp()}]`;
            
            const textSpan = document.createElement('span');
            textSpan.className = cssClass;
            textSpan.innerHTML = text;

            line.appendChild(timeSpan);
            line.appendChild(textSpan);
            body.appendChild(line);

            // Auto scroll to bottom
            body.scrollTop = body.scrollHeight;
        }

        async function runTest(type) {
            const statusDot = document.getElementById('status-dot');
            const statusText = document.getElementById('status-text');
            const body = document.getElementById('console-body');
            
            // Set running state
            statusDot.className = 'status-indicator running';
            statusText.innerText = 'RUNNING';
            body.innerHTML = ''; // Clear previous logs
            
            appendLog(`Initializing ${type.toUpperCase()} test case...`, 'log-indra');
            
            if (type === 'revocation') {
                try {
                    const response = await fetch(`/api/revoke-test`);
                    if (!response.body) {
                        appendLog(`Streaming not supported by browser.`, 'log-error');
                        return;
                    }
                    const reader = response.body.getReader();
                    const decoder = new TextDecoder();
                    let done = false;
                    let buffer = '';

                    while (!done) {
                        const { value, done: doneReading } = await reader.read();
                        done = doneReading;
                        buffer += decoder.decode(value, { stream: !done });
                        
                        const lines = buffer.split('\\n');
                        buffer = lines.pop(); // Keep the last partial line in buffer
                        
                        for (const line of lines) {
                            if (!line.trim()) continue;
                            let cssClass = '';
                            let cleanLog = line;
                            
                            if (line.startsWith('[Indra]')) {
                                cssClass = 'log-indra';
                            } else if (line.startsWith('[Agent]')) {
                                cssClass = 'log-agent';
                            } else if (line.startsWith('[LLM]')) {
                                cssClass = 'log-llm';
                            } else if (line.startsWith('[Stripe]')) {
                                cssClass = 'log-stripe';
                            } else if (line.startsWith('[Error]')) {
                                cssClass = 'log-error';
                            } else if (line.includes('Success')) {
                                cssClass = 'log-success';
                            }
                            
                            // Parse custom security alerts
                            if (line.startsWith('[SECURITY ALERT]')) {
                                appendLog('[SECURITY ALERT] Outbound request blocked!', 'log-alert');
                                continue;
                            }
                            
                            if (line.startsWith('[Reason]')) {
                                appendLog(line, 'log-reason');
                                continue;
                            }
                            
                            appendLog(cleanLog, cssClass);
                        }
                    }
                    appendLog(`Revocation Loop Test completed.`, 'log-success');
                } catch (err) {
                    appendLog(`Connection error: ${err.message}`, 'log-error');
                } finally {
                    statusDot.className = 'status-indicator';
                    statusText.innerText = 'IDLE';
                }
                return;
            }

            try {
                const response = await fetch(`/api/agent?test_type=${type}`);
                const data = await response.json();
                
                if (data.logs && Array.isArray(data.logs)) {
                    for (const log of data.logs) {
                        let cssClass = '';
                        let cleanLog = log;
                        
                        if (log.startsWith('[Indra]')) {
                            cssClass = 'log-indra';
                        } else if (log.startsWith('[Agent]')) {
                            cssClass = 'log-agent';
                        } else if (log.startsWith('[LLM]')) {
                            cssClass = 'log-llm';
                        } else if (log.startsWith('[Stripe]')) {
                            cssClass = 'log-stripe';
                        } else if (log.startsWith('[Error]')) {
                            cssClass = 'log-error';
                        } else if (log.includes('Success')) {
                            cssClass = 'log-success';
                        }
                        
                        // Parse custom security alerts
                        if (log.startsWith('[SECURITY ALERT]')) {
                            appendLog('[SECURITY ALERT] Outbound request blocked!', 'log-alert');
                            continue;
                        }
                        
                        if (log.startsWith('[Reason]')) {
                            appendLog(log, 'log-reason');
                            continue;
                        }
                        
                        appendLog(cleanLog, cssClass);
                        // Add tiny delay to simulate real-time output
                        await new Promise(r => setTimeout(r, 80));
                    }
                }
                
                if (response.ok && data.success) {
                    appendLog(`Test case completed successfully (Allowed).`, 'log-success');
                } else if (response.status === 401) {
                    appendLog(`Test case successfully allowed by Semantic Firewall (forwarded to Stripe).`, 'log-success');
                } else if (response.status === 403) {
                    appendLog(`Test case successfully blocked by Semantic Firewall policy.`, 'log-success');
                } else {
                    appendLog(`Test case finished with semantic block or connection error.`, 'log-error');
                }
            } catch (err) {
                appendLog(`Connection error: ${err.message}`, 'log-error');
            } finally {
                statusDot.className = 'status-indicator';
                statusText.innerText = 'IDLE';
            }
        }
    </script>
</body>
</html>
"""

@app.route('/api/agent', methods=['GET', 'POST'])
def run_agent():
    test_type = flask_request.values.get("test_type", "positive")
    logs = []
    
    if test_type == "negative":
        prompt = "Post a new ad to Instagram"
        task_name = "Post a new ad to Instagram"
    else:
        prompt = flask_request.values.get("prompt", "Make stripe charges of $100")
        task_name = f"Stripe Charge Agent: {prompt}"

    try:
        # 1. Initialize Indra SDK in serverless mode
        indra_sdk.init(
            task=task_name,
            is_serverless=True
        )
        logs.append(f"[Indra] Session initialized securely on the Edge.")
        logs.append(f"[Indra] Task context set to: \"{task_name}\"")

        openai_key = os.getenv("OPENAI_API_KEY")
        stripe_key = os.getenv("STRIPE_API_KEY") or "sk_test_mock_stripe_key"

        tool_call_args = None

        if test_type == "negative":
            # Simulate a hijacked / compromised agent bypassing the assigned task steps
            # and executing an unauthorized Stripe charge directly.
            logs.append(f"[Agent] Rogue behavior triggered (simulating hijacking/compromise)!")
            logs.append(f"[Agent] Task is \"Post a new ad to Instagram\", but executing unauthorized Stripe charge...")
            tool_call_args = {"amount": 100}
        else:
            # 2. Call the LLM (OpenAI) to parse the request in positive mode
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
            
            # This call to Stripe is audited, logged, and matched against semantic/OPA policy on the Edge.
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
            body_json = json.loads(body)
        except:
            body_json = None
            
        if e.code == 403:
            logs.append("[SECURITY ALERT] Request blocked by Indra Edge Semantic Firewall!")
            logs.append(f"[Reason] {body}")
        elif e.code == 401:
            # Statically, the token is valid for Edge, but failed with Stripe's API because key is mock.
            # This demonstrates that the request successfully passed the Edge Semantic Firewall interception!
            logs.append("[Security] Request allowed by Edge Semantic Firewall (aligned with task).")
            logs.append("[Stripe] Outbound request forwarded to Stripe.com successfully.")
            logs.append("[Stripe] Stripe API returned 401 Unauthorized (expected due to mock api key).")
        else:
            logs.append(f"[Error] HTTP {e.code}: {e.reason}")
            if body:
                logs.append(f"[Detail] {body}")

        return jsonify({
            'success': False,
            'logs': logs,
            'error': f"HTTP {e.code}: {e.reason}",
            'body': body_json or body
        }), e.code
    except Exception as e:
        logs.append(f"[Error] Exception: {str(e)}")
        return jsonify({
            'success': False,
            'logs': logs,
            'error': str(e)
        }), 500
    finally:
        try:
            indra_sdk.close()
            logs.append("[Indra] Session securely closed.")
        except Exception as close_err:
            print(f"[AGENT-ERROR] Failed to close agent session: {close_err}")


@app.route('/api/revoke-test')
def run_revoke_test():
    import time
    from flask import Response, stream_with_context

    def generate():
        task_name = "Stripe Charge Agent: Make stripe charges of $100"
        
        try:
            # 1. Initialize Indra SDK in serverless mode
            indra_sdk.init(
                task=task_name,
                is_serverless=True
            )
            yield "[Indra] Session initialized securely on the Edge.\n"
            yield f"[Indra] Task context set to: \"{task_name}\"\n"
            yield "[Agent] Starting loop to make Stripe calls (interval: 10s). Go to the Edge Dashboard and click KILL to test revocation!\n"
            
            stripe_key = os.getenv("STRIPE_API_KEY") or "sk_test_mock_stripe_key"
            
            for i in range(1, 6):
                yield f"[Agent] Loop iteration {i}/5: Initiating Stripe charge...\n"
                
                headers = {
                    "Authorization": f"Bearer {stripe_key}",
                    "Content-Type": "application/x-www-form-urlencoded"
                }
                payload = {
                    "amount": 10000, # $100 in cents
                    "currency": "usd",
                    "source": "tok_visa"
                }
                
                # Make the Stripe call
                req = urllib.request.Request(
                    "https://api.stripe.com/v1/charges",
                    headers=headers,
                    data=urllib.parse.urlencode(payload).encode('utf-8'),
                    method="POST"
                )
                
                try:
                    with urllib.request.urlopen(req) as resp:
                        status = resp.status
                        body = resp.read().decode('utf-8')
                    
                    if status == 200:
                        yield "[Stripe] Success! Charge created.\n"
                    else:
                        yield f"[Error] Stripe request returned status {status}: {body}\n"
                        
                except urllib.error.HTTPError as e:
                    body = e.read().decode('utf-8')
                    if e.code == 403:
                        yield "[SECURITY ALERT] Request blocked by Indra Edge Semantic Firewall!\n"
                        yield f"[Reason] {body}\n"
                        yield "[Agent] Breaking execution loop due to active block.\n"
                        break
                    elif e.code == 401:
                        yield "[Security] Request allowed by Edge Semantic Firewall (aligned with task).\n"
                        yield "[Stripe] Stripe API returned 401 Unauthorized (expected due to mock api key).\n"
                    else:
                        yield f"[Error] HTTP {e.code}: {e.reason}\n"
                
                if i < 5:
                    yield "[Agent] Sleeping for 10 seconds...\n"
                    time.sleep(10)
                    
            yield "[Agent] Loop complete.\n"
            
        except Exception as err:
            yield f"[Error] Exception: {str(err)}\n"
        finally:
            try:
                indra_sdk.close()
                yield "[Indra] Session securely closed.\n"
            except Exception as close_err:
                print(f"[AGENT-ERROR] Failed to close agent session: {close_err}")
                
    return Response(stream_with_context(generate()), mimetype='text/plain')

