import os
import json
import httpx
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from reader import extract_text
from analyzer import analyze_report
from correlator import correlate_findings

app = FastAPI(
    title="ThreatBridge API",
    description="AI Powered SOC Automation Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Deploy request model ──────────────────────────────────────────────────────

class DeployRequest(BaseModel):
    siem: str
    soar: str
    siem_url: str
    siem_api_key: str
    soar_url: str
    soar_api_key: str
    siem_rule_code: str
    siem_rule_filename: str
    soar_playbook_code: str
    soar_playbook_filename: str


# ── Home ──────────────────────────────────────────────────────────────────────

@app.get("/")
def home():
    return {
        "message": "ThreatBridge Backend is running",
        "status": "online"
    }


# ── Upload & Analyse ──────────────────────────────────────────────────────────

@app.post("/upload")
async def upload_report(
    file: UploadFile = File(...),
    siem: str = "Wazuh",
    soar: str = "Shuffle"
):
    allowed_types = ["pdf", "docx", "txt"]
    extension = file.filename.lower().split(".")[-1]
    if extension not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="File type not supported. Please upload PDF, DOCX or TXT"
        )

    file_bytes = await file.read()

    try:
        text = extract_text(file_bytes, file.filename)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not read file: {str(e)}")

    try:
        analysis = analyze_report(text, siem, soar)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

    try:
        findings = analysis.get("findings", [])
        correlation = correlate_findings(findings) if len(findings) > 1 else None
    except Exception:
        correlation = None

    return {
        "filename": file.filename,
        "siem": siem,
        "soar": soar,
        "status": "success",
        "analysis": analysis,
        "correlation": correlation
    }


# ── Deploy ────────────────────────────────────────────────────────────────────

@app.post("/deploy")
async def deploy(req: DeployRequest):
    results = {}

    # ── SIEM deploy ───────────────────────────────────────────────────────────
    try:
        if req.siem == "Wazuh":
            results["siem"] = await deploy_wazuh(
                req.siem_url, req.siem_api_key,
                req.siem_rule_code, req.siem_rule_filename
            )

        elif req.siem == "Splunk":
            results["siem"] = await deploy_splunk(
                req.siem_url, req.siem_api_key,
                req.siem_rule_code, req.siem_rule_filename
            )

        elif req.siem == "Elastic":
            results["siem"] = await deploy_elastic(
                req.siem_url, req.siem_api_key,
                req.siem_rule_code, req.siem_rule_filename
            )

        elif req.siem == "Microsoft Sentinel":
            results["siem"] = await deploy_sentinel_rule(
                req.siem_url, req.siem_api_key,
                req.siem_rule_code, req.siem_rule_filename
            )

        elif req.siem == "IBM QRadar":
            results["siem"] = await deploy_qradar(
                req.siem_url, req.siem_api_key,
                req.siem_rule_code, req.siem_rule_filename
            )

        else:
            results["siem"] = {
                "status": "skipped",
                "message": f"Deploy not supported for {req.siem}"
            }

    except Exception as e:
        results["siem"] = {"status": "error", "message": str(e)}

    # ── SOAR deploy ───────────────────────────────────────────────────────────
    try:
        if req.soar == "Shuffle":
            results["soar"] = await deploy_shuffle(
                req.soar_url, req.soar_api_key,
                req.soar_playbook_code, req.soar_playbook_filename
            )

        elif req.soar == "Palo Alto XSOAR":
            results["soar"] = await deploy_xsoar(
                req.soar_url, req.soar_api_key,
                req.soar_playbook_code, req.soar_playbook_filename
            )

        elif req.soar == "Splunk SOAR":
            results["soar"] = await deploy_splunk_soar(
                req.soar_url, req.soar_api_key,
                req.soar_playbook_code, req.soar_playbook_filename
            )

        elif req.soar == "Microsoft Sentinel Playbooks":
            results["soar"] = await deploy_sentinel_playbook(
                req.soar_url, req.soar_api_key,
                req.soar_playbook_code, req.soar_playbook_filename
            )

        elif req.soar == "Tines":
            results["soar"] = await deploy_tines(
                req.soar_url, req.soar_api_key,
                req.soar_playbook_code, req.soar_playbook_filename
            )

        else:
            results["soar"] = {
                "status": "skipped",
                "message": f"Deploy not supported for {req.soar}"
            }

    except Exception as e:
        results["soar"] = {"status": "error", "message": str(e)}

    # ── Overall status ────────────────────────────────────────────────────────
    siem_ok = results.get("siem", {}).get("status") == "success"
    soar_ok = results.get("soar", {}).get("status") == "success"

    if siem_ok and soar_ok:
        overall = "success"
    elif siem_ok or soar_ok:
        overall = "partial"
    else:
        overall = "error"

    return {
        "status": overall,
        "siem_result": results.get("siem"),
        "soar_result": results.get("soar")
    }


# ── SIEM deployers ────────────────────────────────────────────────────────────

async def deploy_wazuh(url: str, api_key: str, code: str, filename: str) -> dict:
    """
    Wazuh Manager REST API
    Step 1: Authenticate with username:password to get JWT
    Step 2: PUT /rules/files/{filename} — uploads a custom XML rule file
    Step 3: Restart the manager so the rule is loaded
    api_key format expected: "username:password" e.g. "wazuh-wui:MyPassword1+"
    """
    base = url.rstrip("/")

    try:
        username, password = api_key.split(":", 1)
    except ValueError:
        return {
            "status": "error",
            "message": "Wazuh API key must be in 'username:password' format"
        }

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        # Step 1: Authenticate to get JWT
        auth_resp = await client.get(
            f"{base}/security/user/authenticate",
            auth=(username, password)
        )
        if auth_resp.status_code != 200:
            return {
                "status": "error",
                "message": f"Wazuh auth failed: {auth_resp.status_code} {auth_resp.text}"
            }

        token = auth_resp.json()["data"]["token"]
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/octet-stream"
        }

        # Step 2: Upload rule file
        xml_filename = filename.replace('.txt', '.xml')
        upload_resp = await client.put(
            f"{base}/rules/files/{xml_filename}",
            headers=headers,
            content=code.encode("utf-8"),
            params={"overwrite": "true"}
        )
        if upload_resp.status_code not in (200, 201):
            return {
                "status": "error",
                "message": f"Wazuh upload failed: {upload_resp.status_code} {upload_resp.text}"
            }

        # Step 3: Restart manager to load new rule
        restart_resp = await client.put(
            f"{base}/manager/restart",
            headers=headers
        )
        if restart_resp.status_code not in (200, 202):
            return {
                "status": "error",
                "message": f"Wazuh restart failed: {restart_resp.status_code} {restart_resp.text}"
            }

    return {
        "status": "success",
        "message": f"Rule {filename} deployed to Wazuh and manager restarted"
    }


async def deploy_splunk(url: str, api_key: str, code: str, filename: str) -> dict:
    """
    Splunk REST API
    POST /services/saved/searches  — creates a saved search (alert) from SPL
    """
    base = url.rstrip("/")
    # Use only the first rule (IOC rule) before the semicolon
    ioc_rule = code.split(";")[0].strip()
    search_name = filename.replace(".txt", "").replace("_", " ")

    headers = { 
       "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "name": search_name,
        "search": ioc_rule,
        "is_scheduled": "1",
        "cron_schedule": "*/5 * * * *",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.severity": "4",

        "description": f"ThreatBridge auto-deployed rule: {filename}"
    }

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.post(
            f"{base}/services/saved/searches",
            headers=headers,
            data=data
        )
        if resp.status_code not in (200, 201):
            return {
                "status": "error",
                "message": f"Splunk deploy failed: {resp.status_code} {resp.text}"
            }

    return {
        "status": "success",
        "message": f"Saved search '{search_name}' deployed to Splunk"
    }


async def deploy_elastic(url: str, api_key: str, code: str, filename: str) -> dict:
    """
    Elastic Security API
    POST /api/detection_engine/rules  — creates a detection rule
    """
    base = url.rstrip("/")
    rule_name = filename.replace(".txt", "").replace("_", " ")
    # Use only IOC rule (before semicolon)
    ioc_rule = code.split(";")[0].strip()

    headers = {
        "Authorization": f"ApiKey {api_key}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true"
    }

    payload = {
        "type": "eql",
        "language": "eql",
        "name": rule_name,
        "description": f"ThreatBridge auto-deployed: {filename}",
        "severity": "high",
        "risk_score": 75,
        "query": ioc_rule,
        "enabled": True,
        "from": "now-1h"
    }

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.post(
            f"{base}/api/detection_engine/rules",
            headers=headers,
            json=payload
        )
        if resp.status_code not in (200, 201):
            return {
                "status": "error",
                "message": f"Elastic deploy failed: {resp.status_code} {resp.text}"
            }

    return {
        "status": "success",
        "message": f"Detection rule '{rule_name}' deployed to Elastic Security"
    }


async def deploy_sentinel_rule(url: str, api_key: str, code: str, filename: str) -> dict:
    """
    Microsoft Sentinel Analytics Rules API
    PUT /providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/
        Microsoft.SecurityInsights/alertRules/{ruleId}
    url format expected: https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/
                         providers/Microsoft.OperationalInsights/workspaces/{workspace}
    """
    base = url.rstrip("/")
    rule_name = filename.replace(".txt", "").replace("_", " ")
    ioc_rule = code.split(";")[0].strip()
    rule_id = filename.replace(".txt", "").replace(" ", "-").lower()

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "kind": "Scheduled",
        "properties": {
            "displayName": rule_name,
            "description": f"ThreatBridge auto-deployed: {filename}",
            "severity": "High",
            "enabled": True,
            "query": ioc_rule,
            "queryFrequency": "PT1H",
            "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT5H",
            "suppressionEnabled": False
        }
    }

    sentinel_url = (
        f"{base}/providers/Microsoft.SecurityInsights/alertRules/{rule_id}"
        f"?api-version=2023-02-01"
    )

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.put(
            sentinel_url,
            headers=headers,
            json=payload
        )
        if resp.status_code not in (200, 201):
            return {
                "status": "error",
                "message": f"Sentinel deploy failed: {resp.status_code} {resp.text}"
            }

    return {
        "status": "success",
        "message": f"Analytics rule '{rule_name}' deployed to Microsoft Sentinel"
    }


async def deploy_qradar(url: str, api_key: str, code: str, filename: str) -> dict:
    """
    IBM QRadar REST API
    POST /api/ariel/searches  — runs the AQL query as a saved search
    """
    base = url.rstrip("/")
    ioc_rule = code.split(";")[0].strip()

    headers = {
        "SEC": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Version": "14.0"
    }

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.post(
            f"{base}/api/ariel/searches",
            headers=headers,
            json={"query_expression": ioc_rule}
        )
        if resp.status_code not in (200, 201):
            return {
                "status": "error",
                "message": f"QRadar deploy failed: {resp.status_code} {resp.text}"
            }

    return {
        "status": "success",
        "message": f"AQL search deployed to IBM QRadar"
    }


# ── SOAR deployers ────────────────────────────────────────────────────────────

async def deploy_shuffle(url: str, api_key: str, code: str, filename: str) -> dict:
    """
    Shuffle REST API
    POST /api/v1/workflows  — creates a new workflow
    """
    base = url.rstrip("/")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    # code is already valid Shuffle JSON
     # Parse the playbook
    try:
        playbook = json.loads(code)
    except Exception:
        playbook = {"name": filename, "description": code}

    # Build Shuffle-native actions from playbook
    actions = []
    for i, action in enumerate(playbook.get("actions", [])):
        actions.append({
            "app_name": "http",
            "app_version": "1.0.0",
            "app_id": "http",
            "name": "call_url",
            "label": action.get("name", f"Action {i+1}"),
            "environment": "Cloud",
            "is_valid": True,
            "isStartNode": i == 0,
            "parameters": [
                {
                    "name": "url",
                    "value": str(action.get("parameters", {}).get("url", "")),
                    "variant": "STATIC_VALUE",
                    "required": True
                },
                {
                    "name": "body",
                    "value": json.dumps(action.get("parameters", {}).get("body", {})),
                    "variant": "STATIC_VALUE",
                    "required": False
                }
            ],
            "position": {"x": 0, "y": i * 150},
            "id": f"action_{i}"
        })

    workflow = {
        "name": playbook.get("name", filename),
        "description": playbook.get("description", "ThreatBridge auto-deployed"),
        "actions": actions,
        "branches": [],
        "triggers": [],
        "is_valid": True,
        "start": "action_0" if actions else ""
    }

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        # Step 1: Create blank workflow to get ID
        create_resp = await client.post(
            f"{base}/api/v1/workflows",
            headers=headers,
            json={
                "name": workflow.get("name", filename),
                "description": workflow.get("description", "ThreatBridge auto-deployed")
            }
        )
        if create_resp.status_code not in (200, 201):
            return {
                "status": "error",
                "message": f"Shuffle create failed: {create_resp.status_code} {create_resp.text}"
            }

        workflow_id = create_resp.json().get("id")
        if not workflow_id:
            return {
                "status": "error",
                "message": "Shuffle did not return a workflow ID"
            }

        # Step 2: Save full workflow content
        workflow["id"] = workflow_id
        save_resp = await client.put(
            f"{base}/api/v1/workflows/{workflow_id}",
            headers=headers,
            json=workflow
        )
        if save_resp.status_code not in (200, 201):
            return {
                "status": "error",
                "message": f"Shuffle save failed: {save_resp.status_code} {save_resp.text}"
            }

    return {
        "status": "success",
        "message": f"Workflow '{workflow.get('name', filename)}' deployed to Shuffle"
    }


async def deploy_xsoar(url: str, api_key: str, code: str, filename: str) -> dict:
    """
    Cortex XSOAR REST API
    POST /automation/save  — uploads a Python automation script
    """
    base = url.rstrip("/")
    script_name = filename.replace(".txt", "").replace("_", "")

    headers = {
       "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = {
        "script": {
            "name": script_name,
            "type": "python",
            "subtype": "python3",
            "script": code,
            "comment": f"ThreatBridge auto-deployed: {filename}"
        }
    }

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.post(
            f"{base}/automation/save",
            headers=headers,
            json=payload
        )
        if resp.status_code not in (200, 201):
            return {
                "status": "error",
                "message": f"XSOAR deploy failed: {resp.status_code} {resp.text}"
            }

    return {
        "status": "success",
        "message": f"Automation script '{script_name}' deployed to Palo Alto XSOAR"
    }


async def deploy_splunk_soar(url: str, api_key: str, code: str, filename: str) -> dict:
    """
    Splunk SOAR (Phantom) REST API
    POST /rest/playbook  — uploads a playbook
    """
    base = url.rstrip("/")
    playbook_name = filename.replace(".txt", "").replace("_", " ")

    headers = {
        "ph-auth-token": api_key,
        "Content-Type": "application/json"
    }

    payload = {
        "name": playbook_name,
        "scm": "local",
        "language": "python",
        "playbook": code,
        "status": "active"
    }

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.post(
            f"{base}/rest/playbook",
            headers=headers,
            json=payload
        )
        if resp.status_code not in (200, 201):
            return {
                "status": "error",
                "message": f"Splunk SOAR deploy failed: {resp.status_code} {resp.text}"
            }

    return {
        "status": "success",
        "message": f"Playbook '{playbook_name}' deployed to Splunk SOAR"
    }


async def deploy_sentinel_playbook(url: str, api_key: str, code: str, filename: str) -> dict:
    """
    Microsoft Logic Apps REST API
    PUT /providers/Microsoft.Logic/workflows/{workflowName}
    url format: https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}
    """
    base = url.rstrip("/")
    workflow_name = filename.replace(".txt", "").replace("_", "-").lower()

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    try:
        definition = json.loads(code)
    except Exception:
        definition = {}

    payload = {
        "location": "eastus",
        "properties": {
            "definition": definition.get("definition", definition),
            "state": "Enabled"
        }
    }

    logic_app_url = (
        f"{base}/providers/Microsoft.Logic/workflows/{workflow_name}"
        f"?api-version=2016-06-01"
    )

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.put(
            logic_app_url,
            headers=headers,
            json=payload
        )
        if resp.status_code not in (200, 201):
            return {
                "status": "error",
                "message": f"Sentinel Playbook deploy failed: {resp.status_code} {resp.text}"
            }

    return {
        "status": "success",
        "message": f"Logic App '{workflow_name}' deployed to Microsoft Sentinel"
    }


async def deploy_tines(url: str, api_key: str, code: str, filename: str) -> dict:
    """
    Tines REST API
    POST /api/v1/stories/import  — imports a workflow story
    """
    base = url.rstrip("/")

    headers = {
        "x-user-token": api_key,
        "Content-Type": "application/json"
    }

    try:
        story = json.loads(code)
    except Exception:
        story = {"name": filename}

    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.post(
            f"{base}/api/v1/stories/import",
            headers=headers,
            json={"story": story}
        )
        if resp.status_code not in (200, 201):
            return {
                "status": "error",
                "message": f"Tines deploy failed: {resp.status_code} {resp.text}"
            }

    return {
        "status": "success",
        "message": f"Story deployed to Tines"
    }