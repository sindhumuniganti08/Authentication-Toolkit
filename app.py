"""
FastAPI Web App for Project 4: Application Security Demonstration Lab
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
import os
from pydantic import BaseModel
from typing import Optional

from vulnerabilities import appsec_engine

app = FastAPI(
    title="Application Security Demonstration Lab API",
    description="Interactive Web Application Security testing laboratory showcasing OWASP vulnerabilities and secure coding mitigations.",
    version="1.0.0"
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)

class SQLiRequest(BaseModel):
    user_input: str

class XSSRequest(BaseModel):
    user_input: str

class IDORRequest(BaseModel):
    requested_user_id: int
    current_user_id: int
    current_role: str

class CmdInjectionRequest(BaseModel):
    target_domain: str

@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>AppSec Security Lab Web UI</h1>"

@app.post("/api/demo/sqli")
def demo_sqli(req: SQLiRequest):
    return appsec_engine.demo_sqli(req.user_input)

@app.post("/api/demo/xss")
def demo_xss(req: XSSRequest):
    return appsec_engine.demo_xss(req.user_input)

@app.post("/api/demo/idor")
def demo_idor(req: IDORRequest):
    return appsec_engine.demo_idor(req.requested_user_id, req.current_user_id, req.current_role)

@app.post("/api/demo/command-injection")
def demo_cmd_injection(req: CmdInjectionRequest):
    return appsec_engine.demo_command_injection(req.target_domain)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)

