from __future__ import annotations
import logging, os
from typing import Any
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from core.analyzer import SecurityAnalyzer

BASE_DIR=os.path.dirname(os.path.abspath(__file__))
templates=Jinja2Templates(directory=os.path.join(BASE_DIR,"templates"))
logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO").upper(),format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger=logging.getLogger("security-auditor")
app=FastAPI(title="SecureLens",version="2.1.1",description="Passive-first web security posture auditor with website reconnaissance.")

def _int(name:str,default:int)->int:
    try:return int(os.getenv(name,str(default)))
    except ValueError:return default

def _float(name:str,default:float)->float:
    try:return float(os.getenv(name,str(default)))
    except ValueError:return default

def _options(active:bool)->dict[str,Any]:
    return {"timeout":_float("AUDITOR_TIMEOUT",10),"max_redirects":_int("AUDITOR_MAX_REDIRECTS",10),"verify_tls":os.getenv("AUDITOR_VERIFY_TLS","true").lower() not in {"0","false","no"},"dns_timeout":_float("AUDITOR_DNS_TIMEOUT",5),"enable_active_checks":active,"max_body_bytes":_int("AUDITOR_MAX_BODY_BYTES",524288),"max_crawl_depth":_int("AUDITOR_MAX_CRAWL_DEPTH",2),"max_crawl_urls":_int("AUDITOR_MAX_CRAWL_URLS",200),"crawl_concurrency":_int("AUDITOR_CRAWL_CONCURRENCY",8)}

def page(request:Request,results=None,target="",status_code=200):
    return templates.TemplateResponse(request, "dashboard.html", {"results": results, "target": target}, status_code=status_code)

@app.get("/",response_class=HTMLResponse)
async def dashboard(request:Request): return page(request)

@app.post("/scan",response_class=HTMLResponse)
async def scan(request:Request,target_url:str=Form(...),active_checks:bool=Form(False)):
    target_url=target_url.strip()
    if not target_url:return page(request,{"error":"A target URL is required."},target_url,400)
    try:
        result=await SecurityAnalyzer(target_url,**_options(active_checks)).run_audit()
        return page(request,result,target_url,200 if result.get("audit",{}).get("status")!="failed" else 502)
    except ValueError as exc:return page(request,{"error":str(exc)},target_url,400)
    except Exception as exc:
        logger.exception("Unhandled scan failure")
        return page(request,{"error":f"Scan failed: {exc}"},target_url,500)

@app.post("/api/scan")
async def api_scan(target_url:str=Form(...),active_checks:bool=Form(False)):
    target_url=target_url.strip()
    if not target_url:return JSONResponse({"error":"A target URL is required."},status_code=400)
    try:return JSONResponse(await SecurityAnalyzer(target_url,**_options(active_checks)).run_audit())
    except ValueError as exc:return JSONResponse({"error":str(exc)},status_code=400)
    except Exception as exc:
        logger.exception("API scan failure")
        return JSONResponse({"error":f"Scan failed: {exc}"},status_code=500)

@app.get("/health")
async def health():return {"status":"ok","service":"SecureLens","version":app.version}

if __name__=="__main__":
    import uvicorn
    uvicorn.run("app:app",host=os.getenv("HOST","127.0.0.1"),port=_int("PORT",8000))
