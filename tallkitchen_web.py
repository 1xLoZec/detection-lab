"""
Tall Kitchen Hunt - web API.
Thin wrapper over tallkitchen_hunt. Imports the real logic, never duplicates it.
Serves the concise verdict + source breakdown as JSON, and the static page.
"""
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

import tallkitchen_hunt as tk

app = FastAPI(title="Tall Kitchen Hunt")

HERE = Path(__file__).parent
WEB_DIR = HERE / "web"


def _run_hunt(ioc: str) -> dict:
    ioc = (ioc or "").strip()
    if not ioc:
        raise HTTPException(status_code=400, detail="empty IOC")
    ioc_type = tk.detect_ioc_type(ioc)
    if ioc_type not in ("ipv4", "md5", "sha1", "sha256", "domain"):
        return {"ioc": ioc, "ioc_type": ioc_type, "supported": False,
                "message": f"Unsupported IOC type: {ioc_type}. Supported: IPv4, file hash, domain."}

    conn = tk.memory_init()
    try:
        is_hash = ioc_type in ("md5", "sha1", "sha256")
        is_domain = ioc_type == "domain"
        if is_hash:
            external = tk.bucket_external_hash(conn, ioc, ioc_type)
        elif is_domain:
            external = tk.bucket_external_domain(conn, ioc)
        else:
            # IP path needs internal SIEM; degrade gracefully if unreachable
            try:
                external = tk.bucket_external_ip(conn, ioc)
            except Exception as e:
                external = {}
        verdict = tk.bucket_verdict({}, external, ioc_type)
    finally:
        conn.close()

    return {"ioc": ioc, "ioc_type": ioc_type, "supported": True,
            "verdict": verdict, "external": external}


@app.get("/api/hunt")
def api_hunt(ioc: str):
    return JSONResponse(_run_hunt(ioc))


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
