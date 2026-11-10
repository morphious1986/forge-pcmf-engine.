#!/usr/bin/env python3
import json, os, subprocess, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SETUP=ROOT/"bin"/"pcmf-setup"

class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        if self.path!="/v1/models":
            self.send_response(404); self.end_headers(); return
        body=json.dumps({"object":"list","data":[{"id":"sol","object":"model"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)

srv=ThreadingHTTPServer(("127.0.0.1",0),H)
threading.Thread(target=srv.serve_forever,daemon=True).start()
endpoint=f"http://127.0.0.1:{srv.server_address[1]}/v1"
home=Path(tempfile.mkdtemp(prefix="pcmf-setup-llama-"))
try:
    env=os.environ.copy()
    env["HOME"]=str(home)
    inp=f"18\n{endpoint}\nsol\n\nq\n"
    p=subprocess.run([str(SETUP)],input=inp,text=True,capture_output=True,env=env,timeout=15)
    if p.returncode!=0:
        raise SystemExit(f"setup failed rc={p.returncode}\n{p.stdout}\n{p.stderr}")
    if "PASS_LOCAL_LLAMA_CONNECTION model=sol memory_transfer=false" not in p.stdout:
        raise SystemExit("setup did not confirm local llama connection")
    conf=(home/".config/pcmf/pcmf.conf").read_text()
    required=[
        "local_llama_provider=llama_cpp",
        f"local_llama_endpoint={endpoint}",
        "local_llama_model=sol",
        "local_llama_enabled=true",
        "local_llama_memory_transfer=false",
    ]
    for x in required:
        if x not in conf:
            raise SystemExit(f"missing config: {x}")
    print("PASS_PCMF_SETUP_LOCAL_LLAMA_DIRECT model=sol enabled=true memory_transfer=false")
finally:
    srv.shutdown(); srv.server_close()
    import shutil; shutil.rmtree(home,ignore_errors=True)
