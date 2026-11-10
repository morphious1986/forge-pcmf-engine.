#!/usr/bin/env python3
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BIN=ROOT/"bin"/"pcmf-local-model"
checks=0
def ok(cond,msg):
    global checks
    if not cond:
        raise AssertionError(msg)
    checks+=1

class H(BaseHTTPRequestHandler):
    def log_message(self,*args):
        pass
    def do_GET(self):
        if self.path != "/v1/models":
            self.send_response(404); self.end_headers(); return
        body=json.dumps({"object":"list","data":[{"id":"sol","object":"model"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_response(404); self.end_headers(); return
        n=int(self.headers.get("Content-Length","0"))
        req=json.loads(self.rfile.read(n))
        assert req["model"]=="sol"
        assert req["stream"] is False
        assert req["messages"][0]["content"]=="package connector test"
        body=json.dumps({
            "id":"mock",
            "object":"chat.completion",
            "choices":[{"index":0,"message":{"role":"assistant","content":"mock-sol-ok"}}]
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)

srv=ThreadingHTTPServer(("127.0.0.1",0),H)
port=srv.server_address[1]
thread=threading.Thread(target=srv.serve_forever,daemon=True)
thread.start()
endpoint=f"http://127.0.0.1:{port}/v1"

try:
    p=subprocess.run([str(BIN),"health","--endpoint",endpoint,"--model","sol"],
                     text=True,capture_output=True,timeout=10)
    ok(p.returncode==0,"health return")
    h=json.loads(p.stdout)
    ok(h["status"]=="OK","health status")
    ok(h["model"]=="sol","health model")
    ok(h["transport"]=="LOOPBACK_ONLY","health transport")
    ok(h["memory_authority"] is False,"health memory authority")

    p=subprocess.run([str(BIN),"chat","--endpoint",endpoint,"--model","sol"],
                     input="package connector test",text=True,capture_output=True,timeout=10)
    ok(p.returncode==0,"chat return")
    c=json.loads(p.stdout)
    ok(c["content"]=="mock-sol-ok","chat content")
    ok(c["memory_authority"] is False,"chat memory authority")

    p=subprocess.run([str(BIN),"health","--endpoint",endpoint,"--model","missing"],
                     text=True,capture_output=True,timeout=10)
    ok(p.returncode==2 and "REQUESTED_MODEL_NOT_FOUND" in p.stderr,
       "missing model rejected")

    p=subprocess.run([str(BIN),"health","--endpoint","http://192.0.2.1:8080/v1","--model","sol"],
                     text=True,capture_output=True,timeout=10)
    ok(p.returncode==2 and "NON_LOOPBACK_ENDPOINT_REJECTED" in p.stderr,
       "non-loopback rejected")

    p=subprocess.run([str(BIN),"chat","--endpoint",endpoint,"--model","sol"],
                     input="",text=True,capture_output=True,timeout=10)
    ok(p.returncode==2 and "PROMPT_REQUIRED_ON_STDIN" in p.stderr,
       "empty prompt rejected")
finally:
    srv.shutdown()
    srv.server_close()

print(f"PASS_PCMF_LOCAL_LLAMA_CONNECTOR checks={checks} model=sol transport=LOOPBACK_ONLY memory_authority=false")
