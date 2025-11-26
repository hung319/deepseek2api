import os
import json
import time
import uuid
import random
import logging
import struct
import base64
import ctypes
import asyncio
from typing import List, Optional, Any, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from curl_cffi import requests
from wasmtime import Linker, Module, Store, Engine

# --- 1. CONFIG & INIT ---
load_dotenv()

# Cấu hình Log gọn gàng
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DeepSeekProxy")

class Config:
    ACCOUNTS = json.loads(os.getenv("DS_ACCOUNTS", "[]"))
    API_KEY = os.getenv("PROXY_API_KEY", "sk-default-key")
    PROXY = os.getenv("PROXY_URL", None)
    WASM_PATH = "sha3_wasm_bg.7b9ca65ddd.wasm" # File gốc bắt buộc phải có

# Security Scheme
security_scheme = HTTPBearer()

async def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security_scheme)):
    if credentials.credentials != Config.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return credentials.credentials

# --- 2. MODELS (OpenAI Standard) ---
class Message(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str = "deepseek-chat"
    messages: List[Message]
    stream: bool = False
    temperature: Optional[float] = None
    presence_penalty: Optional[float] = 0
    frequency_penalty: Optional[float] = 0

# --- 3. CORE LOGIC: WASM / PoW (Giữ nguyên logic gốc) ---
class PoWManager:
    def __init__(self, wasm_path: str):
        self.ready = False
        if not os.path.exists(wasm_path):
            logger.error(f"❌ File WASM không tồn tại: {wasm_path}")
            return
        
        try:
            self.engine = Engine()
            self.linker = Linker(self.engine)
            self.linker.define_func("env", "emscripten_notify_memory_growth", lambda x: None)
            
            with open(wasm_path, "rb") as f:
                self.module = Module(self.engine, f.read())
            
            self.ready = True
            logger.info("✅ WASM Module loaded.")
        except Exception as e:
            logger.error(f"❌ Lỗi load WASM: {e}")

    def compute_answer(self, challenge_str: str, salt: str, difficulty: float, expire_at: int) -> Optional[int]:
        """Logic giải đố DeepSeek (Sử dụng ctypes thao tác memory WASM)"""
        if not self.ready: return None

        store = Store(self.engine)
        try:
            instance = self.linker.instantiate(store, self.module)
            exports = instance.exports(store)
            
            memory = exports["memory"]
            add_to_stack = exports["__wbindgen_add_to_stack_pointer"]
            alloc = exports["__wbindgen_export_0"]
            wasm_solve = exports["wasm_solve"]

            # Helpers thao tác memory
            def get_mem_ptr():
                return ctypes.cast(memory.data_ptr(store), ctypes.c_void_p).value

            def encode_string(text: str):
                data = text.encode("utf-8")
                length = len(data)
                ptr = alloc(store, length, 1)
                base = get_mem_ptr()
                ctypes.memmove(base + ptr, data, length)
                return ptr, length

            # Prepare Inputs
            prefix = f"{salt}_{expire_at}_"
            retptr = add_to_stack(store, -16)
            
            ptr_c, len_c = encode_string(challenge_str)
            ptr_p, len_p = encode_string(prefix)

            # Solve
            wasm_solve(store, retptr, ptr_c, len_c, ptr_p, len_p, float(difficulty))

            # Read Result
            base = get_mem_ptr()
            status = struct.unpack("<i", ctypes.string_at(base + retptr, 4))[0]
            value = struct.unpack("<d", ctypes.string_at(base + retptr + 8, 8))[0]

            add_to_stack(store, 16) # Cleanup

            if status == 0: return None
            return int(value)

        except Exception as e:
            logger.error(f"PoW Error: {e}")
            return None

# Khởi tạo PoW Global
pow_manager = PoWManager(Config.WASM_PATH)

# --- 4. ACCOUNT & SESSION LOGIC ---
class SessionManager:
    def __init__(self):
        self.queue = []
        self.sessions = {}
        
        if not Config.ACCOUNTS:
            logger.warning("⚠️ Chưa cấu hình tài khoản trong .env!")

        for acc in Config.ACCOUNTS:
            email = acc.get("email")
            self.queue.append(email)
            self.sessions[email] = {
                "config": acc,
                "token": None,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }

    def login(self, email: str) -> bool:
        session = self.sessions[email]
        logger.info(f"🔄 Đang đăng nhập lại: {email}")
        
        try:
            url = "https://chat.deepseek.com/api/v0/users/login"
            payload = {"email": session["config"]["email"], "password": session["config"]["password"]}
            
            r = requests.post(
                url, json=payload, impersonate="chrome120",
                proxies={"https": Config.PROXY} if Config.PROXY else None
            )
            
            if r.status_code == 200 and "token" in r.text:
                data = r.json()
                # Cấu trúc JSON DeepSeek có thể thay đổi, cần linh hoạt
                token = data.get("data", {}).get("biz_data", {}).get("user", {}).get("token") or \
                        data.get("data", {}).get("token")
                
                if token:
                    session["token"] = token
                    logger.info(f"✅ Đăng nhập thành công: {email}")
                    return True
            
            logger.error(f"❌ Đăng nhập thất bại {email}: {r.text}")
        except Exception as e:
            logger.error(f"❌ Exception Login {email}: {e}")
        return False

    def get_session(self):
        if not self.queue: raise HTTPException(500, "No accounts available")
        
        # Round Robin
        email = self.queue.pop(0)
        self.queue.append(email)
        
        sess = self.sessions[email]
        if not sess["token"]:
            if not self.login(email):
                raise HTTPException(502, "Upstream login failed")
        return sess

session_manager = SessionManager()

# --- 5. FASTAPI APP ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Server Starting...")
    yield
    logger.info("🛑 Server Stopping...")

app = FastAPI(title="DeepSeek OpenAI API", version="2.0", lifespan=lifespan, docs_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 6. ENDPOINTS (OpenAI Only) ---

@app.get("/v1/models")
async def list_models():
    return {
        "object": "list",
        "data": [
            {"id": "deepseek-chat", "object": "model", "created": 1677610602, "owned_by": "deepseek"},
            {"id": "deepseek-reasoner", "object": "model", "created": 1677610602, "owned_by": "deepseek"},
        ]
    }

@app.post("/v1/chat/completions", dependencies=[Depends(verify_api_key)])
async def chat_completions(req: ChatCompletionRequest):
    session = session_manager.get_session()
    
    headers = {
        "Authorization": f"Bearer {session['token']}",
        "User-Agent": session['user_agent'],
        "Content-Type": "application/json",
        "X-App-Version": "20240125.0", # Giả lập version app
    }

    # 1. PoW Challenge (Nếu cần)
    try:
        pow_req = requests.post(
            "https://chat.deepseek.com/api/v0/chat/create_pow_challenge",
            json={"target_path": "/api/v0/chat/completion"},
            headers=headers, impersonate="chrome120",
            proxies={"https": Config.PROXY} if Config.PROXY else None
        )
        if pow_req.status_code == 200:
            c_data = pow_req.json().get("data", {}).get("biz_data", {}).get("challenge")
            if c_data:
                ans = pow_manager.compute_answer(
                    c_data["challenge"], c_data["salt"], 
                    c_data["difficulty"], c_data["expire_at"]
                )
                if ans:
                    resp_json = {
                        "algorithm": c_data["algorithm"],
                        "challenge": c_data["challenge"],
                        "salt": c_data["salt"],
                        "answer": ans,
                        "signature": c_data["signature"],
                        "target_path": c_data["target_path"]
                    }
                    pow_str = base64.b64encode(json.dumps(resp_json).encode()).decode().rstrip()
                    headers["x-ds-pow-response"] = pow_str
    except Exception as e:
        logger.warning(f"PoW warning: {e}")

    # 2. Tạo Session ID (Bắt buộc với DeepSeek Web)
    try:
        s_resp = requests.post(
            "https://chat.deepseek.com/api/v0/chat_session/create",
            json={"agent": "chat"}, headers=headers, impersonate="chrome120",
            proxies={"https": Config.PROXY} if Config.PROXY else None
        )
        chat_session_id = s_resp.json()["data"]["biz_data"]["id"]
    except:
        chat_session_id = None # Có thể fail nếu token die

    # 3. Chuẩn bị Payload DeepSeek
    # Gom lịch sử chat thành một prompt string (Cách đơn giản nhất cho Web API)
    # Hoặc convert message struct nếu API hỗ trợ. Dưới đây là cách gom text an toàn:
    full_prompt = ""
    for msg in req.messages:
        role = "User" if msg.role == "user" else "Assistant"
        if msg.role == "system": role = "System"
        full_prompt += f"\n\n{role}: {msg.content}"
    full_prompt += "\n\nAssistant:"

    payload = {
        "chat_session_id": chat_session_id,
        "parent_message_id": None,
        "prompt": full_prompt.strip(),
        "stream": True,
        "ref_file_ids": [],
        "thinking_enabled": False, # Bật nếu muốn model R1
        "search_enabled": False
    }

    # 4. Request Upstream
    try:
        r = requests.post(
            "https://chat.deepseek.com/api/v0/chat/completion",
            json=payload, headers=headers, impersonate="chrome120", stream=True,
            proxies={"https": Config.PROXY} if Config.PROXY else None
        )
    except Exception as e:
        raise HTTPException(502, f"Upstream connect error: {e}")

    # 5. Stream Converter (DeepSeek -> OpenAI)
    async def openai_stream():
        chat_id = f"chatcmpl-{uuid.uuid4()}"
        created = int(time.time())
        
        for line in r.iter_lines():
            if not line: continue
            line = line.decode('utf-8')
            if not line.startswith("data: "): continue
            
            txt = line[6:].strip()
            if txt == "[DONE]":
                yield "data: [DONE]\n\n"
                break
            
            try:
                data = json.loads(txt)
                # Parse content từ DeepSeek structure
                content = ""
                choices = data.get("choices", [])
                if choices:
                    content = choices[0].get("delta", {}).get("content", "")
                
                # Format OpenAI Chunk
                if content:
                    chunk = {
                        "id": chat_id, "object": "chat.completion.chunk",
                        "created": created, "model": req.model,
                        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}]
                    }
                    yield f"data: {json.dumps(chunk)}\n\n"
            except: pass

    if req.stream:
        return StreamingResponse(openai_stream(), media_type="text/event-stream")
    
    # Non-stream handling (Fake it by consuming stream)
    full_text = ""
    async for chunk in openai_stream():
        if "[DONE]" in chunk: break
        try:
            j = json.loads(chunk[6:])
            full_text += j["choices"][0]["delta"]["content"]
        except: pass

    return {
        "id": f"chatcmpl-{uuid.uuid4()}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": full_text}, "finish_reason": "stop"}]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5001)
