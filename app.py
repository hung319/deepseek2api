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
# --- FIX: Import thêm FuncType và ValType ---
from wasmtime import Linker, Module, Store, Engine, FuncType, ValType

# --- 1. CONFIG & INIT ---
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DeepSeekProxy")

class Config:
    ACCOUNTS = json.loads(os.getenv("DS_ACCOUNTS", "[]"))
    API_KEY = os.getenv("PROXY_API_KEY", "sk-default-key")
    PROXY = os.getenv("PROXY_URL", None)
    WASM_PATH = "sha3_wasm_bg.7b9ca65ddd.wasm"

# Security
security_scheme = HTTPBearer()

async def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security_scheme)):
    if credentials.credentials != Config.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return credentials.credentials

# --- 2. MODELS ---
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

# --- 3. CORE LOGIC: WASM / PoW (FIXED) ---
class PoWManager:
    def __init__(self, wasm_path: str):
        self.ready = False
        if not os.path.exists(wasm_path):
            logger.error(f"❌ File WASM không tồn tại: {wasm_path}")
            return
        
        try:
            self.engine = Engine()
            self.linker = Linker(self.engine)
            
            # --- FIX: Định nghĩa hàm Import với Type rõ ràng ---
            # Hàm: emscripten_notify_memory_growth(index: i32) -> void
            func_type = FuncType([ValType.i32()], []) 
            
            # Define func: (module, name, type, callback)
            # Callback nhận (caller, arg1) hoặc (*args) tuỳ version, dùng *args cho an toàn
            self.linker.define_func("env", "emscripten_notify_memory_growth", func_type, lambda *args: None)
            
            with open(wasm_path, "rb") as f:
                self.module = Module(self.engine, f.read())
            
            self.ready = True
            logger.info("✅ WASM Module loaded successfully.")
        except Exception as e:
            logger.error(f"❌ Lỗi load WASM: {e}")

    def compute_answer(self, challenge_str: str, salt: str, difficulty: float, expire_at: int) -> Optional[int]:
        if not self.ready: return None

        store = Store(self.engine)
        try:
            instance = self.linker.instantiate(store, self.module)
            exports = instance.exports(store)
            
            memory = exports["memory"]
            add_to_stack = exports["__wbindgen_add_to_stack_pointer"]
            alloc = exports["__wbindgen_export_0"]
            wasm_solve = exports["wasm_solve"]

            def get_mem_ptr():
                return ctypes.cast(memory.data_ptr(store), ctypes.c_void_p).value

            def encode_string(text: str):
                data = text.encode("utf-8")
                length = len(data)
                ptr = alloc(store, length, 1)
                base = get_mem_ptr()
                ctypes.memmove(base + ptr, data, length)
                return ptr, length

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

            add_to_stack(store, 16)

            if status == 0: return None
            return int(value)

        except Exception as e:
            logger.error(f"PoW Runtime Error: {e}")
            return None

pow_manager = PoWManager(Config.WASM_PATH)

# --- 4. SESSION MANAGER ---
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
            
            # --- FIX: Thêm device_id và os ---
            payload = {
                "email": session["config"]["email"], 
                "password": session["config"]["password"],
                "device_id": str(uuid.uuid4()),  # Tạo UUID ngẫu nhiên cho thiết bị
                "os": "web"                      # Khai báo là nền tảng Web
            }
            
            # Hỗ trợ trường hợp login bằng mobile (nếu config có)
            if "mobile" in session["config"] and not session["config"].get("email"):
                 payload = {
                    "mobile": session["config"]["mobile"], 
                    "password": session["config"]["password"],
                    "area_code": "+86",
                    "device_id": str(uuid.uuid4()),
                    "os": "web"
                 }
            
            r = requests.post(
                url, json=payload, impersonate="chrome120",
                proxies={"https": Config.PROXY} if Config.PROXY else None
            )
            
            if r.status_code == 200:
                data = r.json()
                token = None
                # DeepSeek json structure parsing
                if "data" in data:
                    if "biz_data" in data["data"] and "user" in data["data"]["biz_data"]:
                        token = data["data"]["biz_data"]["user"]["token"]
                    elif "token" in data["data"]:
                        token = data["data"]["token"]
                
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
        email = self.queue.pop(0)
        self.queue.append(email)
        sess = self.sessions[email]
        if not sess["token"]:
            if not self.login(email):
                raise HTTPException(502, "Upstream login failed")
        return sess

session_manager = SessionManager()

# --- HELPER: Format tin nhắn chuẩn DeepSeek ---
def messages_prepare(messages: list) -> str:
    """
    Chuyển đổi list messages thành string format đặc biệt của DeepSeek.
    Logic được port từ file gốc app (2).py
    """
    merged = []
    # 1. Merge các tin nhắn cùng role liên tiếp
    for m in messages:
        role = m.role.lower()
        content = m.content
        
        # Xử lý content là list (trường hợp client gửi multimodal/image)
        if isinstance(content, list):
            texts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    texts.append(item.get("text", ""))
                elif isinstance(item, str):
                    texts.append(item)
            content = "\n".join(texts)
            
        if merged and merged[-1]["role"] == role:
            merged[-1]["content"] += "\n\n" + content
        else:
            merged.append({"role": role, "content": content})

    # 2. Gắn thẻ <｜User｜>, <｜Assistant｜>
    parts = []
    for idx, block in enumerate(merged):
        role = block["role"]
        text = block["content"]
        
        if role == "assistant":
            parts.append(f"<｜Assistant｜>{text}<｜end of sentence｜>")
        elif role in ("user", "system"):
            if idx > 0:
                parts.append(f"<｜User｜>{text}")
            else:
                parts.append(text) # Tin nhắn đầu tiên không cần tag User?
        else:
            parts.append(text)
            
    return "".join(parts)

# --- 5. APP & ROUTES ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Server Starting...")
    yield
    logger.info("🛑 Server Stopping...")

app = FastAPI(title="DeepSeek OpenAI API", version="2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"status": "running", "pow_ready": pow_manager.ready}

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
    request_id = str(uuid.uuid4())[:8] # ID ngắn để trace log
    
    logger.info(f"[{request_id}] 🚀 New Chat Request. Model: {req.model}")

    headers = {
        "Authorization": f"Bearer {session['token']}",
        "User-Agent": session['user_agent'],
        "Content-Type": "application/json",
        "X-App-Version": "20240125.0",
        "Accept": "*/*"
    }
    IMPERSONATE = "safari15_3"

    # --- 1. PoW & Challenge ---
    try:
        pow_req = requests.post(
            "https://chat.deepseek.com/api/v0/chat/create_pow_challenge",
            json={"target_path": "/api/v0/chat/completion"},
            headers=headers, impersonate=IMPERSONATE,
            proxies={"https": Config.PROXY} if Config.PROXY else None,
            timeout=30
        )
        if pow_req.status_code == 200:
            c_data = pow_req.json().get("data", {}).get("biz_data", {}).get("challenge")
            if c_data:
                logger.info(f"[{request_id}] 🧩 Solving PoW Challenge...")
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
                    logger.info(f"[{request_id}] ✅ PoW Solved.")
                else:
                    logger.warning(f"[{request_id}] ⚠️ PoW Solve Failed!")
    except Exception as e:
        logger.warning(f"[{request_id}] PoW Error: {e}")

    # --- 2. Session ID ---
    chat_session_id = None
    try:
        s_resp = requests.post(
            "https://chat.deepseek.com/api/v0/chat_session/create",
            json={"agent": "chat"}, headers=headers, impersonate=IMPERSONATE,
            proxies={"https": Config.PROXY} if Config.PROXY else None,
            timeout=30
        )
        if s_resp.status_code == 200:
            chat_session_id = s_resp.json()["data"]["biz_data"]["id"]
            logger.info(f"[{request_id}] 🆔 Session Created: {chat_session_id}")
        else:
            logger.error(f"[{request_id}] ❌ Session Create Failed: {s_resp.text}")
    except Exception as e:
        logger.error(f"[{request_id}] Session Create Exception: {e}")

    # --- 3. Payload ---
    final_prompt = messages_prepare(req.messages)
    # Log 100 ký tự đầu của prompt để debug format
    logger.info(f"[{request_id}] 📝 Prompt Preview: {final_prompt[:100]}...")

    thinking_enabled = False
    if "reasoner" in req.model or "r1" in req.model:
        thinking_enabled = True
        
    payload = {
        "chat_session_id": chat_session_id,
        "parent_message_id": None,
        "prompt": final_prompt,
        "stream": True,
        "ref_file_ids": [],
        "thinking_enabled": thinking_enabled,
        "search_enabled": False
    }

    # --- 4. Request Upstream ---
    try:
        logger.info(f"[{request_id}] 📡 Sending request to DeepSeek...")
        r = requests.post(
            "https://chat.deepseek.com/api/v0/chat/completion",
            json=payload, headers=headers, impersonate=IMPERSONATE, stream=True,
            proxies={"https": Config.PROXY} if Config.PROXY else None,
            timeout=120
        )
        logger.info(f"[{request_id}] 🔙 Response Status: {r.status_code}")
        
        if r.status_code != 200:
            logger.error(f"[{request_id}] ❌ Error Body: {r.text}")
            raise HTTPException(r.status_code, f"Upstream Error: {r.text}")

    except Exception as e:
        logger.error(f"[{request_id}] 💥 Connection Failed: {e}")
        raise HTTPException(502, f"Upstream connect error: {e}")

    # --- 5. Stream Converter (DEBUG MODE) ---
    async def openai_stream():
        chat_id = f"chatcmpl-{uuid.uuid4()}"
        created = int(time.time())
        line_count = 0
        
        for line in r.iter_lines():
            if not line: continue
            line = line.decode('utf-8')
            
            # LOG 10 dòng đầu tiên để soi dữ liệu
            line_count += 1
            if line_count <= 10:
                logger.info(f"[{request_id}] 📥 Stream Line {line_count}: {line}")

            if not line.startswith("data: "): continue
            
            txt = line[6:].strip()
            if txt == "[DONE]":
                logger.info(f"[{request_id}] ✅ Stream DONE received.")
                yield "data: [DONE]\n\n"
                break
            
            try:
                chunk = json.loads(txt)
                content = ""
                
                # Logic Parse
                if "choices" in chunk:
                    choice = chunk["choices"][0]
                    if choice.get("finish_reason") == "backend_busy":
                        content = " [Server Busy] "
                        logger.warning(f"[{request_id}] ⚠️ Server Busy Signal")
                    else:
                        content = choice.get("delta", {}).get("content", "")
                
                elif "v" in chunk:
                    v_val = chunk.get("v")
                    p_val = chunk.get("p")
                    if isinstance(v_val, str):
                        content = v_val
                        # Log nếu nhận được text thật
                        if line_count <= 20: 
                             logger.info(f"[{request_id}] 🎯 Parsed Content: {content[:20]}...")
                
                if content:
                    resp_chunk = {
                        "id": chat_id, "object": "chat.completion.chunk",
                        "created": created, "model": req.model,
                        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}]
                    }
                    yield f"data: {json.dumps(resp_chunk)}\n\n"
                    
            except Exception as e:
                logger.error(f"[{request_id}] ⚠️ Parse Error: {e} | Line: {line}")
                continue

    if req.stream:
        return StreamingResponse(openai_stream(), media_type="text/event-stream")
    
    # Non-stream
    logger.info(f"[{request_id}] ⚠️ Client requested non-stream mode (simulated)")
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
