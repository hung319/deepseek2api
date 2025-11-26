import base64
import ctypes
import json
import logging
import queue
import random
import re
import struct
import threading
import time
import os
import sys
from typing import Optional, List

# Load environment variables
from dotenv import load_dotenv
import transformers
from curl_cffi import requests
from fastapi import FastAPI, HTTPException, Request, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from wasmtime import Linker, Module, Store

# -------------------------- Cấu hình Environment --------------------------
load_dotenv()

SERVER_PORT = int(os.getenv("PORT", 5001))
SERVER_API_KEYS = os.getenv("SERVER_API_KEYS", "").split(",")
PROXY_URL = os.getenv("PROXY_URL", None)
ACCOUNTS_JSON = os.getenv("DEEPSEEK_ACCOUNTS", "[]")

try:
    ACCOUNTS_LIST = json.loads(ACCOUNTS_JSON)
except json.JSONDecodeError:
    print("Lỗi: DEEPSEEK_ACCOUNTS trong .env không đúng định dạng JSON.")
    ACCOUNTS_LIST = []

# -------------------------- Khởi tạo Tokenizer & Logger --------------------------
# Lưu ý: Cần folder tokenizer hoặc set path đúng
chat_tokenizer_dir = "./" 
try:
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        chat_tokenizer_dir, trust_remote_code=True
    )
except Exception as e:
    print(f"Warning: Không load được tokenizer từ {chat_tokenizer_dir}. Token count có thể không chính xác. {e}")

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("DeepSeek-Proxy")

app = FastAPI(docs_url=None, redoc_url=None) # Tắt docs mặc định để ẩn danh

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# -------------------------- Quản lý tài khoản Global --------------------------
account_queue = []

def init_account_queue():
    global account_queue
    # Load từ env, gán token rỗng nếu chưa có
    raw_accounts = ACCOUNTS_LIST[:]
    for acc in raw_accounts:
        if "token" not in acc:
            acc["token"] = ""
    account_queue = raw_accounts
    random.shuffle(account_queue)
    logger.info(f"Đã load {len(account_queue)} tài khoản.")

init_account_queue()

# -------------------------- DeepSeek Constants --------------------------
DEEPSEEK_HOST = "chat.deepseek.com"
DEEPSEEK_LOGIN_URL = f"https://{DEEPSEEK_HOST}/api/v0/users/login"
DEEPSEEK_CREATE_SESSION_URL = f"https://{DEEPSEEK_HOST}/api/v0/chat_session/create"
DEEPSEEK_CREATE_POW_URL = f"https://{DEEPSEEK_HOST}/api/v0/chat/create_pow_challenge"
DEEPSEEK_COMPLETION_URL = f"https://{DEEPSEEK_HOST}/api/v0/chat/completion"

BASE_HEADERS = {
    "Host": DEEPSEEK_HOST,
    "User-Agent": "DeepSeek/1.0.13 Android/35",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/json",
    "x-client-platform": "android",
    "x-client-version": "1.3.0-auto-resume",
    "x-client-locale": "zh_CN",
    "accept-charset": "UTF-8",
}

WASM_PATH = "sha3_wasm_bg.7b9ca65ddd.wasm"
KEEP_ALIVE_TIMEOUT = 5

# -------------------------- Helper Functions --------------------------

def get_proxy_kwargs():
    """Trả về cấu hình proxy cho requests"""
    if PROXY_URL:
        return {"proxies": {"http": PROXY_URL, "https": PROXY_URL}}
    return {}

def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Middleware kiểm tra API Key từ Client"""
    token = credentials.credentials
    # Nếu không set key trong env thì cho qua (dev mode), ngược lại check list
    if SERVER_API_KEYS and SERVER_API_KEYS != [""]:
        if token not in SERVER_API_KEYS:
            raise HTTPException(status_code=401, detail="Invalid API Key")
    return token

def get_account_identifier(account):
    return account.get("email", "").strip() or account.get("mobile", "").strip()

# -------------------------- Logic Login & Account --------------------------

def login_deepseek_via_account(account):
    email = account.get("email", "").strip()
    mobile = account.get("mobile", "").strip()
    password = account.get("password", "").strip()
    
    if not password or (not email and not mobile):
        raise HTTPException(status_code=400, detail="Account config error in .env")

    payload = {
        "password": password,
        "device_id": "deepseek_to_api",
        "os": "android"
    }
    
    if email:
        payload["email"] = email
    else:
        payload["mobile"] = mobile
        payload["area_code"] = None

    try:
        resp = requests.post(
            DEEPSEEK_LOGIN_URL, 
            headers=BASE_HEADERS, 
            json=payload, 
            impersonate="safari15_3",
            **get_proxy_kwargs() # Thêm Proxy
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.error(f"[Login] Lỗi login: {e}")
        raise HTTPException(status_code=500, detail="Login failed upstream")

    try:
        new_token = data["data"]["biz_data"]["user"]["token"]
        account["token"] = new_token
        # Lưu ý: Token chỉ lưu trong RAM, restart server sẽ login lại.
        # Nếu muốn lưu file, cần logic ghi file riêng, tránh ghi đè .env
        return new_token
    except Exception as e:
        logger.error(f"[Login] Parse response failed: {data}")
        raise HTTPException(status_code=500, detail="Invalid login response")

def choose_account(exclude_ids=None):
    if exclude_ids is None:
        exclude_ids = []
    
    for i in range(len(account_queue)):
        acc = account_queue[i]
        acc_id = get_account_identifier(acc)
        if acc_id and acc_id not in exclude_ids:
            # Move to end of queue (Simple Round Robin)
            account_queue.pop(i)
            account_queue.append(acc)
            return acc
            
    logger.warning("[Account] No available accounts")
    return None

def get_valid_token(request: Request):
    """
    Lấy token hợp lệ của DeepSeek.
    Logic: Client gọi API -> Server chọn Acc -> Login (nếu cần) -> Trả về Token DeepSeek
    """
    if not hasattr(request.state, "tried_accounts"):
        request.state.tried_accounts = []
        
    account = choose_account(request.state.tried_accounts)
    if not account:
         raise HTTPException(status_code=429, detail="No accounts available or all busy.")
    
    request.state.account = account
    request.state.tried_accounts.append(get_account_identifier(account))
    
    token = account.get("token")
    if not token:
        token = login_deepseek_via_account(account)
    
    return token

def get_auth_headers(token):
    return {**BASE_HEADERS, "authorization": f"Bearer {token}"}

# -------------------------- PoW & WASM --------------------------
# Giữ nguyên logic WASM phức tạp để tính Proof of Work
def compute_pow_answer(algorithm, challenge_str, salt, difficulty, expire_at, signature, target_path, wasm_path):
    if algorithm != "DeepSeekHashV1":
        return None
        
    prefix = f"{salt}_{expire_at}_"
    store = Store()
    linker = Linker(store.engine)
    
    try:
        with open(wasm_path, "rb") as f:
            wasm_bytes = f.read()
    except Exception as e:
        logger.error(f"WASM load error: {e}")
        return None
        
    module = Module(store.engine, wasm_bytes)
    instance = linker.instantiate(store, module)
    exports = instance.exports(store)
    
    memory = exports["memory"]
    add_to_stack = exports["__wbindgen_add_to_stack_pointer"]
    alloc = exports["__wbindgen_export_0"]
    wasm_solve = exports["wasm_solve"]

    def write_memory(offset, data):
        base_addr = ctypes.cast(memory.data_ptr(store), ctypes.c_void_p).value
        ctypes.memmove(base_addr + offset, data, len(data))

    def read_memory(offset, size):
        base_addr = ctypes.cast(memory.data_ptr(store), ctypes.c_void_p).value
        return ctypes.string_at(base_addr + offset, size)

    def encode_string(text):
        data = text.encode("utf-8")
        length = len(data)
        ptr_val = alloc(store, length, 1)
        ptr = int(ptr_val.value) if hasattr(ptr_val, "value") else int(ptr_val)
        write_memory(ptr, data)
        return ptr, length

    retptr = add_to_stack(store, -16)
    ptr_challenge, len_challenge = encode_string(challenge_str)
    ptr_prefix, len_prefix = encode_string(prefix)
    
    wasm_solve(store, retptr, ptr_challenge, len_challenge, ptr_prefix, len_prefix, float(difficulty))
    
    status = struct.unpack("<i", read_memory(retptr, 4))[0]
    value = struct.unpack("<d", read_memory(retptr + 8, 8))[0]
    add_to_stack(store, 16)
    
    return int(value) if status != 0 else None

def get_pow_response(token, max_attempts=3):
    headers = get_auth_headers(token)
    for _ in range(max_attempts):
        try:
            resp = requests.post(
                DEEPSEEK_CREATE_POW_URL,
                headers=headers,
                json={"target_path": "/api/v0/chat/completion"},
                timeout=30,
                impersonate="safari15_3",
                **get_proxy_kwargs()
            )
            data = resp.json()
            if data.get("code") == 0:
                c = data["data"]["biz_data"]["challenge"]
                answer = compute_pow_answer(
                    c["algorithm"], c["challenge"], c["salt"], 
                    c.get("difficulty", 144000), c.get("expire_at", 1680000000), 
                    c["signature"], c["target_path"], WASM_PATH
                )
                if answer:
                    pow_dict = {
                        "algorithm": c["algorithm"],
                        "challenge": c["challenge"],
                        "salt": c["salt"],
                        "answer": answer,
                        "signature": c["signature"],
                        "target_path": c["target_path"],
                    }
                    pow_str = json.dumps(pow_dict, separators=(",", ":"), ensure_ascii=False)
                    return base64.b64encode(pow_str.encode("utf-8")).decode("utf-8").rstrip()
        except Exception as e:
            logger.warning(f"[PoW] Error: {e}")
            time.sleep(1)
    return None

def create_session(token, max_attempts=3):
    headers = get_auth_headers(token)
    for _ in range(max_attempts):
        try:
            resp = requests.post(
                DEEPSEEK_CREATE_SESSION_URL, 
                headers=headers, 
                json={"agent": "chat"}, 
                impersonate="safari15_3",
                **get_proxy_kwargs()
            )
            data = resp.json()
            if data.get("code") == 0:
                return data["data"]["biz_data"]["id"]
        except Exception as e:
            logger.warning(f"[Session] Error: {e}")
        time.sleep(1)
    return None

# -------------------------- Helpers --------------------------

def messages_prepare(messages: list) -> str:
    # Logic gộp message, thêm tag (Assistant/User) giống file gốc
    processed = []
    for m in messages:
        role = m.get("role", "")
        content = m.get("content", "")
        if isinstance(content, list):
            text = "\n".join([item.get("text", "") for item in content if item.get("type") == "text"])
        else:
            text = str(content)
        processed.append({"role": role, "text": text})

    if not processed: return ""
    
    merged = [processed[0]]
    for msg in processed[1:]:
        if msg["role"] == merged[-1]["role"]:
            merged[-1]["text"] += "\n\n" + msg["text"]
        else:
            merged.append(msg)
            
    parts = []
    for idx, block in enumerate(merged):
        role = block["role"]
        text = block["text"]
        if role == "assistant":
            parts.append(f"<｜Assistant｜>{text}<｜end of sentence｜>")
        elif role in ("user", "system"):
            if idx > 0:
                parts.append(f"<｜User｜>{text}")
            else:
                parts.append(text)
        else:
            parts.append(text)
            
    final = "".join(parts)
    # Remove markdown images
    return re.sub(r"!\[(.*?)\]\((.*?)\)", r"[\1](\2)", final)

# -------------------------- Endpoints --------------------------

@app.get("/v1/models")
async def list_models(api_key: str = Depends(verify_api_key)):
    # Trả về danh sách model giả lập OpenAI
    current_time = int(time.time())
    models = [
        {"id": "deepseek-chat", "object": "model", "created": current_time, "owned_by": "deepseek"},
        {"id": "deepseek-reasoner", "object": "model", "created": current_time, "owned_by": "deepseek"},
    ]
    return JSONResponse(content={"object": "list", "data": models})

@app.post("/v1/chat/completions")
async def chat_completions(request: Request, api_key: str = Depends(verify_api_key)):
    try:
        req_data = await request.json()
        model = req_data.get("model", "deepseek-chat")
        messages = req_data.get("messages", [])
        stream = req_data.get("stream", False)

        # 1. Config Model
        model_lower = model.lower()
        thinking_enabled = False
        search_enabled = False
        
        if "reasoner" in model_lower or "r1" in model_lower:
            thinking_enabled = True
        if "search" in model_lower:
            search_enabled = True

        # 2. Prepare DeepSeek Auth & Context
        ds_token = get_valid_token(request) # Sẽ retry/re-login nếu cần
        session_id = create_session(ds_token)
        pow_resp = get_pow_response(ds_token)
        
        if not session_id or not pow_resp:
            # Nếu auth lỗi, có thể do token hết hạn, ở đây đơn giản báo lỗi
            # Trong thực tế nên trigger re-login và retry
            raise HTTPException(status_code=500, detail="DeepSeek upstream auth failed")

        # 3. Request Upstream
        final_prompt = messages_prepare(messages)
        headers = {**get_auth_headers(ds_token), "x-ds-pow-response": pow_resp}
        payload = {
            "chat_session_id": session_id,
            "parent_message_id": None,
            "prompt": final_prompt,
            "ref_file_ids": [],
            "thinking_enabled": thinking_enabled,
            "search_enabled": search_enabled,
        }

        # Gọi request (có retry logic đơn giản)
        ds_resp = None
        for _ in range(3):
            try:
                ds_resp = requests.post(
                    DEEPSEEK_COMPLETION_URL, headers=headers, json=payload, stream=True, 
                    impersonate="safari15_3", **get_proxy_kwargs()
                )
                if ds_resp.status_code == 200: break
            except Exception:
                time.sleep(1)
        
        if not ds_resp or ds_resp.status_code != 200:
            raise HTTPException(status_code=502, detail="DeepSeek API error")

        # 4. Response Handling
        created = int(time.time())
        chat_id = f"chatcmpl-{session_id}"

        if stream:
            return StreamingResponse(
                stream_generator(ds_resp, model, chat_id, created, thinking_enabled),
                media_type="text/event-stream"
            )
        else:
            return await handle_non_stream(ds_resp, model, chat_id, created, thinking_enabled)

    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error in chat_completions: {e}")
        return JSONResponse(status_code=500, content={"error": {"message": str(e)}})

# Logic xử lý stream đã được tách gọn
def stream_generator(response, model, chat_id, created, thinking_enabled):
    last_send = time.time()
    
    yield f"data: {json.dumps({'id': chat_id, 'model': model, 'choices': [{'index': 0, 'delta': {'role': 'assistant'}, 'finish_reason': None}]})}\n\n"

    try:
        for line in response.iter_lines():
            if not line: continue
            line = line.decode('utf-8')
            if not line.startswith("data:"): continue
            
            data_str = line[5:].strip()
            if data_str == "[DONE]": break
            
            try:
                chunk = json.loads(data_str)
                content = ""
                msg_type = "text" # text or thinking
                
                # Parse v/p format of DeepSeek
                if "v" in chunk:
                    val = chunk["v"]
                    if isinstance(val, list): # Check finish status
                        for item in val:
                            if item.get("p") == "status" and item.get("v") == "FINISHED":
                                yield f"data: {json.dumps({'id': chat_id, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]})}\n\n"
                                yield "data: [DONE]\n\n"
                                return
                    elif isinstance(val, str):
                        content = val
                        p = chunk.get("p", "")
                        if p == "response/thinking_content":
                            msg_type = "thinking"
                        elif p == "response/search_status":
                            continue # Skip search logs
                        
                        # Output OpenAI Delta
                        delta = {}
                        if msg_type == "thinking" and thinking_enabled:
                            delta["reasoning_content"] = content
                        elif msg_type == "text":
                            delta["content"] = content
                            
                        if delta:
                            out = {
                                "id": chat_id,
                                "object": "chat.completion.chunk",
                                "created": created,
                                "model": model,
                                "choices": [{"index": 0, "delta": delta, "finish_reason": None}]
                            }
                            yield f"data: {json.dumps(out)}\n\n"
                            
            except Exception:
                continue
                
            # Keep-alive
            if time.time() - last_send > KEEP_ALIVE_TIMEOUT:
                yield ": keep-alive\n\n"
                last_send = time.time()
                
    finally:
        response.close()

async def handle_non_stream(response, model, chat_id, created, thinking_enabled):
    full_text = ""
    full_think = ""
    
    try:
        for line in response.iter_lines():
            line = line.decode('utf-8')
            if not line.startswith("data:") or "[DONE]" in line: continue
            try:
                chunk = json.loads(line[5:].strip())
                if "v" in chunk and isinstance(chunk["v"], str):
                    p = chunk.get("p", "")
                    if p == "response/content":
                        full_text += chunk["v"]
                    elif p == "response/thinking_content":
                        full_think += chunk["v"]
            except: pass
            
        result = {
            "id": chat_id,
            "object": "chat.completion",
            "created": created,
            "model": model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": full_text,
                    "reasoning_content": full_think if thinking_enabled else None
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0} # Dummy usage
        }
        return JSONResponse(content=result)
    finally:
        response.close()

if __name__ == "__main__":
    import uvicorn
    print(f"Server starting on port {SERVER_PORT}...")
    uvicorn.run(app, host="0.0.0.0", port=SERVER_PORT)
