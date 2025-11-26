import base64
import ctypes
import json
import logging
import random
import re
import struct
import time
import os
import queue
import threading
import uuid
from dotenv import load_dotenv
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

# -------------------------- Logger --------------------------
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("DeepSeek-Proxy")

app = FastAPI(docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# -------------------------- Helper Token Count --------------------------
def estimate_tokens(text: str) -> int:
    if not text: return 0
    return len(text) // 4

# -------------------------- Quản lý tài khoản --------------------------
account_queue = []

def init_account_queue():
    global account_queue
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
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/json",
    "x-client-platform": "web",
    "x-client-version": "1.5.0",
    "x-client-locale": "en_US",
    "accept-charset": "UTF-8",
    "origin": f"https://{DEEPSEEK_HOST}",
    "referer": f"https://{DEEPSEEK_HOST}/"
}

WASM_PATH = "sha3_wasm_bg.7b9ca65ddd.wasm"
KEEP_ALIVE_TIMEOUT = 5

# -------------------------- Auth & Proxy Helpers --------------------------
def get_proxy_kwargs():
    if PROXY_URL:
        return {"proxies": {"http": PROXY_URL, "https": PROXY_URL}}
    return {}

def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    if SERVER_API_KEYS and SERVER_API_KEYS != [""]:
        if token not in SERVER_API_KEYS:
            raise HTTPException(status_code=401, detail="Invalid API Key")
    return token

def get_account_identifier(account):
    return account.get("email", "").strip() or account.get("mobile", "").strip()

# -------------------------- Logic DeepSeek --------------------------
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
            DEEPSEEK_LOGIN_URL, headers=BASE_HEADERS, json=payload, impersonate="safari15_3", **get_proxy_kwargs()
        )
        resp.raise_for_status()
        data = resp.json()
        new_token = data["data"]["biz_data"]["user"]["token"]
        account["token"] = new_token
        return new_token
    except Exception as e:
        logger.error(f"[Login] Failed: {e}")
        raise HTTPException(status_code=500, detail="Login failed upstream")

def get_valid_token(request: Request):
    if not hasattr(request.state, "tried_accounts"):
        request.state.tried_accounts = []
    
    available_accounts = [acc for acc in account_queue if get_account_identifier(acc) not in request.state.tried_accounts]
    if not available_accounts:
         request.state.tried_accounts = []
         available_accounts = account_queue
    
    if not available_accounts:
        raise HTTPException(status_code=429, detail="No accounts configured.")

    account = available_accounts[0]
    request.state.account = account
    request.state.tried_accounts.append(get_account_identifier(account))
    
    token = account.get("token")
    if not token:
        token = login_deepseek_via_account(account)
    return token

def get_auth_headers(token):
    return {**BASE_HEADERS, "authorization": f"Bearer {token}"}

# -------------------------- PoW Calculation --------------------------
def compute_pow_answer(algorithm, challenge_str, salt, difficulty, expire_at, signature, target_path, wasm_path):
    if algorithm != "DeepSeekHashV1": return None
    prefix = f"{salt}_{expire_at}_"
    store = Store()
    linker = Linker(store.engine)
    try:
        with open(wasm_path, "rb") as f: wasm_bytes = f.read()
    except: return None
        
    module = Module(store.engine, wasm_bytes)
    instance = linker.instantiate(store, module)
    exports = instance.exports(store)
    
    memory = exports["memory"]
    add_to_stack = exports["__wbindgen_add_to_stack_pointer"]
    alloc = exports["__wbindgen_export_0"]
    wasm_solve = exports["wasm_solve"]

    def write_mem(offset, data):
        ctypes.memmove(ctypes.cast(memory.data_ptr(store), ctypes.c_void_p).value + offset, data, len(data))

    def read_mem(offset, size):
        return ctypes.string_at(ctypes.cast(memory.data_ptr(store), ctypes.c_void_p).value + offset, size)

    def encode(text):
        data = text.encode("utf-8")
        ptr = int(alloc(store, len(data), 1))
        write_mem(ptr, data)
        return ptr, len(data)

    retptr = add_to_stack(store, -16)
    ptr_c, len_c = encode(challenge_str)
    ptr_p, len_p = encode(prefix)
    wasm_solve(store, retptr, ptr_c, len_c, ptr_p, len_p, float(difficulty))
    
    status = struct.unpack("<i", read_mem(retptr, 4))[0]
    val = struct.unpack("<d", read_mem(retptr + 8, 8))[0]
    add_to_stack(store, 16)
    return int(val) if status != 0 else None

def get_pow_response(token):
    headers = get_auth_headers(token)
    for _ in range(3):
        try:
            resp = requests.post(
                DEEPSEEK_CREATE_POW_URL, headers=headers, json={"target_path": "/api/v0/chat/completion"},
                timeout=30, impersonate="safari15_3", **get_proxy_kwargs()
            )
            data = resp.json()
            if data.get("code") == 0:
                c = data["data"]["biz_data"]["challenge"]
                ans = compute_pow_answer(
                    c["algorithm"], c["challenge"], c["salt"], c.get("difficulty", 144000),
                    c.get("expire_at", 1680000000), c["signature"], c["target_path"], WASM_PATH
                )
                if ans:
                    pow_data = {
                        "algorithm": c["algorithm"], "challenge": c["challenge"], "salt": c["salt"],
                        "answer": ans, "signature": c["signature"], "target_path": c["target_path"]
                    }
                    return base64.b64encode(json.dumps(pow_data, separators=(",", ":"), ensure_ascii=False).encode()).decode().rstrip()
        except: time.sleep(1)
    return None

def create_session(token):
    headers = get_auth_headers(token)
    for _ in range(3):
        try:
            resp = requests.post(
                DEEPSEEK_CREATE_SESSION_URL, headers=headers, json={"agent": "chat"},
                impersonate="safari15_3", **get_proxy_kwargs()
            )
            if resp.json().get("code") == 0: return resp.json()["data"]["biz_data"]["id"]
        except: time.sleep(1)
    return None

def messages_prepare(messages: list) -> str:
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
    return re.sub(r"!\[(.*?)\]\((.*?)\)", r"[\1](\2)", final)

# -------------------------- Streaming Logic (Advanced Dynamic Parser) --------------------------
def sse_generator(response, model, chat_id, created, thinking_enabled):
    last_send = time.time()
    result_queue = queue.Queue()
    
    # State mapping để biết fragment index nào là THINK, index nào là RESPONSE
    # Mặc định: fragment 0 thường là text, nhưng nếu có think thì fragment 0 là think, fragment 1 là response.
    # Ta sẽ auto-detect dựa vào "type" trong packet khai báo fragment.
    fragment_type_map = {} 

    def reader():
        try:
            for line in response.iter_lines():
                if not line: continue
                line = line.decode('utf-8')
                if not line.startswith("data:"): continue
                
                data_str = line[5:].strip()
                if data_str == "[DONE]":
                    result_queue.put("DONE")
                    break
                
                try:
                    chunk = json.loads(data_str)
                    if "v" not in chunk: continue
                    val = chunk["v"]

                    # ---------------------------------------------------------
                    # 1. Packet quản lý Fragments (Khai báo hoặc Append)
                    # ---------------------------------------------------------
                    if isinstance(val, list):
                        for item in val:
                            # 1.1 Check Finish
                            if item.get("p") == "status" and item.get("v") == "FINISHED":
                                result_queue.put("DONE")
                                return
                            
                            # 1.2 Khai báo Fragment Mới (Dựa vào p="response/fragments" hoặc p="fragments")
                            # DeepSeek gửi: {"v": [{"id": 1, "type": "THINK", ...}], "p": "fragments", "o": "APPEND"}
                            # Hoặc: {"v": [{"id": 2, "type": "RESPONSE", ...}], "p": "response/fragments", "o": "APPEND"}
                            p = item.get("p", "")
                            if (p == "fragments" or p == "response/fragments") and isinstance(item.get("v"), list):
                                for fragment in item["v"]:
                                    # Lấy ID của fragment (trong mảng fragments, id này thường là 1, 2...)
                                    # Nhưng DeepSeek truy cập theo index mảng (0, 1).
                                    # Ta cần map index hiện tại của fragment list với Type.
                                    frag_type = fragment.get("type", "RESPONSE") # THINK hoặc RESPONSE
                                    
                                    # Hack: Đếm số lượng key trong map để đoán index mới
                                    # Nếu đây là fragment đầu tiên -> index 0
                                    # Nếu đã có 1 fragment -> index 1
                                    new_index = len(fragment_type_map)
                                    fragment_type_map[str(new_index)] = frag_type
                                    
                                    # Nếu có content ngay trong khai báo (thường là chữ cái đầu tiên)
                                    if "content" in fragment:
                                        msg_type = "thinking" if frag_type == "THINK" else "text"
                                        result_queue.put({"type": msg_type, "content": fragment["content"]})
                            
                            # 1.3 Trường hợp fragment lồng trong list cha (dạng cũ)
                            if p == "fragments" and isinstance(item.get("v"), list):
                                for fragment in item["v"]:
                                    if "content" in fragment:
                                        # Fallback: Nếu chưa map được type thì đoán dựa vào content hoặc mặc định text
                                        result_queue.put({"type": "text", "content": fragment["content"]})
                        continue

                    # ---------------------------------------------------------
                    # 2. Packet nội dung (String) - Append vào fragment cụ thể
                    # ---------------------------------------------------------
                    if isinstance(val, str):
                        p = chunk.get("p", "") # Ví dụ: "response/fragments/0/content"
                        content = val

                        # Parse path để lấy index: "response/fragments/0/content" -> index = "0"
                        match = re.search(r"fragments/(\d+)/content", p)
                        if match:
                            idx = match.group(1)
                            frag_type = fragment_type_map.get(idx, "RESPONSE") # Default RESPONSE if unknown
                            
                            msg_type = "thinking" if frag_type == "THINK" else "text"
                            result_queue.put({"type": msg_type, "content": content})
                        
                        # Fallback cho path cũ hoặc không có path (mặc định text)
                        elif p == "response/content" or p is None:
                             result_queue.put({"type": "text", "content": content})
                        
                        # Ignore other paths like "response/search_status"
                except Exception as e:
                    continue
        except Exception as e:
            logger.error(f"Stream reader error: {e}")
            result_queue.put("DONE")
        finally:
            response.close()

    threading.Thread(target=reader, daemon=True).start()

    yield f"data: {json.dumps({'id': chat_id, 'model': model, 'choices': [{'index': 0, 'delta': {'role': 'assistant'}, 'finish_reason': None}]})}\n\n"

    while True:
        try:
            item = result_queue.get(timeout=KEEP_ALIVE_TIMEOUT)
            if item == "DONE":
                yield f"data: {json.dumps({'id': chat_id, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]})}\n\n"
                yield "data: [DONE]\n\n"
                break
            
            delta = {}
            if item["type"] == "thinking" and thinking_enabled:
                delta["reasoning_content"] = item["content"]
            elif item["type"] == "text":
                delta["content"] = item["content"]
            
            if delta:
                chunk_data = {
                    "id": chat_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": None}]
                }
                yield f"data: {json.dumps(chunk_data)}\n\n"
                last_send = time.time()
                
        except queue.Empty:
            yield ": keep-alive\n\n"

# -------------------------- Endpoints --------------------------

@app.get("/v1/models")
async def list_models(api_key: str = Depends(verify_api_key)):
    t = int(time.time())
    return JSONResponse(content={"object": "list", "data": [
        {"id": "deepseek-chat", "object": "model", "created": t, "owned_by": "deepseek"},
        {"id": "deepseek-reasoner", "object": "model", "created": t, "owned_by": "deepseek"}
    ]})

@app.post("/v1/chat/completions")
async def chat_completions(request: Request, api_key: str = Depends(verify_api_key)):
    try:
        req = await request.json()
        model = req.get("model", "deepseek-chat")
        messages = req.get("messages", [])
        stream = req.get("stream", False)

        model_lower = model.lower()
        # Auto detect thinking/search based on model name OR explicit param
        thinking = req.get("thinking_enabled", False) or ("reasoner" in model_lower or "r1" in model_lower)
        search = req.get("search_enabled", False) or ("search" in model_lower)

        token = get_valid_token(request)
        session_id = create_session(token)
        pow_resp = get_pow_response(token)
        
        if not session_id or not pow_resp:
            raise HTTPException(status_code=500, detail="DeepSeek auth failed")

        payload = {
            "chat_session_id": session_id,
            "parent_message_id": None,
            "prompt": messages_prepare(messages),
            "ref_file_ids": [],
            "thinking_enabled": thinking,
            "search_enabled": search,
            "client_stream_id": f"20251126-{uuid.uuid4().hex[:16]}"
        }
        headers = {**get_auth_headers(token), "x-ds-pow-response": pow_resp}

        resp = requests.post(
            DEEPSEEK_COMPLETION_URL, headers=headers, json=payload, stream=True, 
            impersonate="safari15_3", **get_proxy_kwargs()
        )
        
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Upstream Error: {resp.text}")

        chat_id = f"chatcmpl-{session_id}"
        created = int(time.time())

        if stream:
            return StreamingResponse(sse_generator(resp, model, chat_id, created, thinking), media_type="text/event-stream")
        
        # Non-stream handling (Simplified logic, can be improved similarly to sse_generator if needed)
        # For full support, client should use stream=True
        return JSONResponse(status_code=400, content={"error": "Please use stream=true for full DeepSeek R1/Search support"})

    except Exception as e:
        logger.error(f"Chat Error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVER_PORT)
