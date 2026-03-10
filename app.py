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

# -------------------------- Environment Config --------------------------
load_dotenv()

SERVER_PORT = int(os.getenv("PORT", 5001))
SERVER_API_KEYS = os.getenv("SERVER_API_KEYS", "").split(",")
PROXY_URL = os.getenv("PROXY_URL", None)
ACCOUNTS_JSON = os.getenv("DEEPSEEK_ACCOUNTS", "[]")

try:
    ACCOUNTS_LIST = json.loads(ACCOUNTS_JSON)
except json.JSONDecodeError:
    print("Error: DEEPSEEK_ACCOUNTS in .env is not valid JSON.")
    ACCOUNTS_LIST = []

# -------------------------- Logger --------------------------
# Set level to INFO to reduce noise, formatted for readability
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("DeepSeek-Proxy")

# Reduce curl_cffi log level
logging.getLogger("curl_cffi").setLevel(logging.WARNING)

app = FastAPI(docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# -------------------------- Account Management --------------------------
account_queue = []


def init_account_queue():
    global account_queue
    raw_accounts = ACCOUNTS_LIST[:]
    for acc in raw_accounts:
        if "token" not in acc:
            acc["token"] = ""
    account_queue = raw_accounts
    random.shuffle(account_queue)
    logger.info(f"Loaded {len(account_queue)} accounts from config.")


init_account_queue()

# -------------------------- Constants --------------------------
DEEPSEEK_HOST = "chat.deepseek.com"
DEEPSEEK_LOGIN_URL = f"https://{DEEPSEEK_HOST}/api/v0/users/login"
DEEPSEEK_CREATE_SESSION_URL = f"https://{DEEPSEEK_HOST}/api/v0/chat_session/create"
DEEPSEEK_CREATE_POW_URL = f"https://{DEEPSEEK_HOST}/api/v0/chat/create_pow_challenge"
DEEPSEEK_COMPLETION_URL = f"https://{DEEPSEEK_HOST}/api/v0/chat/completion"

BASE_HEADERS = {
    "Host": DEEPSEEK_HOST,
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/json",
    "x-client-platform": "web",
    "x-client-version": "1.5.0",
    "x-client-locale": "en_US",
    "accept-charset": "UTF-8",
    "origin": f"https://{DEEPSEEK_HOST}",
    "referer": f"https://{DEEPSEEK_HOST}/",
}

WASM_PATH = "sha3_wasm_bg.7b9ca65ddd.wasm"
KEEP_ALIVE_TIMEOUT = 10


# -------------------------- Helpers --------------------------
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


# -------------------------- Auth Logic --------------------------
def login_deepseek_via_account(account):
    email = account.get("email", "").strip()
    mobile = account.get("mobile", "").strip()
    password = account.get("password", "").strip()

    logger.info(f"Logging in: {email or mobile}")

    if not password or (not email and not mobile):
        raise HTTPException(status_code=400, detail="Account config error in .env")

    payload = {"password": password, "device_id": "deepseek_to_api", "os": "android"}
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
            **get_proxy_kwargs(),
        )
        resp.raise_for_status()
        data = resp.json()
        new_token = data["data"]["biz_data"]["user"]["token"]
        account["token"] = new_token
        logger.info("Login successful, token updated.")
        return new_token
    except Exception as e:
        logger.error(f"Login failed: {e}")
        raise HTTPException(status_code=500, detail="Login failed upstream")


def get_valid_token(request: Request):
    if not hasattr(request.state, "tried_accounts"):
        request.state.tried_accounts = []

    available_accounts = [
        acc
        for acc in account_queue
        if get_account_identifier(acc) not in request.state.tried_accounts
    ]
    if not available_accounts:
        request.state.tried_accounts = []
        available_accounts = account_queue

    if not available_accounts:
        raise HTTPException(status_code=429, detail="No accounts available.")

    account = available_accounts[0]
    request.state.account = account
    request.state.tried_accounts.append(get_account_identifier(account))

    token = account.get("token")
    if not token:
        token = login_deepseek_via_account(account)
    return token


def get_auth_headers(token):
    return {**BASE_HEADERS, "authorization": f"Bearer {token}"}


# -------------------------- PoW & Session --------------------------
def compute_pow_answer(
    algorithm,
    challenge_str,
    salt,
    difficulty,
    expire_at,
    signature,
    target_path,
    wasm_path,
):
    if algorithm != "DeepSeekHashV1":
        return None
    prefix = f"{salt}_{expire_at}_"
    store = Store()
    linker = Linker(store.engine)
    try:
        with open(wasm_path, "rb") as f:
            wasm_bytes = f.read()
    except FileNotFoundError:
        logger.error(f"WASM file not found at: {wasm_path}")
        return None

    module = Module(store.engine, wasm_bytes)
    instance = linker.instantiate(store, module)
    exports = instance.exports(store)

    memory = exports["memory"]
    add_to_stack = exports["__wbindgen_add_to_stack_pointer"]
    alloc = exports["__wbindgen_export_0"]
    wasm_solve = exports["wasm_solve"]

    def write_mem(offset, data):
        ctypes.memmove(
            ctypes.cast(memory.data_ptr(store), ctypes.c_void_p).value + offset,
            data,
            len(data),
        )

    def read_mem(offset, size):
        return ctypes.string_at(
            ctypes.cast(memory.data_ptr(store), ctypes.c_void_p).value + offset, size
        )

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
    logger.debug(f"Getting PoW response with token: {token[:10]}...")
    headers = get_auth_headers(token)
    logger.debug(f"PoW request headers: {headers}")

    for i in range(3):
        logger.debug(f"PoW creation attempt {i + 1}/3")
        try:
            payload = {"target_path": "/api/v0/chat/completion"}
            logger.debug(f"PoW request payload: {payload}")
            resp = requests.post(
                DEEPSEEK_CREATE_POW_URL,
                headers=headers,
                json=payload,
                timeout=30,
                impersonate="safari15_3",
                **get_proxy_kwargs(),
            )
            logger.debug(f"PoW response status: {resp.status_code}")
            logger.debug(f"PoW raw response: {resp.text[:200]}...")

            data = resp.json()
            logger.debug(f"PoW response JSON: {data}")

            if data.get("code") == 0:
                c = data["data"]["biz_data"]["challenge"]
                logger.debug(f"PoW challenge received: {c}")

                ans = compute_pow_answer(
                    c["algorithm"],
                    c["challenge"],
                    c["salt"],
                    c.get("difficulty", 144000),
                    c.get("expire_at", 1680000000),
                    c["signature"],
                    c["target_path"],
                    WASM_PATH,
                )
                logger.debug(f"PoW answer computed: {ans}")

                if ans:
                    pow_data = {
                        "algorithm": c["algorithm"],
                        "challenge": c["challenge"],
                        "salt": c["salt"],
                        "answer": ans,
                        "signature": c["signature"],
                        "target_path": c["target_path"],
                    }
                    logger.debug(f"PoW data to encode: {pow_data}")

                    encoded_pow = (
                        base64.b64encode(
                            json.dumps(
                                pow_data, separators=(",", ":"), ensure_ascii=False
                            ).encode()
                        )
                        .decode()
                        .rstrip()
                    )
                    logger.debug(
                        f"PoW response encoded successfully: {encoded_pow[:50]}..."
                    )
                    return encoded_pow
                else:
                    logger.warning(f"PoW answer computation failed")
            else:
                logger.warning(
                    f"PoW request failed with code: {data.get('code')}, message: {data.get('msg')}"
                )
        except Exception as e:
            logger.error(f"PoW attempt {i + 1} failed with error: {e}")
            time.sleep(1)

    logger.error("All PoW attempts failed")
    return None


def create_session(token):
    logger.debug(f"Creating session with token: {token[:10]}...")
    headers = get_auth_headers(token)
    logger.debug(f"Session request headers: {headers}")

    for i in range(3):
        logger.debug(f"Session creation attempt {i + 1}/3")
        try:
            resp = requests.post(
                DEEPSEEK_CREATE_SESSION_URL,
                headers=headers,
                json={"agent": "chat"},
                impersonate="safari15_3",
                **get_proxy_kwargs(),
            )
            logger.debug(f"Session creation response status: {resp.status_code}")
            logger.debug(f"Session creation response text: {resp.text[:200]}...")

            resp_data = resp.json()
            logger.debug(f"Session creation response JSON: {resp_data}")

            if resp_data.get("code") == 0:
                session_id = resp_data["data"]["biz_data"]["id"]
                logger.debug(f"Session created successfully with ID: {session_id}")
                return session_id
            else:
                logger.warning(
                    f"Session creation failed with code: {resp_data.get('code')}, message: {resp_data.get('msg')}"
                )
        except Exception as e:
            logger.error(f"Session creation attempt {i + 1} failed with error: {e}")
            time.sleep(1)

    logger.error("All session creation attempts failed")
    return None


def messages_prepare(messages: list) -> str:
    """
    Merges System Prompt into the first User message to avoid 422 errors.
    Formats the conversation using DeepSeek's internal delimiters.
    """
    logger.debug(f"Input messages to prepare: {messages}")
    system_prompts = []
    conversation = []

    for m in messages:
        role = m.get("role", "")
        content = m.get("content", "")

        if isinstance(content, list):
            text_parts = [
                str(item.get("text", ""))
                for item in content
                if item.get("type") == "text"
            ]
            text = "\n".join(text_parts)
            logger.debug(f"Processed list content: {text}")
        else:
            text = str(content)
            logger.debug(f"Processed string content: {text}")

        if role == "system":
            system_prompts.append(text)
            logger.debug(f"Added system prompt: {text[:50]}...")
        else:
            conversation.append({"role": role, "text": text})
            logger.debug(f"Added conversation item: {role} - {text[:50]}...")

    logger.debug(f"System prompts collected: {system_prompts}")
    logger.debug(f"Initial conversation: {conversation}")

    if system_prompts:
        system_text = "\n\n".join(system_prompts)
        logger.debug(f"Merged system text: {system_text[:100]}...")
        if conversation:
            logger.debug(f"Original first message: {conversation[0]['text'][:100]}...")
            conversation[0]["text"] = f"{system_text}\n\n{conversation[0]['text']}"
            logger.debug(
                f"Updated first message with system text: {conversation[0]['text'][:150]}..."
            )
        else:
            conversation.append({"role": "user", "text": system_text})
            logger.debug(
                f"Created first message with system text: {system_text[:100]}..."
            )

    parts = []
    for idx, block in enumerate(conversation):
        role = block["role"]
        text = block["text"]

        logger.debug(f"Processing conversation block {idx}: {role} | {text[:50]}...")

        if role == "assistant":
            formatted_text = f"<｜Assistant｜>{text}<｜end of sentence｜>"
            parts.append(formatted_text)
            logger.debug(f"Added assistant block: {formatted_text[:70]}...")
        elif role == "user":
            if idx > 0:
                formatted_text = f"<｜User｜>{text}"
                parts.append(formatted_text)
                logger.debug(f"Added user block: {formatted_text[:70]}...")
            else:
                parts.append(text)  # First message (with system prompt) has no tag
                logger.debug(f"Added first user block: {text[:70]}...")
        else:
            parts.append(text)
            logger.debug(f"Added other role block: {role} | {text[:70]}...")

    final = "".join(parts)
    logger.debug(f"Final formatted conversation: {final[:200]}...")

    processed_final = re.sub(r"!\[(.*?)\]\((.*?)\)", r"[\1](\2)", final)
    logger.debug(f"Processed final conversation: {processed_final[:200]}...")
    return processed_final


# -------------------------- Streaming Logic --------------------------
def sse_generator(response, model, chat_id, created, thinking_enabled):
    logger.debug(f"SSE Generator initiated | Model: {model} | Chat ID: {chat_id}")
    last_send = time.time()
    result_queue = queue.Queue()

    # Track the type of each fragment: 'THINK' or 'RESPONSE'
    # Default is RESPONSE (text)
    fragment_type_map = {}
    current_fragment_id = None

    def reader():
        logger.debug("Starting response reader thread...")
        try:
            for line_num, line in enumerate(response.iter_lines()):
                if not line:
                    continue
                line = line.decode("utf-8")
                logger.debug(
                    f"Processing line {line_num}: {line[:100]}..."
                )  # First 100 chars only

                # Ignore events that are not data (like 'event: update_session')
                if line.startswith("event:"):
                    logger.debug(f"Ignoring event line: {line}")
                    continue
                if not line.startswith("data:"):
                    logger.debug(f"Ignoring non-data line: {line}")
                    continue

                data_str = line[5:].strip()
                logger.debug(
                    f"Parsed data string: {data_str[:100]}..."
                )  # First 100 chars only

                # Handle stream end markers
                if data_str == "[DONE]" or data_str == "":
                    logger.debug("Received DONE marker, continuing...")
                    continue

                try:
                    chunk = json.loads(data_str)
                    logger.debug(f"Parsed JSON chunk: {chunk}")

                    # Case 0: Update Session / Title (Ignore)
                    if "updated_at" in chunk or "click_behavior" in chunk:
                        logger.debug(f"Ignoring update chunk: {chunk}")
                        continue

                    # Case 1: Simple content stream (Found in your logs: {"v": "..."})
                    # This is usually text content for the current active fragment
                    if (
                        "v" in chunk
                        and "p" not in chunk
                        and isinstance(chunk["v"], str)
                    ):
                        content = chunk["v"]
                        # Determine type based on last known fragment or default to text
                        # If we haven't seen a fragment definition yet, it's likely text.
                        msg_type = "text"
                        if (
                            current_fragment_id is not None
                            and fragment_type_map.get(str(current_fragment_id))
                            == "THINK"
                        ):
                            msg_type = "thinking"

                        result_queue.put({"type": msg_type, "content": content})
                        continue

                    # Case 2: Complex Batch/Update
                    if "v" in chunk:
                        val = chunk["v"]
                        p = chunk.get("p", "")

                        # 2a. Status check
                        if isinstance(val, list):
                            for item in val:
                                if (
                                    item.get("p") == "status"
                                    and item.get("v") == "FINISHED"
                                ):
                                    result_queue.put("DONE")
                                    return

                                # 2b. Fragment Definition (Start of Think or Response)
                                sub_p = item.get("p", "")
                                if (
                                    sub_p == "fragments"
                                    or sub_p == "response/fragments"
                                ) and isinstance(item.get("v"), list):
                                    for fragment in item["v"]:
                                        f_id = fragment.get("id")
                                        f_type = fragment.get(
                                            "type", "RESPONSE"
                                        )  # THINK or RESPONSE

                                        # Map ID to Type
                                        if f_id is not None:
                                            fragment_type_map[str(f_id)] = f_type
                                            current_fragment_id = (
                                                f_id  # Set active fragment
                                            )

                                        # If content exists immediately
                                        if "content" in fragment:
                                            msg_type = (
                                                "thinking"
                                                if f_type == "THINK"
                                                else "text"
                                            )
                                            result_queue.put(
                                                {
                                                    "type": msg_type,
                                                    "content": fragment["content"],
                                                }
                                            )

                        # 2c. String append via Path (e.g., "response/fragments/-1/content")
                        elif isinstance(val, str):
                            # Try to extract fragment ID from path
                            match = re.search(r"fragments/(\d+)/content", p)
                            if match:
                                f_id = match.group(1)
                                f_type = fragment_type_map.get(f_id, "RESPONSE")
                                msg_type = "thinking" if f_type == "THINK" else "text"
                                result_queue.put({"type": msg_type, "content": val})
                            else:
                                # Fallback: Assume it belongs to the current active fragment or is text
                                result_queue.put({"type": "text", "content": val})

                except json.JSONDecodeError:
                    continue
                except Exception:
                    continue

        except Exception as e:
            logger.error(f"Stream Reader Error: {e}")
            result_queue.put("DONE")
        finally:
            response.close()

    logger.debug("Starting SSE reader thread...")
    threading.Thread(target=reader, daemon=True).start()
    logger.debug("SSE reader thread started successfully")

    # Initial Chunk
    logger.debug("Sending initial assistant role chunk")
    yield f"data: {json.dumps({'id': chat_id, 'model': model, 'choices': [{'index': 0, 'delta': {'role': 'assistant'}, 'finish_reason': None}]})}\n\n"

    while True:
        try:
            logger.debug("Waiting for item from result queue...")
            item = result_queue.get(timeout=KEEP_ALIVE_TIMEOUT)
            logger.debug(f"Retrieved item from queue: {item}")

            if item == "DONE":
                logger.debug("Received DONE signal, ending stream")
                yield f"data: {json.dumps({'id': chat_id, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]})}\n\n"
                yield "data: [DONE]\n\n"
                break

            delta = {}
            if item["type"] == "thinking" and thinking_enabled:
                logger.debug(f"Processing thinking content: {item['content'][:50]}...")
                delta["reasoning_content"] = item["content"]
            elif item["type"] == "text":
                logger.debug(f"Processing text content: {item['content'][:50]}...")
                delta["content"] = item["content"]
            else:
                logger.debug(
                    f"Processing unknown content type {item['type']}: {item['content'][:50]}..."
                )

            if delta:
                chunk_data = {
                    "id": chat_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
                }
                logger.debug(f"Yielding chunk data: {chunk_data}")
                yield f"data: {json.dumps(chunk_data)}\n\n"
                last_send = time.time()

        except queue.Empty:
            logger.debug("Queue empty, sending keep-alive")
            yield ": keep-alive\n\n"


# -------------------------- Endpoints --------------------------


@app.get("/v1/models")
async def list_models(api_key: str = Depends(verify_api_key)):
    t = int(time.time())
    return JSONResponse(
        content={
            "object": "list",
            "data": [
                {
                    "id": "deepseek-chat",
                    "object": "model",
                    "created": t,
                    "owned_by": "deepseek",
                },
                {
                    "id": "deepseek-reasoner",
                    "object": "model",
                    "created": t,
                    "owned_by": "deepseek",
                },
            ],
        }
    )


@app.post("/v1/chat/completions")
async def chat_completions(request: Request, api_key: str = Depends(verify_api_key)):
    try:
        req = await request.json()
        logger.debug(f"Full request body: {req}")

        model = req.get("model", "deepseek-chat")
        messages = req.get("messages", [])
        stream = req.get("stream", False)

        model_lower = model.lower()
        thinking = req.get("thinking_enabled", False) or (
            "reasoner" in model_lower or "r1" in model_lower
        )
        search = req.get("search_enabled", False) or ("search" in model_lower)

        logger.info(
            f"New Request | Model: {model} | Stream: {stream} | Thinking: {thinking}"
        )
        logger.debug(f"Request messages: {messages}")

        prompt_content = messages_prepare(messages)
        logger.debug(f"Prepared prompt content: {repr(prompt_content)}")

        if not prompt_content or not prompt_content.strip():
            logger.warning("Empty prompt received.")
            return JSONResponse(
                status_code=400, content={"error": "Message content cannot be empty."}
            )

        logger.debug("Getting valid token...")
        token = get_valid_token(request)
        logger.debug(f"Token retrieved: {'Yes' if token else 'No'}")

        logger.debug("Creating session...")
        session_id = create_session(token)
        logger.debug(f"Session ID: {session_id}")

        logger.debug("Getting PoW response...")
        pow_resp = get_pow_response(token)
        logger.debug(f"PoW response: {pow_resp}")

        if not session_id or not pow_resp:
            logger.error(
                f"Auth failed (Session/PoW). Session ID: {session_id}, PoW: {pow_resp}"
            )
            raise HTTPException(status_code=500, detail="DeepSeek auth failed")

        # Use current date for client_stream_id
        current_date = time.strftime("%Y%m%d")
        payload = {
            "chat_session_id": session_id,
            "parent_message_id": None,
            "prompt": prompt_content,
            "ref_file_ids": [],
            "thinking_enabled": thinking,
            "search_enabled": search,
            "client_stream_id": f"{current_date}-{uuid.uuid4().hex[:16]}",
        }
        headers = {**get_auth_headers(token), "x-ds-pow-response": pow_resp}
        logger.debug(f"Upstream request headers: {headers}")
        logger.debug(f"Upstream request payload: {payload}")

        resp = requests.post(
            DEEPSEEK_COMPLETION_URL,
            headers=headers,
            json=payload,
            stream=True,
            impersonate="safari15_3",
            **get_proxy_kwargs(),
        )

        logger.debug(f"Upstream response status: {resp.status_code}")
        if resp.status_code != 200:
            error_text = resp.text
            logger.error(f"Upstream Error: {resp.status_code} | Body: {error_text}")
            raise HTTPException(
                status_code=502, detail=f"Upstream Error: {resp.status_code}"
            )

        chat_id = f"chatcmpl-{session_id}"
        created = int(time.time())

        if stream:
            return StreamingResponse(
                sse_generator(resp, model, chat_id, created, thinking),
                media_type="text/event-stream",
            )

        return JSONResponse(
            status_code=400, content={"error": "Please use stream=true"}
        )

    except HTTPException as e:
        raise e
    except Exception as e:
        logger.exception(f"Internal Error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=SERVER_PORT)
