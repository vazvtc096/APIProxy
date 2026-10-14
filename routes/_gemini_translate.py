"""Gemini ↔ OpenAI 协议翻译（纯函数，无 app 依赖，可单测）。

负责把 Google Generative Language API（v1beta）的 generateContent 请求/响应
与 OpenAI chat.completions 形状互转，使 APIProxy 能像代理 OpenAI/Claude 那样
代理 Gemini。翻译只动消息结构与少量 generationConfig，复用既有上游、计费、限流。

不支持：Gemini 原生 tools / functionCalling / codeExecution（按需再加）。
"""
import json


def _split_model_action(modelpath: str):
    """'gemini-2.0-flash:streamGenerateContent' -> ('gemini-2.0-flash', 'streamGenerateContent')。"""
    if ":" in modelpath:
        model, _, action = modelpath.partition(":")
        return model, action or "generateContent"
    return modelpath, "generateContent"


def _parts_to_openai(parts) -> list:
    """Gemini content.parts -> OpenAI content（文本 + 可选图像）。"""
    out = []
    for p in parts or []:
        if not isinstance(p, dict):
            continue
        if "text" in p and p["text"]:
            out.append({"type": "text", "text": p["text"]})
        elif "inline_data" in p:  # 图像/文件内联
            d = p["inline_data"] or {}
            mime = d.get("mime_type", "image/png")
            data = d.get("data", "")
            out.append({"type": "image_url",
                        "image_url": {"url": f"data:{mime};base64,{data}"}})
    return out


def gemini_to_openai(body: dict) -> dict:
    """Gemini generateContent 请求体 -> OpenAI chat.completions 请求体（子集）。"""
    messages = []
    sys = body.get("systemInstruction")
    if sys:
        parts = sys.get("parts") if isinstance(sys, dict) else None
        if parts:
            txt = "\n".join(p.get("text", "") for p in parts if isinstance(p, dict))
        else:
            txt = str(sys.get("text", "")) if isinstance(sys, dict) else str(sys)
        if txt.strip():
            messages.append({"role": "system", "content": txt})

    for c in body.get("contents") or []:
        role = "assistant" if c.get("role") == "model" else "user"
        content = _parts_to_openai(c.get("parts"))
        if not content:
            content = [{"type": "text", "text": ""}]
        elif len(content) == 1 and "text" in content[0] and len(content[0]) == 2:
            # 纯文本单块 -> 退化为字符串，减少上游歧义
            content = content[0]["text"]
        messages.append({"role": role, "content": content})

    kwargs = {}
    gc = body.get("generationConfig") or {}
    if "maxOutputTokens" in gc:
        kwargs["max_tokens"] = int(gc["maxOutputTokens"])
    if "temperature" in gc:
        kwargs["temperature"] = gc["temperature"]
    if "topP" in gc:
        kwargs["top_p"] = gc["topP"]
    if "stopSequences" in gc:
        kwargs["stop"] = gc["stopSequences"]
    if "candidateCount" in gc and int(gc["candidateCount"]) > 1:
        kwargs["n"] = int(gc["candidateCount"])
    return {"messages": messages, "kwargs": kwargs}


_FINISH_MAP = {
    "stop": "STOP", "length": "MAX_TOKENS", "tool_calls": "STOP",
    "content_filter": "SAFETY", "function_call": "STOP",
}


def openai_to_gemini(result: dict, model: str) -> dict:
    """OpenAI chat.completions 响应 -> Gemini generateContent 响应。"""
    ch = (result.get("choices") or [{}])[0]
    msg = ch.get("message") or {}
    text = msg.get("content") or ""
    fr = ch.get("finish_reason") or "stop"
    u = result.get("usage") or {}
    return _build_gemini_response(text, fr, u, model)


def _build_gemini_response(text: str, finish_reason: str, usage: dict, model: str) -> dict:
    return {
        "candidates": [{
            "content": {"parts": [{"text": text}], "role": "model"},
            "finishReason": _FINISH_MAP.get(finish_reason, "STOP"),
            "index": 0,
            "safetyRatings": [],
        }],
        "usageMetadata": {
            "promptTokenCount": int(usage.get("prompt_tokens") or 0),
            "candidatesTokenCount": int(usage.get("completion_tokens") or 0),
            "totalTokenCount": int(usage.get("total_tokens") or
                                   ((usage.get("prompt_tokens") or 0) +
                                    (usage.get("completion_tokens") or 0))),
        },
        "modelVersion": model,
    }


def openai_chunk_to_gemini(chunk: dict, model: str) -> dict:
    """OpenAI 流式 chunk -> Gemini 流式 chunk（不含 usage，usage 由调用方收尾）。"""
    ch = (chunk.get("choices") or [{}])[0] or {}
    delta = ch.get("delta") or {}
    text = delta.get("content")
    if text is None and not ch.get("finish_reason"):
        return None
    parts = [{"text": text}] if text else []
    return {
        "candidates": [{
            "content": {"parts": parts, "role": "model"},
            "finishReason": _FINISH_MAP.get(ch.get("finish_reason"), "STOP") if ch.get("finish_reason") else None,
            "index": 0,
        }],
        "modelVersion": model,
    }


def gemini_sse(chunk_dict: dict) -> str:
    return "data: " + json.dumps(chunk_dict, ensure_ascii=False) + "\n\n"
