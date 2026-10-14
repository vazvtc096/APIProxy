"""Gemini ↔ OpenAI 翻译纯单元测试（直接加载文件，避免触发 routes/__init__ 的 app 初始化）。"""
import importlib.util
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "gem_translate", os.path.join(_ROOT, "routes", "_gemini_translate.py"))
gem = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gem)


def test_split_model_action():
    assert gem._split_model_action("gemini-2.0-flash:streamGenerateContent") == (
        "gemini-2.0-flash", "streamGenerateContent")
    assert gem._split_model_action("gemini-2.0-flash") == ("gemini-2.0-flash", "generateContent")


def test_gemini_to_openai_basic():
    body = {
        "systemInstruction": {"parts": [{"text": "be brief"}]},
        "contents": [
            {"role": "user", "parts": [{"text": "hi"}]},
            {"role": "model", "parts": [{"text": "hello"}]},
        ],
        "generationConfig": {"maxOutputTokens": 100, "temperature": 0.5,
                              "stopSequences": ["STOP"]},
    }
    t = gem.gemini_to_openai(body)
    assert t["messages"][0] == {"role": "system", "content": "be brief"}
    assert t["messages"][1] == {"role": "user", "content": "hi"}
    assert t["messages"][2] == {"role": "assistant", "content": "hello"}
    assert t["kwargs"]["max_tokens"] == 100
    assert t["kwargs"]["temperature"] == 0.5
    assert t["kwargs"]["stop"] == ["STOP"]


def test_gemini_to_openai_image():
    body = {"contents": [{"role": "user", "parts": [
        {"text": "what is this"},
        {"inline_data": {"mime_type": "image/png", "data": "BASE64DATA"}},
    ]}]}
    t = gem.gemini_to_openai(body)
    content = t["messages"][0]["content"]
    assert isinstance(content, list)
    assert content[0] == {"type": "text", "text": "what is this"}
    assert content[1]["type"] == "image_url"
    assert "data:image/png;base64,BASE64DATA" in content[1]["image_url"]["url"]


def test_openai_to_gemini():
    res = {"choices": [{"message": {"content": "answer"}, "finish_reason": "stop"}],
           "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
    g = gem.openai_to_gemini(res, "gemini-2.0-flash")
    assert g["candidates"][0]["content"]["parts"][0]["text"] == "answer"
    assert g["candidates"][0]["finishReason"] == "STOP"
    assert g["usageMetadata"]["promptTokenCount"] == 10
    assert g["usageMetadata"]["candidatesTokenCount"] == 5


def test_chunk_to_gemini():
    chunk = {"choices": [{"delta": {"content": "hi"}, "finish_reason": None}]}
    g = gem.openai_chunk_to_gemini(chunk, "m")
    assert g["candidates"][0]["content"]["parts"][0]["text"] == "hi"
    assert gem.openai_chunk_to_gemini({"choices": [{}]}, "m") is None
