"""Optional offline differential oracle: pinned openai/tiktoken 0.14.0.

Receives only synthetic test strings on stdin; returns token counts, no text.
TIKTOKEN_CACHE_DIR must be primed explicitly by the test operator. No credentials
or real API calls are used. The Go implementation never imports this script.
"""
import importlib.metadata
import json
import sys
import tiktoken

if importlib.metadata.version("tiktoken") != "0.14.0":
    raise SystemExit("reference version mismatch")

texts = json.load(sys.stdin.buffer)
if len(texts) > 1024 or any(len(t.encode("utf-8")) > 65536 for t in texts):
    raise SystemExit("reference resource limit")
encodings = [tiktoken.get_encoding("cl100k_base"), tiktoken.get_encoding("o200k_base")]
json.dump([[len(encoding.encode_ordinary(text)) for encoding in encodings] for text in texts], sys.stdout)
