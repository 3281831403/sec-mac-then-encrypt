"""Contract tests for the ten defects in envelope/seal.py."""

import hashlib
import hmac

import pytest

import envelope.seal as seal_mod
from envelope.seal import (
    build_aad,
    derive_keys,
    envelope_batch,
    open,
    pad,
    seal,
    unpad,
    xor_stream,
)

MASTER = b"master-material-for-mac-then-encrypt-20261119"
CTX = b"tenant-a/user-17"
AAD = b"transfer/2026-11-19/0001"
PLAINTEXT = b"amount=100.00;account=6222;memo=alpha"
INVALID = "invalid envelope"


def _keys(context: bytes = CTX) -> dict:
    return derive_keys(MASTER, context)


def _counter(token: bytes) -> int:
    return int.from_bytes(token[1:9], "big")


def _flip(token: bytes, index: int) -> bytes:
    changed = bytearray(token)
    changed[index] ^= 0x01
    return bytes(changed)


def test_derive_keys_uses_separate_domains():
    keys = derive_keys(MASTER, CTX)
    other = derive_keys(MASTER, CTX + b"-other")

    assert set(keys) == {"enc", "mac"}
    assert keys["enc"] == hmac.new(
        MASTER, b"MTE-ENC" + CTX, hashlib.sha256
    ).digest()
    assert keys["mac"] == hmac.new(
        MASTER, b"MTE-MAC" + CTX, hashlib.sha256
    ).digest()
    assert len(keys["enc"]) == 32
    assert len(keys["mac"]) == 32
    assert keys["enc"] != keys["mac"]
    assert keys["enc"] != other["enc"]
    assert keys["mac"] != other["mac"]


def test_aad_includes_version():
    aad_v1 = build_aad(1, CTX, 7)
    aad_v2 = build_aad(2, CTX, 7)

    assert aad_v1 == (
        b"MTE-AAD"
        + b"\x01"
        + (7).to_bytes(8, "big")
        + len(CTX).to_bytes(4, "big")
        + CTX
    )
    assert aad_v2 == (
        b"MTE-AAD"
        + b"\x02"
        + (7).to_bytes(8, "big")
        + len(CTX).to_bytes(4, "big")
        + CTX
    )
    assert aad_v1 != aad_v2

    keys = _keys()
    token = seal(keys, PLAINTEXT, AAD)
    crossed = bytes([2]) + token[1:]
    with pytest.raises(ValueError, match="^invalid envelope$"):
        open(keys, crossed, AAD)


def test_aad_includes_counter():
    aad_seven = build_aad(1, CTX, 7)
    aad_eight = build_aad(1, CTX, 8)

    assert aad_seven[8:16] == (7).to_bytes(8, "big")
    assert aad_eight[8:16] == (8).to_bytes(8, "big")
    assert aad_seven != aad_eight

    keys = _keys()
    token = seal(keys, PLAINTEXT, AAD)
    current = _counter(token)
    replacement = current + 1 if current < (1 << 64) - 1 else current - 1
    substituted = token[:1] + replacement.to_bytes(8, "big") + token[9:]
    with pytest.raises(ValueError, match="^invalid envelope$"):
        open(keys, substituted, AAD)


def test_xor_stream_rejects_zero_counter():
    keys = _keys()
    stream = xor_stream(keys["enc"], 1, 64)

    expected_stream = b"".join(
        hmac.new(
            keys["enc"],
            b"MTE-STREAM" + (1).to_bytes(8, "big") + index.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()
        for index in range(2)
    )
    assert len(stream) == 64
    assert stream == expected_stream
    assert stream == xor_stream(keys["enc"], 1, 64)
    assert stream[:16] != xor_stream(keys["enc"], 2, 16)

    with pytest.raises(ValueError):
        xor_stream(keys["enc"], 0, 64)
    with pytest.raises(ValueError):
        xor_stream(keys["enc"], 0, 0)


def test_open_authenticates_before_decrypting(monkeypatch):
    keys = _keys()
    token = seal(keys, PLAINTEXT, AAD)
    calls = []

    def forbidden_xor(*args, **kwargs):
        calls.append(("xor_stream", args, kwargs))
        raise AssertionError("decryption started before authentication")

    def forbidden_unpad(*args, **kwargs):
        calls.append(("unpad", args, kwargs))
        raise AssertionError("unpadding started before authentication")

    monkeypatch.setattr(seal_mod, "xor_stream", forbidden_xor)
    monkeypatch.setattr(seal_mod, "unpad", forbidden_unpad)
    tampered = _flip(token, len(token) - 1)
    with pytest.raises(ValueError, match="^invalid envelope$"):
        open(keys, tampered, AAD)

    assert calls == []


def test_tag_covers_header_bytes():
    keys = _keys()
    token = seal(keys, PLAINTEXT, AAD)

    assert open(keys, token, AAD) == PLAINTEXT
    for changed in (_flip(token, 0), _flip(token, 1), _flip(token, 8)):
        with pytest.raises(ValueError, match="^invalid envelope$"):
            open(keys, changed, AAD)


def test_padding_and_authentication_errors_are_uniform():
    with pytest.raises(ValueError) as padding_error:
        unpad(b"A" * 15 + b"\x02", 16)

    keys = _keys()
    token = seal(keys, PLAINTEXT, AAD)
    bad_tag = _flip(token, len(token) - 1)
    with pytest.raises(ValueError) as authentication_error:
        open(keys, bad_tag, AAD)

    assert type(padding_error.value) is ValueError
    assert type(authentication_error.value) is ValueError
    assert str(padding_error.value) == INVALID
    assert str(authentication_error.value) == INVALID


def test_unpad_validates_padding_content():
    payload = b"authenticated payload with binary bytes"
    padded = pad(payload, 16)

    amount = padded[-1]
    assert len(padded) % 16 == 0
    assert amount == 16 - len(payload) % 16
    assert padded[-amount:] == bytes([amount]) * amount
    assert padded[:-amount] == payload
    assert unpad(padded, 16) == payload
    assert len(pad(b"", 16)) == 16
    assert unpad(pad(b"", 16), 16) == b""
    assert len(pad(b"A" * 16, 16)) == 32
    assert pad(b"A" * 16, 16)[-1] == 16

    bad_padding = (
        b"A" * 16,
        b"A" * 15 + b"\x00",
        b"A" * 15 + b"\x11",
        b"A" * 14 + b"\x03\x02",
        b"A" * 31 + b"\x02",
        b"",
    )
    for data in bad_padding:
        with pytest.raises(ValueError, match="^invalid envelope$"):
            unpad(data, 16)


def test_tag_comparison_uses_compare_digest(monkeypatch):
    keys = _keys()
    token = seal(keys, PLAINTEXT, AAD)
    calls = []

    def always_false(left, right):
        calls.append((left, right))
        return False

    monkeypatch.setattr(seal_mod.hmac, "compare_digest", always_false)
    with pytest.raises(ValueError, match="^invalid envelope$"):
        open(keys, token, AAD)

    assert calls
    left, right = calls[0]
    assert len(left) == 32
    assert len(right) == 32


def test_batch_items_do_not_reuse_counters():
    items = [
        {"context": CTX, "aad": AAD, "plaintext": b"first-transfer"},
        {"context": CTX, "aad": AAD, "plaintext": b"second-transfer"},
    ]
    policy = {"master": MASTER}

    result = envelope_batch(items, policy)

    assert result["problems"] == {}
    assert result["plaintexts"] == [item["plaintext"] for item in items]
    counters = [_counter(token) for token in result["tokens"]]
    assert counters[0] != counters[1]
    assert result["tokens"][0] != result["tokens"][1]

    for index, item in enumerate(items):
        keys = derive_keys(MASTER, item["context"])
        seed = hmac.new(
            keys["mac"],
            b"MTE-CTR"
            + len(item["aad"]).to_bytes(4, "big")
            + item["aad"]
            + item["plaintext"],
            hashlib.sha256,
        ).digest()
        expected_counter = 1 + int.from_bytes(seed[:8], "big") % ((1 << 64) - 1)
        expected = seal(keys, item["plaintext"], item["aad"])
        assert _counter(result["tokens"][index]) == expected_counter
        assert result["tokens"][index] == expected
        assert open(keys, result["tokens"][index], item["aad"]) == item["plaintext"]