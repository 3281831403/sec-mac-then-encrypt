"""Behavioural edge tests for the authenticated envelope contract."""

import hashlib
import hmac

import pytest

from envelope.seal import (
    build_aad,
    derive_keys,
    envelope_batch,
    open,
    pad,
    seal,
    xor_stream,
)

MASTER = b"master-material-for-mac-then-encrypt-20261119"
CTX = b"tenant-a/user-17"
AAD = b"transfer/2026-11-19/0001"
PLAINTEXT = b"amount=100.00;account=6222;memo=alpha"
INVALID = "invalid envelope"


def _keys() -> dict:
    return derive_keys(MASTER, CTX)


def _counter(token: bytes) -> int:
    return int.from_bytes(token[1:9], "big")


def test_seal_open_roundtrip():
    keys = _keys()
    token = seal(keys, PLAINTEXT, AAD)

    assert isinstance(token, bytes)
    assert len(token) >= 9 + 16 + 32
    assert token[0] == 1
    counter = _counter(token)
    assert counter > 0
    assert len(token[9:-32]) % 16 == 0
    assert len(token[-32:]) == 32

    padded = pad(PLAINTEXT, 16)
    stream = xor_stream(keys["enc"], counter, len(padded))
    expected_ciphertext = bytes(
        left ^ right for left, right in zip(padded, stream)
    )
    expected_tag = hmac.new(
        keys["mac"],
        build_aad(1, AAD, counter) + token[:9] + expected_ciphertext,
        hashlib.sha256,
    ).digest()
    assert token[9:-32] == expected_ciphertext
    assert token[-32:] == expected_tag
    assert open(keys, token, AAD) == PLAINTEXT
    assert open(keys, seal(keys, b"", AAD), AAD) == b""


def test_every_single_byte_flip_fails_uniformly():
    keys = _keys()
    token = seal(keys, PLAINTEXT, AAD)

    for index in range(len(token)):
        changed = bytearray(token)
        changed[index] ^= 0x01
        with pytest.raises(ValueError) as error:
            open(keys, bytes(changed), AAD)
        assert type(error.value) is ValueError
        assert str(error.value) == INVALID


def test_zero_counter_is_rejected():
    keys = _keys()

    with pytest.raises(ValueError):
        xor_stream(keys["enc"], 0, 16)
    with pytest.raises(ValueError):
        build_aad(1, CTX, 0)

    token = seal(keys, PLAINTEXT, AAD)
    zeroed_header = token[:1] + b"\x00" * 8 + token[9:]
    with pytest.raises(ValueError, match="^invalid envelope$"):
        open(keys, zeroed_header, AAD)


def test_cross_version_token_is_rejected():
    keys = _keys()
    token = seal(keys, PLAINTEXT, AAD)
    counter = _counter(token)
    ciphertext = token[9:-32]

    header_v2 = b"\x02" + counter.to_bytes(8, "big")
    tag_v2 = hmac.new(
        keys["mac"],
        build_aad(2, AAD, counter) + header_v2 + ciphertext,
        hashlib.sha256,
    ).digest()
    forged_v2 = header_v2 + ciphertext + tag_v2

    with pytest.raises(ValueError, match="^invalid envelope$"):
        open(keys, forged_v2, AAD)


def test_two_batches_match_individual_seals():
    items = [
        {"context": CTX, "aad": b"batch/one", "plaintext": b"one"},
        {"context": CTX + b"-two", "aad": b"batch/two", "plaintext": b"two"},
        {"context": CTX, "aad": b"batch/three", "plaintext": b"three"},
    ]
    policy = {"master": MASTER}

    first = envelope_batch(items, policy)
    second = envelope_batch(items, policy)

    assert first["problems"] == {}
    assert first == second
    for index, item in enumerate(items):
        keys = derive_keys(MASTER, item["context"])
        expected = seal(keys, item["plaintext"], item["aad"])
        assert first["tokens"][index] == expected
        assert first["plaintexts"][index] == item["plaintext"]
        assert open(keys, first["tokens"][index], item["aad"]) == item["plaintext"]