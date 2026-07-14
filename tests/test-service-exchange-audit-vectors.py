#!/usr/bin/env python3
"""Stdlib-only verifier for the frozen service-exchange byte transcript."""

import hashlib
import struct


VECTORS = (
    {
        "intention": "01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
        "request": "000000000000000000000000000",
        "credential": "wlc_000000000000000000000000000",
        "generation": 0x0102030405060708,
        "principal": "svc:billing:reader",
        "tenant": "tenant-a",
        "session": "01890f47-3c4b-7cc2-98c4-dc0c0c07398f",
        "jti": "01890f47-3c4b-7cc2-a8c4-dc0c0c073990",
        "created": 1712345678901234,
        "hex": "777972656c6f672e736572766963652d65786368616e67652e696e74656e74696f6e2d7061796c6f616400000000010000002430313839306634372d336334622d376363322d623863342d6463306330633037333939310000001b736572766963652e63726564656e7469616c2e65786368616e676500000007616c6c6f7765640006155e8bec6ff20000001b3030303030303030303030303030303030303030303030303030300000001f776c635f3030303030303030303030303030303030303030303030303030300102030405060708000000127376633a62696c6c696e673a7265616465720000000874656e616e742d6100000001000000200da4415c0595bc92941dbb76d6efc38fda8ca71da515c59ed28dc461d076737a000000202f21c5654459acb3315b999dbdf891a63f19a36f91a1ebefeb88c05bd310a724",
        "digest": "b6448d2d41708cd15a391ac8812fcbc0b7d4d6898d8ffe02f80a01a0539877a5",
    },
    {
        "intention": "ffffffff-ffff-7fff-bfff-ffffffffffff",
        "request": "0ujtsYcgvSTl8PAuAdqWYSMnLOv",
        "credential": "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
        "generation": 0x7FFFFFFFFFFFFFFF,
        "principal": "svc:x",
        "tenant": "z",
        "session": "01890f47-3c4b-7cc2-98c4-dc0c0c07398f",
        "jti": "01890f47-3c4b-7cc2-a8c4-dc0c0c073990",
        "created": 1,
        "hex": "777972656c6f672e736572766963652d65786368616e67652e696e74656e74696f6e2d7061796c6f616400000000010000002466666666666666662d666666662d376666662d626666662d6666666666666666666666660000001b736572766963652e63726564656e7469616c2e65786368616e676500000007616c6c6f77656400000000000000010000001b30756a74735963677653546c385041754164715759534d6e4c4f760000001f776c635f30756a74735963677653546c385041754164715759534d6e4c4f767fffffffffffffff000000057376633a78000000017a00000001000000200da4415c0595bc92941dbb76d6efc38fda8ca71da515c59ed28dc461d076737a000000202f21c5654459acb3315b999dbdf891a63f19a36f91a1ebefeb88c05bd310a724",
        "digest": "d6aa950d795193fba20c37825584b3d7673b314ceb8d45e895f0f64d7b4642fb",
    },
    {
        "intention": "01890f47-3c4b-7cc2-b8c4-dc0c0c073993",
        "request": "000000000000000000000000002",
        "credential": "wlc_000000000000000000000000002",
        "generation": 2,
        "principal": "svc:utf8",
        "tenant": "테넌트",
        "session": "01890f47-3c4b-7cc2-98c4-dc0c0c07398f",
        "jti": "01890f47-3c4b-7cc2-a8c4-dc0c0c073990",
        "created": 2,
        "hex": "777972656c6f672e736572766963652d65786368616e67652e696e74656e74696f6e2d7061796c6f616400000000010000002430313839306634372d336334622d376363322d623863342d6463306330633037333939330000001b736572766963652e63726564656e7469616c2e65786368616e676500000007616c6c6f77656400000000000000020000001b3030303030303030303030303030303030303030303030303030320000001f776c635f3030303030303030303030303030303030303030303030303030320000000000000002000000087376633a7574663800000009ed858ceb848ced8ab800000001000000200da4415c0595bc92941dbb76d6efc38fda8ca71da515c59ed28dc461d076737a000000202f21c5654459acb3315b999dbdf891a63f19a36f91a1ebefeb88c05bd310a724",
        "digest": "2182e3fdba829b86b0be0249c72b9939e2a7fb2f6fdbaf45d932149eb8135013",
    },
)


def u32(value):
    return struct.pack(">I", value)


def u64(value):
    return struct.pack(">Q", value)


def field_bytes(field, value):
    encoding = "utf-8" if field in {"principal", "tenant"} else "ascii"
    return value.encode(encoding)


def framed(field, value):
    raw = field_bytes(field, value)
    return u32(len(raw)) + raw


def fingerprint(kind, identifier):
    raw_kind = kind.encode("ascii")
    raw_id = identifier.encode("ascii")
    transcript = (b"wyrelog.service-exchange.audit-fingerprint\0" + u32(1)
                  + u32(len(raw_kind)) + raw_kind + u64(len(raw_id)) + raw_id)
    return hashlib.sha256(transcript).digest()


def encode(vector):
    return (b"wyrelog.service-exchange.intention-payload\0" + u32(1)
            + framed("intention", vector["intention"])
            + framed("event", "service.credential.exchange")
            + framed("outcome", "allowed")
            + u64(vector["created"])
            + framed("request", vector["request"])
            + framed("credential", vector["credential"])
            + u64(vector["generation"])
            + framed("principal", vector["principal"])
            + framed("tenant", vector["tenant"])
            + u32(1) + u32(32) + fingerprint("session_id", vector["session"])
            + u32(32) + fingerprint("jti", vector["jti"]))


def take_u32(raw, offset):
    return struct.unpack_from(">I", raw, offset)[0], offset + 4


def take_bytes(raw, offset):
    length, offset = take_u32(raw, offset)
    if offset + length > len(raw):
        raise AssertionError("length prefix exceeds transcript bounds")
    return raw[offset:offset + length], offset + length


def verify_offsets(raw, vector):
    domain = b"wyrelog.service-exchange.intention-payload\0"
    assert raw.startswith(domain)
    offset = len(domain)
    version, offset = take_u32(raw, offset)
    assert version == 1
    for field, expected in (("intention", vector["intention"]),
                            ("event", "service.credential.exchange"),
                            ("outcome", "allowed")):
        actual, offset = take_bytes(raw, offset)
        assert actual == field_bytes(field, expected)
    created = struct.unpack_from(">Q", raw, offset)[0]
    assert created == vector["created"]
    offset += 8
    for field, expected in (("request", vector["request"]),
                            ("credential", vector["credential"])):
        actual, offset = take_bytes(raw, offset)
        assert actual == field_bytes(field, expected)
    generation = struct.unpack_from(">Q", raw, offset)[0]
    assert generation == vector["generation"]
    offset += 8
    for field, expected in (("principal", vector["principal"]),
                            ("tenant", vector["tenant"])):
        actual, offset = take_bytes(raw, offset)
        expected_bytes = field_bytes(field, expected)
        assert actual == expected_bytes
        if field == "tenant" and any(ord(char) > 127 for char in expected):
            assert len(actual) == len(expected_bytes)
            assert len(actual) != len(expected)
    fingerprint_version, offset = take_u32(raw, offset)
    assert fingerprint_version == 1
    session, offset = take_bytes(raw, offset)
    jti, offset = take_bytes(raw, offset)
    assert len(session) == len(jti) == 32
    assert session == fingerprint("session_id", vector["session"])
    assert jti == fingerprint("jti", vector["jti"])
    assert offset == len(raw)


def main():
    for vector in VECTORS:
        literal = bytes.fromhex(vector["hex"])
        independently_encoded = encode(vector)
        assert literal == independently_encoded
        assert hashlib.sha256(literal).hexdigest() == vector["digest"]
        verify_offsets(literal, vector)

        mutations = (
            literal.replace(b"intention-payload", b"audit-payload", 1),
            literal[:49] + literal[89:],  # omit framed intention
            literal[:45] + u32(2) + literal[49:],  # wrong payload schema
            literal[:49] + literal[53:],  # omit intention length prefix
            literal[:-36] + u32(31) + literal[-32:],  # wrong jti length
        )
        for mutation in mutations:
            assert mutation != literal
            assert hashlib.sha256(mutation).hexdigest() != vector["digest"]
            try:
                verify_offsets(mutation, vector)
            except (AssertionError, struct.error):
                pass
            else:
                raise AssertionError("malformed transcript was accepted")

        tenant = field_bytes("tenant", vector["tenant"])
        if len(tenant) != len(vector["tenant"]):
            marker = u32(len(tenant)) + tenant
            position = literal.find(marker)
            assert position >= 0
            codepoint_length = (literal[:position] + u32(len(vector["tenant"]))
                                + literal[position + 4:])
            assert hashlib.sha256(codepoint_length).hexdigest() != vector["digest"]
            try:
                verify_offsets(codepoint_length, vector)
            except (AssertionError, struct.error):
                pass
            else:
                raise AssertionError("codepoint length framing was accepted")

        marker = u32(1) + u32(32) + fingerprint("session_id",
                                                vector["session"])
        position = literal.rfind(marker)
        assert position >= 0
        wrong_fingerprint_schema = (literal[:position] + u32(2)
                                    + literal[position + 4:])
        assert hashlib.sha256(wrong_fingerprint_schema).hexdigest() != vector["digest"]
        try:
            verify_offsets(wrong_fingerprint_schema, vector)
        except AssertionError:
            pass
        else:
            raise AssertionError("wrong fingerprint schema was accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
