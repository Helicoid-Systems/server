"""Minimal real STUN/TURN (RFC 5389/5766/8656) message codec and long-term auth.

Used only by the relay-expiry lab harness against a local loopback turnserver.
Not a general-purpose client library. No secrets are printed.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
import time
from dataclasses import dataclass, field

MAGIC_COOKIE = 0x2112A442

# Methods
METHOD_BINDING = 0x001
METHOD_ALLOCATE = 0x003
METHOD_REFRESH = 0x004
METHOD_SEND = 0x006
METHOD_DATA = 0x007
METHOD_CREATE_PERMISSION = 0x008
METHOD_CHANNEL_BIND = 0x009

# Classes
CLASS_REQUEST = 0x000
CLASS_INDICATION = 0x010
CLASS_SUCCESS = 0x100
CLASS_ERROR = 0x110

# Attributes
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_UNKNOWN_ATTRIBUTES = 0x000A
ATTR_CHANNEL_NUMBER = 0x000C
ATTR_LIFETIME = 0x000D
ATTR_XOR_PEER_ADDRESS = 0x0012
ATTR_DATA = 0x0013
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015
ATTR_XOR_RELAYED_ADDRESS = 0x0016
ATTR_EVEN_PORT = 0x0018
ATTR_REQUESTED_TRANSPORT = 0x0019
ATTR_DONT_FRAGMENT = 0x001A
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_RESERVATION_TOKEN = 0x0022
ATTR_SOFTWARE = 0x8022
ATTR_FINGERPRINT = 0x8028

TRANSPORT_UDP = 17
TRANSPORT_TCP = 6


def _pad4(n: int) -> int:
    return (4 - (n % 4)) % 4


def msg_type(method: int, cls: int) -> int:
    return ((method & 0x0F80) << 2) | ((method & 0x0070) << 1) | (method & 0x000F) | cls


def msg_method(mtype: int) -> int:
    return ((mtype & 0x3E00) >> 2) | ((mtype & 0x00E0) >> 1) | (mtype & 0x000F)


def msg_class(mtype: int) -> int:
    """Return class bit-mask (CLASS_REQUEST/INDICATION/SUCCESS/ERROR)."""
    return mtype & 0x0110


@dataclass
class Attr:
    type: int
    value: bytes


@dataclass
class StunMessage:
    method: int
    cls: int
    transaction_id: bytes
    attrs: list[Attr] = field(default_factory=list)

    def get(self, atype: int) -> bytes | None:
        for a in self.attrs:
            if a.type == atype:
                return a.value
        return None

    def get_text(self, atype: int) -> str | None:
        v = self.get(atype)
        return v.decode("utf-8", errors="replace") if v is not None else None

    def get_u32(self, atype: int) -> int | None:
        v = self.get(atype)
        if v is None or len(v) < 4:
            return None
        return struct.unpack("!I", v[:4])[0]


def encode(msg: StunMessage) -> bytes:
    body = b""
    for a in msg.attrs:
        val = a.value
        body += struct.pack("!HH", a.type, len(val)) + val + (b"\x00" * _pad4(len(val)))
    header = struct.pack(
        "!HHI12s",
        msg_type(msg.method, msg.cls),
        len(body),
        MAGIC_COOKIE,
        msg.transaction_id,
    )
    return header + body


def decode(data: bytes) -> StunMessage:
    if len(data) < 20:
        raise ValueError("STUN message too short")
    mtype, length, magic, tid = struct.unpack("!HHI12s", data[:20])
    if magic != MAGIC_COOKIE:
        raise ValueError("bad STUN magic cookie")
    if len(data) < 20 + length:
        raise ValueError("truncated STUN message")
    attrs: list[Attr] = []
    off = 20
    end = 20 + length
    while off + 4 <= end:
        atype, alen = struct.unpack("!HH", data[off : off + 4])
        off += 4
        if off + alen > end:
            raise ValueError("truncated STUN attribute")
        attrs.append(Attr(atype, data[off : off + alen]))
        off += alen + _pad4(alen)
    return StunMessage(msg_method(mtype), msg_class(mtype), tid, attrs)


def encode_xor_addr(family: int, addr: str, port: int, tid: bytes) -> bytes:
    xport = port ^ (MAGIC_COOKIE >> 16)
    if family == socket.AF_INET:
        ip = socket.inet_aton(addr)
        xip = bytes(b ^ ((MAGIC_COOKIE >> (8 * (3 - i))) & 0xFF) for i, b in enumerate(ip))
        return struct.pack("!BBH4s", 0, 0x01, xport, xip)
    if family == socket.AF_INET6:
        ip = socket.inet_pton(socket.AF_INET6, addr)
        magic_bytes = struct.pack("!I", MAGIC_COOKIE) + tid
        xip = bytes(a ^ b for a, b in zip(ip, magic_bytes))
        return struct.pack("!BBH16s", 0, 0x02, xport, xip)
    raise ValueError("unsupported family")


def decode_xor_addr(value: bytes, tid: bytes) -> tuple[int, str, int]:
    if len(value) < 4:
        raise ValueError("short address")
    _, family, xport = struct.unpack("!BBH", value[:4])
    port = xport ^ (MAGIC_COOKIE >> 16)
    if family == 0x01 and len(value) >= 8:
        xip = value[4:8]
        ip = bytes(b ^ ((MAGIC_COOKIE >> (8 * (3 - i))) & 0xFF) for i, b in enumerate(xip))
        return socket.AF_INET, socket.inet_ntoa(ip), port
    if family == 0x02 and len(value) >= 20:
        xip = value[4:20]
        magic_bytes = struct.pack("!I", MAGIC_COOKIE) + tid
        ip = bytes(a ^ b for a, b in zip(xip, magic_bytes))
        return socket.AF_INET6, socket.inet_ntop(socket.AF_INET6, ip), port
    raise ValueError("unsupported address family")


def decode_error_code(value: bytes) -> tuple[int, str]:
    if len(value) < 4:
        return 0, ""
    code = (value[2] & 0x07) * 100 + value[3]
    reason = value[4:].decode("utf-8", errors="replace")
    return code, reason


def long_term_key(username: str, realm: str, password: str) -> bytes:
    """RFC 5389 long-term credential key = MD5(username:realm:password)."""
    material = f"{username}:{realm}:{password}".encode("utf-8")
    return hashlib.md5(material).digest()


def rest_password(username: str, secret: str) -> str:
    """TURN REST API password = base64(HMAC-SHA1(username, secret))."""
    import base64

    mac = hmac.new(secret.encode("utf-8"), username.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(mac).decode("ascii")


def add_message_integrity(msg: StunMessage, key: bytes) -> None:
    """Append MESSAGE-INTEGRITY (HMAC-SHA1) computed over the message so far.

    RFC 5389: HMAC is over the STUN message up to but not including the
    MESSAGE-INTEGRITY attribute; the header Length field is adjusted to
    include the MESSAGE-INTEGRITY attribute (4 + 20 bytes).
    """
    body_without_mi = encode(msg)
    mi_len = 20
    header_len = len(body_without_mi) - 20 + 4 + mi_len
    # header: type(2) + adjusted length(2) + magic(4) + tid(12)
    header = body_without_mi[:2] + struct.pack("!H", header_len) + body_without_mi[4:20]
    to_sign = header + body_without_mi[20:]
    digest = hmac.new(key, to_sign, hashlib.sha1).digest()
    msg.attrs.append(Attr(ATTR_MESSAGE_INTEGRITY, digest))


def check_message_integrity(msg_bytes: bytes, key: bytes) -> bool:
    """Verify MESSAGE-INTEGRITY on a raw message."""
    m = decode(msg_bytes)
    mi = m.get(ATTR_MESSAGE_INTEGRITY)
    if mi is None:
        return False
    before = StunMessage(m.method, m.cls, m.transaction_id, [])
    for a in m.attrs:
        if a.type == ATTR_MESSAGE_INTEGRITY:
            break
        before.attrs.append(a)
    encoded_before = encode(before)
    mi_len = 20
    header_len = len(encoded_before) - 20 + 4 + mi_len
    header = encoded_before[:2] + struct.pack("!H", header_len) + encoded_before[4:20]
    to_sign = header + encoded_before[20:]
    expected = hmac.new(key, to_sign, hashlib.sha1).digest()
    return hmac.compare_digest(expected, mi)


class TurnChannel:
    """Loopback TURN client channel over one transport socket."""

    def __init__(self, transport: socket.socket, verbose: bool = False) -> None:
        self.sock = transport
        self.verbose = verbose
        self.realm: str | None = None
        self.nonce: str | None = None
        self.username: str | None = None
        self.password: str | None = None
        self.key: bytes | None = None
        self.relayed_addr: tuple[int, str, int] | None = None
        self.mapped_addr: tuple[int, str, int] | None = None
        self.alloc_lifetime: int | None = None
        self._tid = 0

    def _next_tid(self) -> bytes:
        self._tid = (self._tid + 1) & 0xFFFFFFFF
        return struct.pack("!I", self._tid) + os.urandom(8)

    def _log(self, kind: str, msg: StunMessage) -> None:
        if not self.verbose:
            return
        err = msg.get(ATTR_ERROR_CODE)
        extra = ""
        if err:
            code, reason = decode_error_code(err)
            extra = f" error={code} {reason!r}"
        lifetime = msg.get_u32(ATTR_LIFETIME)
        if lifetime is not None:
            extra += f" lifetime={lifetime}"
        print(f"  [{kind}] method=0x{msg.method:03x} class=0x{msg.cls:03x}{extra}", flush=True)

    def send_raw(self, data: bytes) -> None:
        # coturn frames TCP/TLS by the STUN header Length field (no RFC 4571
        # 2-byte prefix). ChannelData is distinguished by a type in 0x4000-0x7FFF.
        if self.sock.type & socket.SOCK_STREAM:
            self.sock.sendall(data)
        else:
            self.sock.send(data)

    def recv_raw(self, timeout: float = 3.0) -> StunMessage | None:
        self.sock.settimeout(timeout)
        try:
            if self.sock.type & socket.SOCK_STREAM:
                header = self._recv_exact(20)
                if header is None or len(header) < 20:
                    return None
                (length,) = struct.unpack("!H", header[2:4])
                rest = self._recv_exact(length) if length else b""
                if rest is None:
                    return None
                data = header + rest
                msg = decode(data)
            else:
                data, _ = self.sock.recvfrom(65535)
                if len(data) < 20:
                    return None
                msg = decode(data)
            self._log("recv", msg)
            return msg
        except socket.timeout:
            return None

    def _recv_exact(self, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def verify_authed_response(self, resp: StunMessage | None, req: StunMessage,
                               expect_method: int) -> tuple[bool, str]:
        """Check method/class/tid/MESSAGE-INTEGRITY on an authenticated response."""
        if resp is None:
            return False, "no_response"
        if resp.method != expect_method:
            return False, f"method_mismatch got=0x{resp.method:03x}"
        if resp.transaction_id != req.transaction_id:
            return False, "tid_mismatch"
        if resp.cls == CLASS_ERROR:
            return True, "error_class"
        if resp.cls != CLASS_SUCCESS:
            return False, f"class_mismatch got=0x{resp.cls:03x}"
        if self.key is not None:
            raw_mi = resp.get(ATTR_MESSAGE_INTEGRITY)
            if raw_mi is None:
                return False, "missing_message_integrity"
            # Re-encode is unnecessary: check_message_integrity works on raw.
            # We only have the decoded message; rebuild raw via encode is lossy
            # for unknown attrs. Verify using the attrs we hold.
            before = StunMessage(resp.method, resp.cls, resp.transaction_id, [])
            for a in resp.attrs:
                if a.type == ATTR_MESSAGE_INTEGRITY:
                    break
                before.attrs.append(a)
            encoded_before = encode(before)
            header_len = len(encoded_before) - 20 + 4 + 20
            header = encoded_before[:2] + struct.pack("!H", header_len) + encoded_before[4:20]
            to_sign = header + encoded_before[20:]
            expected = hmac.new(self.key, to_sign, hashlib.sha1).digest()
            if not hmac.compare_digest(expected, raw_mi):
                return False, "message_integrity_mismatch"
        return True, "ok"

    def bind_challenge(self) -> bool:
        """Fetch realm/nonce via unauthenticated Binding or Allocate error."""
        tid = self._next_tid()
        req = StunMessage(METHOD_ALLOCATE, CLASS_REQUEST, tid)
        req.attrs.append(Attr(ATTR_REQUESTED_TRANSPORT, struct.pack("!I", TRANSPORT_UDP << 24)))
        self.send_raw(encode(req))
        resp = self.recv_raw()
        if resp is None:
            return False
        self.realm = resp.get_text(ATTR_REALM)
        self.nonce = resp.get_text(ATTR_NONCE)
        return self.realm is not None and self.nonce is not None

    def set_credentials(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        if self.realm is not None:
            self.key = long_term_key(username, self.realm, password)

    def _authed_request(self, method: int, extra: list[Attr] | None = None) -> StunMessage:
        if self.key is None or self.username is None:
            raise RuntimeError("credentials not set")
        tid = self._next_tid()
        req = StunMessage(method, CLASS_REQUEST, tid)
        req.attrs.append(Attr(ATTR_USERNAME, self.username.encode("utf-8")))
        req.attrs.append(Attr(ATTR_REALM, self.realm.encode("utf-8") if self.realm else b""))
        req.attrs.append(Attr(ATTR_NONCE, self.nonce.encode("utf-8") if self.nonce else b""))
        if extra:
            req.attrs.extend(extra)
        add_message_integrity(req, self.key)
        return req

    def allocate(self, lifetime: int | None = None) -> tuple[bool, int | None, int | None]:
        """Returns (ok, granted_lifetime, error_code)."""
        extra: list[Attr] = [
            Attr(ATTR_REQUESTED_TRANSPORT, struct.pack("!I", TRANSPORT_UDP << 24)),
        ]
        if lifetime is not None:
            extra.append(Attr(ATTR_LIFETIME, struct.pack("!I", lifetime)))
        req = self._authed_request(METHOD_ALLOCATE, extra)
        self.send_raw(encode(req))
        resp = self.recv_raw()
        vok, vreason = self.verify_authed_response(resp, req, METHOD_ALLOCATE)
        if not vok:
            return False, None, f"verify:{vreason}"
        if resp is None:
            return False, None, None
        if resp.cls == CLASS_ERROR:
            code, _ = decode_error_code(resp.get(ATTR_ERROR_CODE) or b"")
            if code in (401, 438) and resp.get(ATTR_NONCE):
                self.nonce = resp.get_text(ATTR_NONCE)
            return False, None, code
        self.alloc_lifetime = resp.get_u32(ATTR_LIFETIME)
        relayed = resp.get(ATTR_XOR_RELAYED_ADDRESS)
        if relayed:
            self.relayed_addr = decode_xor_addr(relayed, resp.transaction_id)
        mapped = resp.get(ATTR_XOR_MAPPED_ADDRESS)
        if mapped:
            self.mapped_addr = decode_xor_addr(mapped, resp.transaction_id)
        return True, self.alloc_lifetime, None

    def refresh(self, lifetime: int | None = None) -> tuple[bool, int | None, int | None]:
        """Refresh allocation. Returns (ok, granted_lifetime, error_code)."""
        extra: list[Attr] = []
        if lifetime is not None:
            extra.append(Attr(ATTR_LIFETIME, struct.pack("!I", lifetime)))
        req = self._authed_request(METHOD_REFRESH, extra)
        self.send_raw(encode(req))
        resp = self.recv_raw()
        vok, vreason = self.verify_authed_response(resp, req, METHOD_REFRESH)
        if not vok:
            return False, None, f"verify:{vreason}"
        if resp is None:
            return False, None, None
        if resp.cls == CLASS_ERROR:
            code, _ = decode_error_code(resp.get(ATTR_ERROR_CODE) or b"")
            if code in (401, 438) and resp.get(ATTR_NONCE):
                self.nonce = resp.get_text(ATTR_NONCE)
            return False, None, code
        self.alloc_lifetime = resp.get_u32(ATTR_LIFETIME)
        return True, self.alloc_lifetime, None

    def create_permission(self, peer_addr: str, peer_port: int, family: int = socket.AF_INET) -> tuple[bool, int | None]:
        tid = self._next_tid()
        req = StunMessage(METHOD_CREATE_PERMISSION, CLASS_REQUEST, tid)
        req.attrs.append(Attr(ATTR_USERNAME, self.username.encode("utf-8")))
        req.attrs.append(Attr(ATTR_REALM, self.realm.encode("utf-8") if self.realm else b""))
        req.attrs.append(Attr(ATTR_NONCE, self.nonce.encode("utf-8") if self.nonce else b""))
        req.attrs.append(Attr(ATTR_XOR_PEER_ADDRESS, encode_xor_addr(family, peer_addr, peer_port, tid)))
        add_message_integrity(req, self.key or b"")
        self.send_raw(encode(req))
        resp = self.recv_raw()
        vok, vreason = self.verify_authed_response(resp, req, METHOD_CREATE_PERMISSION)
        if not vok:
            return False, f"verify:{vreason}"
        if resp is None:
            return False, None
        if resp.cls == CLASS_ERROR:
            code, _ = decode_error_code(resp.get(ATTR_ERROR_CODE) or b"")
            return False, code
        return True, None

    def send_indication(self, peer_addr: str, peer_port: int, data: bytes, family: int = socket.AF_INET) -> None:
        tid = self._next_tid()
        msg = StunMessage(METHOD_SEND, CLASS_INDICATION, tid)
        msg.attrs.append(Attr(ATTR_XOR_PEER_ADDRESS, encode_xor_addr(family, peer_addr, peer_port, tid)))
        msg.attrs.append(Attr(ATTR_DATA, data))
        self.send_raw(encode(msg))

    def send_channel_data(self, channel_number: int, peer_addr: str, peer_port: int, data: bytes,
                          family: int = socket.AF_INET) -> None:
        # ChannelData: channel(2) length(2) data
        # Peer address is implied by prior ChannelBind; for lab we use Send indication instead.
        raise NotImplementedError("use send_indication")

    def recv_data(self, timeout: float = 2.0) -> tuple[tuple[str, int], bytes] | None:
        """Receive a Data indication (peer address + payload)."""
        self.sock.settimeout(timeout)
        try:
            if self.sock.type & socket.SOCK_STREAM:
                header = self._recv_exact(20)
                if header is None or len(header) < 20:
                    return None
                (length,) = struct.unpack("!H", header[2:4])
                rest = self._recv_exact(length) if length else b""
                if rest is None:
                    return None
                msg = decode(header + rest)
            else:
                data, _ = self.sock.recvfrom(65535)
                if len(data) < 20:
                    return None
                msg = decode(data)
        except socket.timeout:
            return None
        if msg.method != METHOD_DATA:
            return None
        peer = msg.get(ATTR_XOR_PEER_ADDRESS)
        payload = msg.get(ATTR_DATA) or b""
        addr = decode_xor_addr(peer, msg.transaction_id) if peer else ("", 0)
        return (addr[1], addr[2]), payload

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def connect_tcp(host: str, port: int) -> socket.socket:
    s = socket.create_connection((host, port), timeout=5.0)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def connect_udp(host: str, port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5.0)
    s.connect((host, port))
    return s
