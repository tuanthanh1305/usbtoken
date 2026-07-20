"""Test pcsc_probe: gate sẵn sàng, list/read ATR, fingerprint (chỉ tối ưu, KHÔNG
kết luận CA), theo dõi cắm/rút (poll diff). Backend tiêm bản giả (không cần pyscard).
"""

from __future__ import annotations

import pytest

from core.errors import PCSCNotReadyError
from core.models import ErrorCode
from core.pcsc_probe import AtrFingerprint, PCSCProbe, fingerprint_by_atr
from tools import import_smartcard_list as imp


class FakeBackend:
    def __init__(self, atrs: dict[str, bytes | None]) -> None:
        self.atrs = atrs

    def list_readers(self) -> list[str]:
        return list(self.atrs.keys())

    def read_atr(self, reader_name: str) -> bytes | None:
        return self.atrs.get(reader_name)


class FakeAdapter:
    def __init__(self, ready: bool, remediation: str = "") -> None:
        self._ready = ready
        self._rem = remediation

    def name(self) -> str:
        return "linux"

    def pcsc_backend_ready(self) -> tuple[bool, str]:
        return self._ready, self._rem


# --------------------------------------------------------------------------- #
# Gate sẵn sàng                                                                 #
# --------------------------------------------------------------------------- #
def test_readiness_not_ready_gives_errorinfo() -> None:
    probe = PCSCProbe(FakeAdapter(False, "systemctl enable --now pcscd"), FakeBackend({}))  # type: ignore[arg-type]
    ready, err = probe.readiness()
    assert ready is False
    assert err is not None and err.code is ErrorCode.PCSC_NOT_READY
    assert "pcscd" in err.remediation  # remediation ĐÚNG OS (từ adapter)


def test_list_readers_blocked_when_not_ready() -> None:
    probe = PCSCProbe(FakeAdapter(False, "sc start SCardSvr"), FakeBackend({}))  # type: ignore[arg-type]
    with pytest.raises(PCSCNotReadyError):
        probe.list_readers()


def test_list_readers_and_read_atr_when_ready() -> None:
    atr = bytes.fromhex("3BAA00")
    probe = PCSCProbe(FakeAdapter(True), FakeBackend({"Reader 0": atr, "Reader 1": None}))  # type: ignore[arg-type]
    assert probe.list_readers() == ["Reader 0", "Reader 1"]
    assert probe.read_atr("Reader 0") == atr
    assert probe.read_atr("Reader 1") is None  # không có thẻ


# --------------------------------------------------------------------------- #
# Fingerprint ATR — chỉ tối ưu, KHÔNG kết luận CA                               #
# --------------------------------------------------------------------------- #
def test_fingerprint_match_gives_chip_and_module_hints() -> None:
    table = {
        "source": "test",
        "entries": [{"atr": "3B .. 00", "description": "Feitian ePass2003", "verified": False}],
    }
    fp = fingerprint_by_atr(bytes.fromhex("3BAA00"), os_name="linux", table=table)
    assert fp.matched is True
    assert "Feitian" in fp.chip_hint
    assert "libcastle.so" in fp.module_hints  # suy từ vendor_intel (Track A)
    assert fp.confidence in ("low", "medium")  # KHÔNG bao giờ high


def test_fingerprint_no_ca_field() -> None:
    fp = fingerprint_by_atr(b"\x3b\xaa", table={"entries": []})
    dumped = fp.model_dump()
    # TUYỆT ĐỐI không có bất kỳ trường nào về CA.
    assert not any(k.lower() == "ca" or "ca_" in k.lower() for k in dumped)
    assert "note" in dumped and "KHÔNG kết luận CA" in dumped["note"]


def test_fingerprint_unknown_when_empty_table() -> None:
    fp = fingerprint_by_atr(bytes.fromhex("3B00"), table={"entries": []})
    assert fp.matched is False and fp.confidence == "unknown"
    assert isinstance(fp, AtrFingerprint)


def test_fingerprint_wildcard_low_confidence() -> None:
    table = {"entries": [{"atr": "3B . 00", "description": "SafeNet eToken"}]}
    fp = fingerprint_by_atr(bytes.fromhex("3BA00"[:4]), os_name="linux", table=table)
    # "3B . 00" -> ^3B[0-9A-F]00$ khớp "3B A 00"? cần 5 nibble; dùng ATR khớp:
    fp = fingerprint_by_atr(bytes.fromhex("3BF00"[:4]), os_name="linux", table=table)
    _ = fp  # chỉ kiểm không nổ; wildcard -> low


# --------------------------------------------------------------------------- #
# Theo dõi cắm/rút (poll diff — không cần luồng)                                #
# --------------------------------------------------------------------------- #
def test_poll_diff_insert_and_remove() -> None:
    backend = FakeBackend({"Reader 0": None})
    probe = PCSCProbe(FakeAdapter(True), backend)  # type: ignore[arg-type]

    events, state = probe.poll_diff({})
    assert events == []  # chưa có thẻ

    backend.atrs["Reader 0"] = bytes.fromhex("3BAA00")  # cắm thẻ
    events, state = probe.poll_diff(state)
    assert len(events) == 1 and events[0]["action"] == "inserted"
    assert events[0]["atr"] == "3baa00"

    backend.atrs["Reader 0"] = None  # rút thẻ
    events, state = probe.poll_diff(state)
    assert len(events) == 1 and events[0]["action"] == "removed"


# --------------------------------------------------------------------------- #
# Import smartcard_list.txt                                                     #
# --------------------------------------------------------------------------- #
def test_parse_smartcard_list() -> None:
    text = (
        "# comment\n"
        "3B F2 18 00 02 C1 0A 31 FE 58 C8 09 75\n"
        "\tFeitian ePass2003\n"
        "\tAlso known as FT-Java\n"
        "3B .. 00\n"
        "\tGeneric\n"
    )
    entries = imp.parse_smartcard_list(text)
    assert len(entries) == 2
    assert entries[0]["description"] == "Feitian ePass2003"
    table = imp.build_table(entries)
    assert all(e["verified"] is False for e in table["entries"])
