"""Unit tests for the UDS server, driven without any socket.

These tests are the fastest way to pin down NRC behaviour: no TCP, no timing,
just request bytes in and response bytes out.
"""

from __future__ import annotations

import zlib

import pytest

from doipbench.config import SecurityConfig, default_config
from doipbench.uds import NegativeResponseCode as NRC
from doipbench.uds import Session, UdsServer, compute_key


class FakeClock:
    """Controllable monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def server(clock: FakeClock) -> UdsServer:
    config = default_config(s3_ms=1000, security=SecurityConfig(delay_seconds=0.5))
    return UdsServer(config, clock=clock)


def nrc(response: bytes) -> int:
    assert response[0] == 0x7F, response.hex()
    return response[2]


pytestmark = pytest.mark.unit


def test_session_control_encodes_p2_timings(server: UdsServer) -> None:
    response = server.handle(b"\x10\x03")
    assert response[:2] == b"\x50\x03"
    assert int.from_bytes(response[2:4], "big") == server.config.p2_ms
    assert int.from_bytes(response[4:6], "big") == server.config.p2_star_ms // 10


def test_unknown_session_is_rejected(server: UdsServer) -> None:
    assert nrc(server.handle(b"\x10\x09")) == NRC.SUB_FUNCTION_NOT_SUPPORTED


def test_security_access_requires_extended_session(server: UdsServer) -> None:
    assert nrc(server.handle(b"\x27\x01")) == NRC.SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION


def test_seed_key_flow_unlocks_the_ecu(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    seed_response = server.handle(b"\x27\x01")
    assert seed_response[0] == 0x67
    assert len(seed_response) == 2 + server.config.security.seed_length

    key = compute_key(seed_response[2:], server.config.security.secret)
    assert server.handle(b"\x27\x02" + key) == b"\x67\x02"
    assert server.security_level == 1


def test_wrong_key_counts_attempts(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    server.handle(b"\x27\x01")
    assert nrc(server.handle(b"\x27\x02\xde\xad\xbe\xef")) == NRC.INVALID_KEY
    assert server.failed_attempts == 1


def test_three_wrong_keys_lock_the_ecu(server: UdsServer, clock: FakeClock) -> None:
    server.handle(b"\x10\x03")
    for _ in range(3):
        server.handle(b"\x27\x01")
        assert nrc(server.handle(b"\x27\x02\xde\xad\xbe\xef")) == (
            NRC.INVALID_KEY if server.failed_attempts < 3 else NRC.EXCEED_NUMBER_OF_ATTEMPTS
        )
    assert nrc(server.handle(b"\x27\x01")) == NRC.REQUIRED_TIME_DELAY_NOT_EXPIRED

    clock.advance(server.config.security.delay_seconds + 0.1)
    assert server.handle(b"\x27\x01")[0] == 0x67


def test_send_key_without_seed_is_a_sequence_error(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    assert nrc(server.handle(b"\x27\x02\x00\x00\x00\x00")) == NRC.REQUEST_SEQUENCE_ERROR


def test_s3_timeout_returns_to_default_session(server: UdsServer, clock: FakeClock) -> None:
    server.handle(b"\x10\x03")
    assert server.session is Session.EXTENDED
    clock.advance(1.5)
    response = server.handle(b"\x22\xf1\x86")
    assert response == b"\x62\xf1\x86\x01"
    assert server.session is Session.DEFAULT


def test_tester_present_keeps_the_session_alive(server: UdsServer, clock: FakeClock) -> None:
    server.handle(b"\x10\x03")
    clock.advance(0.6)
    assert server.handle(b"\x3e\x00") == b"\x7e\x00"
    clock.advance(0.6)
    assert server.handle(b"\x22\xf1\x86") == b"\x62\xf1\x86\x03"


def test_read_multiple_dids_are_concatenated(server: UdsServer) -> None:
    response = server.handle(b"\x22\xf1\x90\xf1\x87")
    assert response[:3] == b"\x62\xf1\x90"
    assert b"8R0 907 115 A" in response


def test_read_unknown_did_is_rejected(server: UdsServer) -> None:
    assert nrc(server.handle(b"\x22\x12\x34")) == NRC.REQUEST_OUT_OF_RANGE


def test_write_is_rejected_in_default_session(server: UdsServer) -> None:
    response = server.handle(b"\x2e\x01\x00" + bytes(8))
    assert nrc(response) == NRC.SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION


def test_write_requires_unlock(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    assert nrc(server.handle(b"\x2e\x01\x00" + bytes(8))) == NRC.SECURITY_ACCESS_DENIED


def test_write_read_closed_loop(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    seed = server.handle(b"\x27\x01")[2:]
    server.handle(b"\x27\x02" + compute_key(seed, server.config.security.secret))

    value = bytes.fromhex("11 22 33 44 55 66 77 88")
    assert server.handle(b"\x2e\x01\x00" + value) == b"\x6e\x01\x00"
    assert server.handle(b"\x22\x01\x00") == b"\x62\x01\x00" + value


def test_write_with_wrong_length_is_rejected(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    seed = server.handle(b"\x27\x01")[2:]
    server.handle(b"\x27\x02" + compute_key(seed, server.config.security.secret))
    assert nrc(server.handle(b"\x2e\x01\x00\x00")) == NRC.INCORRECT_MESSAGE_LENGTH


def test_write_to_read_only_did_is_rejected(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    seed = server.handle(b"\x27\x01")[2:]
    server.handle(b"\x27\x02" + compute_key(seed, server.config.security.secret))
    assert nrc(server.handle(b"\x2e\xf1\x90" + b"X" * 17)) == NRC.REQUEST_OUT_OF_RANGE


def test_dtc_count_and_listing(server: UdsServer) -> None:
    assert server.handle(b"\x19\x01\xff") == b"\x59\x01\xff\x01\x00\x03"
    listing = server.handle(b"\x19\x02\xff")
    assert listing[:4] == b"\x59\x02\xff\xc1"


def test_dtc_mask_filters_pending_only(server: UdsServer) -> None:
    listing = server.handle(b"\x19\x02\x04")
    assert listing == b"\x59\x02\xff\xc1\x23\x87\x04"


def test_dtc_snapshot_contains_vin(server: UdsServer) -> None:
    response = server.handle(b"\x19\x04\xc1\x23\x45\x01")
    assert response[:6] == b"\x59\x04\xc1\x23\x45\x09"
    assert server.config.vin.encode("ascii") in response


def test_dtc_unknown_record_is_out_of_range(server: UdsServer) -> None:
    assert nrc(server.handle(b"\x19\x04\xc1\x23\x45\x09")) == NRC.REQUEST_OUT_OF_RANGE


def test_unsupported_service(server: UdsServer) -> None:
    # 0x85 ControlDTCSetting 没实现。0x31 现在实现了，不能再拿它当"不支持"的例子。
    assert nrc(server.handle(b"\x85\x02")) == NRC.SERVICE_NOT_SUPPORTED


def test_suppress_positive_response(server: UdsServer) -> None:
    assert server.handle(b"\x10\x83") == b""
    assert server.session is Session.EXTENDED


def test_reset_restores_factory_state(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    seed = server.handle(b"\x27\x01")[2:]
    server.handle(b"\x27\x02" + compute_key(seed, server.config.security.secret))
    server.handle(b"\x2e\x01\x00" + bytes(8))

    server.reset()
    assert server.session is Session.DEFAULT
    assert server.security_level == 0
    assert server.handle(b"\x22\x01\x00") == b"\x62\x01\x00" + bytes(8)


def test_lockout_must_survive_session_change():
    """锁定不能因为切会话而解除，否则 max_attempts 形同虚设。"""
    from doipbench.config import default_config
    from doipbench.uds.server import UdsServer

    srv = UdsServer(default_config())
    srv.handle(bytes([0x10, 0x03]))  # 进扩展会话

    for _ in range(3):  # 连续错 3 次
        srv.handle(bytes([0x27, 0x01]))  #   要种子
        srv.handle(bytes([0x27, 0x02]) + b"\x00\x00\x00\x00")

    assert srv.handle(bytes([0x27, 0x01])) == bytes([0x7F, 0x27, 0x37])

    srv.handle(bytes([0x10, 0x03]))  # 关键：切会话

    assert srv.handle(bytes([0x27, 0x01])) == bytes([0x7F, 0x27, 0x37])


def test_open_sockets_are_capped():
    """未激活的连接也必须设上限，否则一条脚本就能把线程和句柄耗尽。"""
    import socket
    import time

    from doipbench.config import default_config
    from doipbench.doip.server import DoIPServer

    cfg = default_config()
    cfg.max_open_sockets = 4
    srv = DoIPServer(cfg, port=0).start()
    socks = []
    try:
        for _ in range(10):
            socks.append(socket.create_connection(("127.0.0.1", srv.port)))
        time.sleep(0.5)
        assert srv.open_sockets() <= 4
    finally:
        for s in socks:
            s.close()
        srv.stop()


def test_lockout_window_expiry_restores_attempts():
    """锁定窗口结束后要重新给满次数，否则失败一次就又锁一轮。"""
    from doipbench.config import default_config
    from doipbench.uds.server import UdsServer

    srv = UdsServer(default_config())
    srv.handle(bytes([0x10, 0x03]))
    for _ in range(3):
        srv.handle(bytes([0x27, 0x01]))
        srv.handle(bytes([0x27, 0x02]) + b"\x00\x00\x00\x00")
    assert srv.handle(bytes([0x27, 0x01])) == bytes([0x7F, 0x27, 0x37])

    srv.lockout_until = 1.0  # 一个早已过去的时间点，触发窗口过期
    srv.handle(bytes([0x27, 0x01]))
    srv.handle(bytes([0x27, 0x02]) + b"\x00\x00\x00\x00")
    assert srv.failed_attempts == 1, "窗口过后应重新计数"


def test_report_supported_dtc_has_no_count_field():
    """0x19 0A 是 availabilityMask + 记录，没有 DTCCount；0x19 01 才有。"""
    from doipbench.config import default_config
    from doipbench.uds.server import UdsServer

    cfg = default_config()
    srv = UdsServer(cfg)
    resp = srv.handle(bytes([0x19, 0x0A]))
    assert resp[0:2] == bytes([0x59, 0x0A])
    assert resp[2] == cfg.dtc_status_availability_mask
    body = resp[3:]
    assert len(body) % 4 == 0

    count_resp = srv.handle(bytes([0x19, 0x01, 0xFF]))
    assert count_resp[0:2] == bytes([0x59, 0x01])
    assert int.from_bytes(count_resp[4:6], "big") * 4 == len(body)


def test_state_for_creates_only_one_state_under_concurrency(monkeypatch):
    """并发首次访问同一地址，只能创建一个 EcuState。"""
    import threading
    import time

    from doipbench.config import default_config
    from doipbench.doip import server as server_mod
    from doipbench.doip.server import DoIPServer

    srv = DoIPServer(default_config(), port=0)
    real = server_mod.EcuState
    created = []

    def slow(config):
        obj = real(config)
        created.append(obj)
        time.sleep(0.01)
        return obj

    monkeypatch.setattr(server_mod, "EcuState", slow)

    barrier = threading.Barrier(8)
    results = []
    guard = threading.Lock()

    def worker():
        barrier.wait()
        st = srv.state_for(0x1001)
        with guard:
            results.append(st)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(created) == 1
    assert len({id(r) for r in results}) == 1


def test_dtc_count_reports_availability_mask_not_request_mask(server: UdsServer) -> None:
    """0x19 01 的第三字节是 ECU 支持哪些 status bit，不能回显请求里的 mask。"""
    response = server.handle(b"\x19\x01\x08")
    assert response[:2] == b"\x59\x01"
    assert response[2] == server.config.dtc_status_availability_mask
    assert response[2] == 0xFF
    assert response[3] == 0x01


def test_dtc_by_status_reports_availability_mask_not_request_mask(server: UdsServer) -> None:
    """0x19 02 同上：首字节恒为 availability mask，与请求 mask 无关。"""
    response = server.handle(b"\x19\x02\x00")
    assert response[:3] == b"\x59\x02\xff"


# ------------------------------------------------------------------ 0x34/36/37
# 刷写只做「34 请求下载 → 36 传数据 → 37 退出」这一段：擦除、校验、复位没实现，
# README 里写了这条边界。下面每条都锁一个具体的拒绝理由，不看总数看原因。

FLASH_ADDRESS = 0x8000


def _enter_programming(server: UdsServer) -> None:
    """走完刷写的前置条件：编程会话 + 安全解锁。"""
    server.handle(b"\x10\x02")
    seed = server.handle(b"\x27\x01")[2:]
    server.handle(b"\x27\x02" + compute_key(seed, server.config.security.secret))


def _download_request(size: int, address: int = FLASH_ADDRESS) -> bytes:
    """dataFormat=0x00，ALFID=0x44（4 字节地址 + 4 字节长度）。"""
    return b"\x34\x00\x44" + address.to_bytes(4, "big") + size.to_bytes(4, "big")


def test_flash_sequence_writes_image(server: UdsServer) -> None:
    """完整三段跑完，写到 0x34 声明的位置，一个字节都不差。"""
    _enter_programming(server)

    response = server.handle(_download_request(10))
    assert response == b"\x74\x20\x01\x02"  # maxNumberOfBlockLength = 258

    assert server.handle(b"\x36\x01" + bytes(range(1, 7))) == b"\x76\x01"
    assert server.handle(b"\x36\x02" + bytes(range(7, 11))) == b"\x76\x02"
    assert server.handle(b"\x37") == b"\x77"

    image = server.flash_image()
    assert image[FLASH_ADDRESS : FLASH_ADDRESS + 10] == bytes(range(1, 11))


def test_flash_requires_programming_session(server: UdsServer) -> None:
    """扩展会话不能刷写：0x34 只在编程会话可用。"""
    server.handle(b"\x10\x03")
    assert nrc(server.handle(_download_request(10))) == NRC.SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION


def test_flash_requires_security_unlock(server: UdsServer) -> None:
    """进了编程会话但没解锁，仍然不许下载。"""
    server.handle(b"\x10\x02")
    assert nrc(server.handle(_download_request(10))) == NRC.SECURITY_ACCESS_DENIED


def test_request_download_rejects_address_beyond_flash(server: UdsServer) -> None:
    """地址 + 长度越过刷写区，回 0x31 而不是截断或写坏别的区域。"""
    _enter_programming(server)
    beyond = _download_request(0x100, address=server.config.flash_size - 0x10)
    assert nrc(server.handle(beyond)) == NRC.REQUEST_OUT_OF_RANGE


def test_request_download_rejects_compressed_format(server: UdsServer) -> None:
    """dataFormatIdentifier 非 0 表示压缩/加密，本实现不支持，必须明拒。"""
    _enter_programming(server)
    request = b"\x34\x11" + _download_request(10)[2:]
    assert nrc(server.handle(request)) == NRC.REQUEST_OUT_OF_RANGE


def test_request_download_rejects_inconsistent_length_format(server: UdsServer) -> None:
    """ALFID 声明 4+4 字节，实际只跟了 4 字节：长度对不上就 0x13。"""
    _enter_programming(server)
    request = b"\x34\x00\x44" + FLASH_ADDRESS.to_bytes(4, "big") + b"\x00\x00"
    assert nrc(server.handle(request)) == NRC.INCORRECT_MESSAGE_LENGTH


def test_transfer_data_rejects_wrong_sequence_counter(server: UdsServer) -> None:
    """块计数器要从 0x01 开始。直接发 0x02 是乱序，回 0x73 让 tester 重发。"""
    _enter_programming(server)
    server.handle(_download_request(10))
    assert nrc(server.handle(b"\x36\x02" + bytes(4))) == NRC.WRONG_BLOCK_SEQUENCE_COUNTER


def test_transfer_data_rejects_block_over_declared_size(server: UdsServer) -> None:
    """声明 4 字节却传 5 字节：不截断，回 0x71。"""
    _enter_programming(server)
    server.handle(_download_request(4))
    assert nrc(server.handle(b"\x36\x01" + bytes(5))) == NRC.TRANSFER_DATA_SUSPENDED


def test_transfer_exit_rejects_incomplete_payload(server: UdsServer) -> None:
    """声明 10 字节只传了 4 字节就 0x37：不写进去，也不当成功。"""
    _enter_programming(server)
    server.handle(_download_request(10))
    server.handle(b"\x36\x01" + bytes(4))

    assert nrc(server.handle(b"\x37")) == NRC.REQUEST_SEQUENCE_ERROR
    assert server.flash_image()[FLASH_ADDRESS : FLASH_ADDRESS + 10] == bytes(10)


def test_second_request_download_is_sequence_error(server: UdsServer) -> None:
    """上一个事务没 0x37 就再来一次 0x34：先退出或切会话。"""
    _enter_programming(server)
    server.handle(_download_request(10))
    assert nrc(server.handle(_download_request(10))) == NRC.REQUEST_SEQUENCE_ERROR


def test_session_change_aborts_download(server: UdsServer) -> None:
    """切会话会中断刷写事务，之后发 0x36 必须回 0x24 而不是拼到旧地址上。"""
    _enter_programming(server)
    server.handle(_download_request(10))

    _enter_programming(server)  # 10 02 重新进一次，事务应被丢弃
    assert nrc(server.handle(b"\x36\x01" + bytes(4))) == NRC.REQUEST_SEQUENCE_ERROR


# ------------------------------------------------------------- 0x31 / 0x11
# 擦除和校验是让"刷写"成为一个完整序列的最后两块：34 之前先擦，37 之后先校验，
# 校验通过才复位。下面每条仍然只锁一个拒绝理由。


def test_erase_clears_flash(server: UdsServer) -> None:
    """31 01 FF00 不带参数擦整片。先写 10 字节，擦完必须全是 0。"""
    _enter_programming(server)
    server.handle(_download_request(10))
    server.handle(b"\x36\x01" + bytes(range(1, 11)))
    assert server.handle(b"\x37") == b"\x77"
    assert server.flash_image()[FLASH_ADDRESS] == 0x01

    assert server.handle(b"\x31\x01\xff\x00") == b"\x71\x01\xff\x00\x00"
    assert server.flash_image() == bytes(server.config.flash_size)


def test_erase_requires_programming_session(server: UdsServer) -> None:
    """扩展会话不能擦：擦除和写入一样，只在编程会话可用。"""
    server.handle(b"\x10\x03")
    assert nrc(server.handle(b"\x31\x01\xff\x00")) == NRC.SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION


def test_routine_rejects_unknown_identifier(server: UdsServer) -> None:
    """不认识的 RID 回 0x31，不能静默当成功。"""
    _enter_programming(server)
    assert nrc(server.handle(b"\x31\x01\x12\x34")) == NRC.REQUEST_OUT_OF_RANGE


def test_routine_rejects_stop_subfunction(server: UdsServer) -> None:
    """只做 startRoutine（01）。stop（02）回 0x12，别假装支持。"""
    _enter_programming(server)
    assert nrc(server.handle(b"\x31\x02\xff\x00")) == NRC.SUB_FUNCTION_NOT_SUPPORTED


def test_erase_rejects_range_beyond_flash(server: UdsServer) -> None:
    """带参数的擦除：地址 + 长度越过刷写区，回 0x31。"""
    _enter_programming(server)
    request = (
        b"\x31\x01\xff\x00"
        + (server.config.flash_size - 0x10).to_bytes(4, "big")
        + (0x100).to_bytes(4, "big")
    )
    assert nrc(server.handle(request)) == NRC.REQUEST_OUT_OF_RANGE


def test_verify_reports_crc_and_detects_mismatch(server: UdsServer) -> None:
    """不带参数回报 CRC，带参数就比对：对回 0x00，错回 0x01。"""
    _enter_programming(server)
    server.handle(b"\x31\x01\xff\x00")
    expected = zlib.crc32(server.flash_image()).to_bytes(4, "big")

    assert server.handle(b"\x31\x01\xff\x01") == b"\x71\x01\xff\x01" + expected
    assert server.handle(b"\x31\x01\xff\x01" + expected) == b"\x71\x01\xff\x01\x00"
    assert server.handle(b"\x31\x01\xff\x01" + bytes(4)) == b"\x71\x01\xff\x01\x01"


def test_ecu_reset_returns_to_default_session(server: UdsServer) -> None:
    """11 01 之后会话回默认、安全锁上，和重新上电一个效果。"""
    _enter_programming(server)
    assert server.session is Session.PROGRAMMING
    assert server.security_level == 1

    assert server.handle(b"\x11\x01") == b"\x51\x01"
    assert server.session is Session.DEFAULT
    assert server.security_level == 0


def test_ecu_reset_clears_lockout(server: UdsServer) -> None:
    """复位把 0x27 的错误计数清零——这是真实 ECU 的已知弱点，如实实现并锁住。"""
    server.handle(b"\x10\x03")
    for _ in range(server.config.security.max_attempts):
        server.handle(b"\x27\x01")
        server.handle(b"\x27\x02\x00\x00\x00\x00")
    assert nrc(server.handle(b"\x27\x01")) == NRC.REQUIRED_TIME_DELAY_NOT_EXPIRED

    server.handle(b"\x11\x01")
    server.handle(b"\x10\x03")
    assert server.handle(b"\x27\x01")[0] == 0x67


def test_full_flash_sequence_end_to_end(server: UdsServer) -> None:
    """擦除 → 下载 → 两块数据 → 退出 → 校验 → 复位，一条链走完。"""
    _enter_programming(server)

    assert server.handle(b"\x31\x01\xff\x00") == b"\x71\x01\xff\x00\x00"
    assert server.handle(_download_request(10)) == b"\x74\x20\x01\x02"
    assert server.handle(b"\x36\x01" + bytes(range(1, 7))) == b"\x76\x01"
    assert server.handle(b"\x36\x02" + bytes(range(7, 11))) == b"\x76\x02"
    assert server.handle(b"\x37") == b"\x77"

    checksum = zlib.crc32(server.flash_image()).to_bytes(4, "big")
    assert server.handle(b"\x31\x01\xff\x01" + checksum) == b"\x71\x01\xff\x01\x00"
    assert server.handle(b"\x11\x01") == b"\x51\x01"

    assert server.flash_image()[FLASH_ADDRESS : FLASH_ADDRESS + 10] == bytes(range(1, 11))
    assert server.session is Session.DEFAULT
