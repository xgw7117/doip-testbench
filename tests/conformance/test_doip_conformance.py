"""DoIP conformance tests (ISO 13400-2).

The cases here focus on the parts that are easy to get wrong in a student
project and expensive to debug on a real bench: framing over a byte stream,
routing activation state, and the difference between a generic NACK and a
diagnostic NACK.
"""

from __future__ import annotations

import socket
import struct
import time

import allure
import pytest

from doipbench.config import EcuConfig, default_config
from doipbench.doip import (
    DiagnosticRejected,
    DoIPClient,
    DoIPConnectionClosed,
    DoIPFrame,
    DoIPServer,
    DoIPTimeout,
    EntityStatus,
)
from doipbench.doip.constants import (
    DiagnosticAckCode,
    GenericNackCode,
    PayloadType,
    RoutingActivationResponseCode,
)
from doipbench.uds.security import compute_key


def _routing_payload(client_address: int, activation_type: int = 0x00) -> bytes:
    return client_address.to_bytes(2, "big") + bytes([activation_type]) + bytes(4)


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Vehicle identification")
def test_vehicle_identification_response(client: DoIPClient, ecu_config: EcuConfig) -> None:
    announcement = client.read_vehicle_identification()
    assert announcement.vin == ecu_config.vin
    assert announcement.logical_address == ecu_config.logical_address
    assert announcement.eid == ecu_config.eid
    assert announcement.gid == ecu_config.gid
    assert announcement.further_action == 0x10


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Vehicle identification")
def test_identification_by_eid_matches(client: DoIPClient, ecu_config: EcuConfig) -> None:
    client.send_frame(DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_EID, ecu_config.eid))
    announcement = client.wait_announcement()
    assert announcement.vin == ecu_config.vin


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Vehicle identification")
def test_identification_by_eid_ignores_other_entity(client: DoIPClient) -> None:
    client.send_frame(
        DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_EID, bytes.fromhex("FFFFFFFFFFFF"))
    )
    with pytest.raises(DoIPTimeout):
        client.wait_announcement(timeout=0.3)


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Vehicle identification")
def test_identification_by_vin_matches(client: DoIPClient, ecu_config: EcuConfig) -> None:
    client.send_frame(
        DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_VIN, ecu_config.vin.encode("ascii"))
    )
    announcement = client.wait_announcement()
    assert announcement.logical_address == ecu_config.logical_address


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Vehicle identification")
def test_identification_by_vin_ignores_other_vehicle(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_VIN, b"X" * 17))
    with pytest.raises(DoIPTimeout):
        client.wait_announcement(timeout=0.3)


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Vehicle identification")
def test_identification_with_wrong_vin_length_is_nacked(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_VIN, b"SHORT"))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.GENERIC_NEGATIVE_ACK
    assert (
        int.from_bytes(frame.payload[:2], "big") == PayloadType.VEHICLE_IDENTIFICATION_REQUEST_VIN
    )
    assert frame.payload[2] == GenericNackCode.INVALID_PAYLOAD_LENGTH


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_routing_activation_is_accepted(client: DoIPClient, ecu_config: EcuConfig) -> None:
    result = client.routing_activation()
    assert result.response_code == RoutingActivationResponseCode.ACCEPTED
    assert result.client_address == client.client_address
    assert result.entity_address == ecu_config.entity_address


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_routing_activation_with_oem_specific_data(client: DoIPClient) -> None:
    result = client.routing_activation(oem=b"\x01\x02\x03\x04")
    assert result.accepted


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_duplicate_routing_activation_is_idempotent(client: DoIPClient) -> None:
    # 同一条 socket 上用同一个 SA 重申是幂等的：0x03 的定义是"该 SA 已在
    # **另一条** socket 上激活"，把它用在这里会让 tester 重发一次就掉线。
    assert client.routing_activation().accepted
    second = client.routing_activation()
    assert second.accepted


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_second_source_address_on_same_socket_is_denied(client: DoIPClient) -> None:
    assert client.routing_activation().accepted
    client.send_frame(DoIPFrame(PayloadType.ROUTING_ACTIVATION_REQUEST, _routing_payload(0x0E01)))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.ROUTING_ACTIVATION_RESPONSE
    assert (
        frame.payload[4] == RoutingActivationResponseCode.DENIED_SA_DIFFERENT_FROM_ALREADY_ACTIVATED
    )


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_zero_source_address_is_denied(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(PayloadType.ROUTING_ACTIVATION_REQUEST, _routing_payload(0x0000)))
    frame = client.receive_frame()
    assert frame.payload[4] == RoutingActivationResponseCode.DENIED_UNKNOWN_SOURCE_ADDRESS


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_unsupported_activation_type_is_denied(client: DoIPClient) -> None:
    payload = _routing_payload(client.client_address, activation_type=0x07)
    client.send_frame(DoIPFrame(PayloadType.ROUTING_ACTIVATION_REQUEST, payload))
    frame = client.receive_frame()
    assert (
        frame.payload[4] == RoutingActivationResponseCode.DENIED_UNSUPPORTED_ROUTING_ACTIVATION_TYPE
    )


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_routing_activation_with_bad_length_is_nacked(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(PayloadType.ROUTING_ACTIVATION_REQUEST, bytes(6)))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.GENERIC_NEGATIVE_ACK
    assert frame.payload[2] == GenericNackCode.INVALID_PAYLOAD_LENGTH


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic messages")
def test_diagnostic_before_routing_activation_is_nacked(client: DoIPClient) -> None:
    client.send_diagnostic(b"\x10\x03")
    with pytest.raises(DiagnosticRejected) as error:
        client.wait_diagnostic()
    assert error.value.code == 0x02  # ISO Table 26: invalid source address


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic messages")
def test_diagnostic_to_unknown_target_is_nacked(routed_client: DoIPClient) -> None:
    routed_client.send_diagnostic(b"\x10\x03", target=0x1234)
    with pytest.raises(DiagnosticRejected) as error:
        routed_client.wait_diagnostic()
    assert error.value.code == 0x03  # ISO Table 26: unknown target address


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic acknowledgement")
def test_diagnostic_message_is_acknowledged_before_the_response(
    routed_client: DoIPClient, ecu_config: EcuConfig
) -> None:
    """0x8002 first, 0x8001 carrying the UDS answer second.

    ``python-doipclient`` blocks on the acknowledgement and drops anything else
    as "unexpected", so an entity that answers with 0x8001 alone looks exactly
    like an entity that never answered.
    """
    routed_client.send_diagnostic(b"\x22\xf1\x90")

    ack = routed_client.receive_frame()
    assert ack.payload_type == PayloadType.DIAGNOSTIC_MESSAGE_ACK
    assert ack.payload == (
        ecu_config.logical_address.to_bytes(2, "big")
        + routed_client.client_address.to_bytes(2, "big")
        + bytes([DiagnosticAckCode.ACCEPTED])
    )

    response = routed_client.receive_frame()
    assert response.payload_type == PayloadType.DIAGNOSTIC_MESSAGE
    assert response.payload[4:].startswith(b"\x62\xf1\x90")


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic acknowledgement")
def test_acknowledgement_can_be_disabled_for_internal_nodes() -> None:
    """A node behind a gateway must not ack: the edge node already did.

    Two acknowledgements for one request upset the tester's P6Client timer,
    which is why ISO 13400-2 leaves this configurable per node role.
    """
    config = default_config(ack_diagnostic_messages=False)
    with DoIPServer(config) as server, DoIPClient(port=server.port, timeout=2.0) as client:
        assert client.routing_activation().accepted
        client.send_diagnostic(b"\x22\xf1\x90")
        frame = client.receive_frame()
        assert frame.payload_type == PayloadType.DIAGNOSTIC_MESSAGE
        assert frame.payload[4:].startswith(b"\x62\xf1\x90")


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic messages")
def test_truncated_diagnostic_message_is_nacked(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, b"\x0e\x00"))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.DIAGNOSTIC_MESSAGE_NACK
    assert frame.payload[4] == 0x08  # ISO Table 26: transport protocol error


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Generic NACK")
def test_unknown_payload_type_is_nacked(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(0x1234, b""))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.GENERIC_NEGATIVE_ACK
    assert int.from_bytes(frame.payload[:2], "big") == 0x1234
    assert frame.payload[2] == GenericNackCode.UNKNOWN_PAYLOAD_TYPE


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Generic NACK")
def test_oversized_payload_is_nacked_and_connection_closed(client: DoIPClient) -> None:
    header = struct.pack(">BBHI", 0x02, 0xFD, PayloadType.DIAGNOSTIC_MESSAGE, 0x00FFFFFF)
    client.send_raw(header)
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.GENERIC_NEGATIVE_ACK
    assert frame.payload[2] == GenericNackCode.MESSAGE_TOO_LARGE
    with pytest.raises((DoIPConnectionClosed, DoIPTimeout)):
        client.receive_frame(timeout=0.5)


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Header validation")
def test_unsupported_protocol_version_closes_connection(client: DoIPClient) -> None:
    client.send_raw(struct.pack(">BBHI", 0x01, 0xFE, PayloadType.VEHICLE_IDENTIFICATION_REQUEST, 0))
    with pytest.raises((DoIPConnectionClosed, DoIPTimeout)):
        client.receive_frame(timeout=0.5)


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Header validation")
def test_inverse_version_mismatch_gets_nack(client: DoIPClient) -> None:
    client.send_raw(struct.pack(">BBHI", 0x02, 0x00, PayloadType.VEHICLE_IDENTIFICATION_REQUEST, 0))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.GENERIC_NEGATIVE_ACK
    assert frame.payload[2] == GenericNackCode.INCORRECT_PATTERN_FORMAT


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Alive check")
def test_alive_check_echoes_source_address(routed_client: DoIPClient) -> None:
    assert routed_client.alive_check() == routed_client.client_address


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Entity status")
def test_entity_status_reports_capabilities(client: DoIPClient, ecu_config: EcuConfig) -> None:
    status: EntityStatus = client.entity_status()
    assert status.node_type == 0x01
    assert status.max_concurrent_sockets == ecu_config.max_concurrent_sockets
    assert status.max_data_size == ecu_config.max_data_size
    assert status.open_sockets >= 1


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Power mode")
def test_power_mode_is_ready(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(PayloadType.POWER_MODE_INFORMATION_REQUEST))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.POWER_MODE_INFORMATION_RESPONSE
    assert frame.payload == b"\x01"


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Framing")
def test_two_frames_in_one_tcp_segment(routed_client: DoIPClient) -> None:
    """Sticky packets: two alive checks coalesced into one send()."""
    request = DoIPFrame(PayloadType.ALIVE_CHECK_REQUEST).encode()
    routed_client.send_raw(request + request)
    first = routed_client.receive_frame()
    second = routed_client.receive_frame()
    for frame in (first, second):
        assert frame.payload_type == PayloadType.ALIVE_CHECK_RESPONSE
        assert int.from_bytes(frame.payload, "big") == routed_client.client_address


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Framing")
def test_split_frame_reassembled_from_three_segments(routed_client: DoIPClient) -> None:
    """Split frames: header, partial payload, remainder."""
    frame = DoIPFrame(PayloadType.ENTITY_STATUS_REQUEST).encode()
    for chunk in (frame[:3], frame[3:7], frame[7:]):
        routed_client.send_raw(chunk)
        time.sleep(0.01)
    response = routed_client.receive_frame(timeout=1.0)
    assert response.payload_type == PayloadType.ENTITY_STATUS_RESPONSE


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Framing")
def test_byte_by_byte_transmission(routed_client: DoIPClient) -> None:
    frame = DoIPFrame(PayloadType.POWER_MODE_INFORMATION_REQUEST).encode()
    for byte in frame:
        routed_client.send_raw(bytes([byte]))
    response = routed_client.receive_frame(timeout=1.0)
    assert response.payload_type == PayloadType.POWER_MODE_INFORMATION_RESPONSE


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Resource limits")
def test_fourth_socket_is_denied_when_three_are_active() -> None:
    """A separate ECU instance keeps the assertion independent of other tests."""
    config = default_config(max_concurrent_sockets=3)
    with DoIPServer(config) as server:
        # 每个 client 用不同的 SA：同一个 SA 在第二条 socket 上会被 0x03 拒掉，
        # 那样就测不到"socket 名额已满"这条路径了。
        clients = [
            DoIPClient(port=server.port, client_address=0x0E00 + index).connect()
            for index in range(4)
        ]
        try:
            for client in clients[:3]:
                assert client.routing_activation().accepted
            denied = clients[3].routing_activation()
            assert (
                denied.response_code == RoutingActivationResponseCode.DENIED_ALL_SOCKETS_REGISTERED
            )
        finally:
            for client in clients:
                client.close()


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Alive check")
def test_alive_check_on_unactivated_connection_closes_it(client: DoIPClient) -> None:
    """未路由激活就发 0x0007，服务端应关闭连接。

    以前这里会回一个 0x0008 + 0x0000，等于告诉 tester「ECU 的逻辑地址是
    0x0000」，比不响应更糟：静默关闭至少让 tester 知道连接没激活。
    """
    client.send_frame(DoIPFrame(PayloadType.ALIVE_CHECK_REQUEST))
    with pytest.raises(DoIPConnectionClosed):
        client.receive_frame()


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Connection lifecycle")
def test_idle_connection_is_reclaimed_after_inactivity_timeout() -> None:
    """空闲连接要被回收，否则会永久占着 ``max_concurrent_sockets`` 名额。

    拔网线、ECU 掉电的对端不会发 FIN 也不会发 RST，服务端只能靠空闲计时发现。
    这里把阈值压到 0.5s、并发上限压到 1，直接观察第二个 tester 从「被拒」到
    「能激活」——这就是现场连不上的那个症状。
    """
    config = default_config(max_concurrent_sockets=1, inactivity_timeout=0.5)
    with DoIPServer(config) as server:
        idle = DoIPClient(port=server.port, timeout=2.0).connect()
        # 换一个 SA：同 SA 第二条连接会被 0x03 拦下（那是另一条用例），
        # 这里要观察的是并发名额，不是 SA 冲突。
        second = DoIPClient(port=server.port, timeout=2.0, client_address=0x0E01).connect()
        try:
            assert idle.routing_activation().accepted

            denied = second.routing_activation()
            assert (
                denied.response_code == RoutingActivationResponseCode.DENIED_ALL_SOCKETS_REGISTERED
            )

            # ISO 13400-2 §9.4.2：响应码不是 0x10 时实体关闭 socket。被拒的
            # tester 必须重连，不能在这条连接上继续发——那样既不合规，也会把
            # "被拒关闭"和"空闲回收"混成同一种现象，测不出名额有没有松开。
            with pytest.raises(DoIPConnectionClosed):
                second.receive_frame(timeout=1.0)
            second.close()

            # idle 从此一个字节都不发，等价于拔线：没有 FIN/RST 可等。
            time.sleep(1.2)

            retry = DoIPClient(port=server.port, timeout=2.0, client_address=0x0E01).connect()
            try:
                assert retry.routing_activation().accepted
            finally:
                retry.close()
        finally:
            idle.close()
            second.close()


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Connection lifecycle")
def test_active_connection_survives_inactivity_timeout() -> None:
    """空闲判定看最后一次收发，不是连接建立时间。

    没有这条，把超时实现成「连接活了 N 秒就关」也能过上面的用例，却会掐掉
    正在跑长流程的 tester（刷写时两次 0x36 之间本来就可能有间隔）。
    """
    config = default_config(inactivity_timeout=0.5)
    with DoIPServer(config) as server, DoIPClient(port=server.port, timeout=2.0) as client:
        assert client.routing_activation().accepted
        deadline = time.monotonic() + 1.2
        while time.monotonic() < deadline:
            assert client.alive_check() == client.client_address
            time.sleep(0.2)


# ---------------------------------------------------------------- raw probes
#
# 下面几条用裸 socket 而不是 DoIPClient：它们要验证的正是"客户端库不可能
# 自己发出来"的报文（2019 版开头、功能寻址、复位后的断链）。用自带客户端
# 测这些等于让出题人自己答题。


def _raw_connect(server: DoIPServer) -> socket.socket:
    return socket.create_connection(("127.0.0.1", server.port), timeout=2.0)


def _raw_send(sock: socket.socket, version: int, payload_type: int, payload: bytes) -> None:
    header = struct.pack(">BBHI", version, (~version) & 0xFF, payload_type, len(payload))
    sock.sendall(header + payload)


def _raw_recv(sock: socket.socket) -> tuple[int, int, bytes]:
    header = b""
    while len(header) < 8:
        chunk = sock.recv(8 - len(header))
        if not chunk:
            raise DoIPConnectionClosed("peer closed while reading header")
        header += chunk
    version, _inverse, payload_type, length = struct.unpack(">BBHI", header)
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise DoIPConnectionClosed("peer closed while reading payload")
        body += chunk
    return version, payload_type, body


def _raw_uds(sock: socket.socket, request: bytes, target: int = 0x1001) -> bytes:
    """Send one UDS request, skip the 0x8002 ack, return the UDS response."""
    _raw_send(
        sock,
        0x03,
        PayloadType.DIAGNOSTIC_MESSAGE,
        b"\x0e\x00" + target.to_bytes(2, "big") + request,
    )
    while True:
        _version, payload_type, body = _raw_recv(sock)
        if payload_type == PayloadType.DIAGNOSTIC_MESSAGE:
            return body[4:]


def _activate(sock: socket.socket, client_address: int = 0x0E00) -> None:
    _raw_send(sock, 0x03, PayloadType.ROUTING_ACTIVATION_REQUEST, _routing_payload(client_address))
    _raw_recv(sock)


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Protocol version")
def test_iso_13400_2_2019_handshake_is_accepted() -> None:
    """0x03 是 2019 版的开头，2019 以后的工具链默认用它。

    只认 0x02 时这类 tester 连握手都过不去，而且拿不到任何错误码——现象和
    "ECU 没上电"一模一样。响应也必须回 0x03，回 0x02 同样会被对端丢弃。
    """
    with DoIPServer(default_config()) as server:
        sock = _raw_connect(server)
        try:
            _raw_send(sock, 0x03, PayloadType.ROUTING_ACTIVATION_REQUEST, _routing_payload(0x0E00))
            version, payload_type, body = _raw_recv(sock)
        finally:
            sock.close()

    assert version == 0x03
    assert payload_type == PayloadType.ROUTING_ACTIVATION_RESPONSE
    assert body[4] == RoutingActivationResponseCode.ACCEPTED


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Functional addressing")
def test_functional_address_reaches_the_ecu() -> None:
    """真实 tester 的第一帧永远是功能寻址的 10 03。

    只认单播时 TA=0xE400 会回 0x8003，后面整条序列一步都走不了。响应里的
    SA 必须是回应的那台 ECU，而不是 0xE400——tester 靠 SA 判断谁答的。
    """
    with DoIPServer(default_config()) as server:
        sock = _raw_connect(server)
        try:
            _activate(sock)
            _raw_send(
                sock,
                0x03,
                PayloadType.DIAGNOSTIC_MESSAGE,
                b"\x0e\x00" + b"\xe4\x00" + b"\x10\x03",
            )
            while True:
                _version, payload_type, body = _raw_recv(sock)
                if payload_type == PayloadType.DIAGNOSTIC_MESSAGE:
                    break
        finally:
            sock.close()

    assert body[0:2] == b"\x10\x01"  # SA 是 ECU 自己
    assert body[2:4] == b"\x0e\x00"  # TA 是 tester
    assert body[4:6] == b"\x50\x03"


@pytest.mark.conformance
@allure.feature("UDS conformance")
@allure.story("Session control")
def test_security_access_survives_extended_to_programming() -> None:
    """扩展 -> 解锁 -> 编程 -> 34 是真实 OEM 的常规刷写序列。

    ISO 14229-1 只在**回到默认会话**时才要求复位安全访问。切会话就清
    security_level 会让这里必然 0x33，而自己写的 shell 走 10 02 -> 27
    绕开了这条路径，所以用例集原本一条都没抓到。
    """
    config = default_config()
    with DoIPServer(config) as server:
        sock = _raw_connect(server)
        try:
            _activate(sock)
            assert _raw_uds(sock, b"\x10\x03")[:2] == b"\x50\x03"
            seed = _raw_uds(sock, b"\x27\x01")[2:]
            key = compute_key(seed, config.security.secret)
            assert _raw_uds(sock, b"\x27\x02" + key)[:2] == b"\x67\x02"
            assert _raw_uds(sock, b"\x10\x02")[:2] == b"\x50\x02"
            download = bytes.fromhex("340044") + (0).to_bytes(4, "big") + (16).to_bytes(4, "big")
            assert _raw_uds(sock, download)[0] == 0x74
        finally:
            sock.close()


@pytest.mark.conformance
@allure.feature("UDS conformance")
@allure.story("Clear diagnostic information")
def test_clear_diagnostic_information_empties_the_dtc_list() -> None:
    """读得出、清不掉，维修闭环就断在第二步。"""
    with DoIPServer(default_config()) as server:
        sock = _raw_connect(server)
        try:
            _activate(sock)
            assert _raw_uds(sock, b"\x19\x02\x09")[3:] != b""  # 先确认有 DTC
            assert _raw_uds(sock, b"\x14\xff\xff\xff") == b"\x54"
            assert _raw_uds(sock, b"\x19\x02\x09")[3:] == b""
        finally:
            sock.close()


@pytest.mark.conformance
@allure.feature("UDS conformance")
@allure.story("ECU reset")
def test_ecu_reset_closes_the_connection() -> None:
    """真 ECU 复位会断链，刷写工具靠"等 socket 关闭"判断复位完成。

    不断链时它只能一直等到 P2* 超时，日志里表现为"复位后无响应"。
    """
    with DoIPServer(default_config()) as server:
        sock = _raw_connect(server)
        try:
            _activate(sock)
            assert _raw_uds(sock, b"\x11\x01") == b"\x51\x01"
            with pytest.raises(DoIPConnectionClosed):
                _raw_recv(sock)
        finally:
            sock.close()


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_same_source_address_on_second_socket_is_denied() -> None:
    """0x03 的含义是"该 SA 已在另一条 socket 上激活"，不是"本 socket 重申"。

    原来这两件事写反了：同一 SA 开两条连接都能拿到 0x10，而同一 socket
    重发一次反而被拒——tester 只要重试一次就掉线。
    """
    with DoIPServer(default_config()) as server:
        first = DoIPClient(port=server.port, client_address=0x0E00).connect()
        second = DoIPClient(port=server.port, client_address=0x0E00).connect()
        try:
            assert first.routing_activation().accepted
            assert (
                second.routing_activation().response_code
                == RoutingActivationResponseCode.DENIED_SA_ALREADY_REGISTERED
            )
        finally:
            first.close()
            second.close()
