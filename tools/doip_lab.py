"""DoIP 边界练习：未激活、超长、换地址。"""

from doipbench.doip import DiagnosticRejected, DoIPClient, DoIPFrame
from doipbench.doip.constants import PayloadType

PORT = 13400

c = DoIPClient(port=PORT).connect()
c.send_diagnostic(b"\x10\x03")
try:
    c.wait_diagnostic()
except DiagnosticRejected as e:
    print("练习1 未激活就发诊断 ->", hex(e.code), " 该是 0x2")
c.close()

c = DoIPClient(port=PORT).connect()
c.routing_activation()
try:
    c.request_uds(b"\x22" + bytes(5000))
except DiagnosticRejected as e:
    print("练习2 超长请求       ->", hex(e.code), " 该是 0x4")
c.close()

c = DoIPClient(port=PORT, client_address=0x0E00).connect()
print("练习3 首次激活       ->", hex(c.routing_activation().response_code))
c.send_frame(
    DoIPFrame(
        PayloadType.ROUTING_ACTIVATION_REQUEST, (0x0E01).to_bytes(2, "big") + b"\x00" + bytes(4)
    )
)
print("      换 0x0E01      ->", hex(c.receive_frame().payload[4]), " 该是 0x2")
c.send_frame(
    DoIPFrame(
        PayloadType.ROUTING_ACTIVATION_REQUEST, (0x0E00).to_bytes(2, "big") + b"\x00" + bytes(4)
    )
)
print("      原地址再激活  ->", hex(c.receive_frame().payload[4]), " 该是 0x3")
c.close()
