from collections.abc import Callable
from scapy.sendrecv import sniff

# 패킷을 처리하는 함수 타입 정의
# 입력값으로 패킷 객체를 받고, 반환값은 없는 함수 형태
PacketHandler = Callable[[object], None]

# 패킷 캡처 중 발생한 예외를 표현하기 위한 사용자 정의 예외 클래스
class PacketCaptureError(RuntimeError):
    """패킷 캡처 초기화 또는 실행 실패를 나타낸다."""


# 지정한 네트워크 인터페이스에서 패킷 캡처를 시작하는 함수
def start_capture(interface: str, packet_handler: PacketHandler) -> None:
    try:
        # scapy에서 제공하는 패킷 캡쳐 함수
        sniff(
            iface = interface,      # 캡처할 네트워크 인터페이스 이름
            prn = packet_handler,   # 패킷이 캡처될 때마다 실행할 콜백 함수
            store = False,          # 캡처한 패킷을 메모리에 저장하지 않음
        )
    except PermissionError as exc:
        # 권한 부족으로 패킷 캡처에 실패한 경우
        # 일반적으로 관리자 권한 없이 실행했을 때 발생 가능
        raise PacketCaptureError(
            f"packet capture permission denied on interface {interface}."
        ) from exc
    except OSError as exc:
        # 존재하지 않는 인터페이스를 사용하거나,
        # 운영체제 수준에서 캡처에 실패한 경우
        raise PacketCaptureError(
            f"packet capture failed on interface {interface}:{exc}"
        ) from exc
    except ValueError as exc:
        # Scapy가 존재하지 않는 인터페이스를 ValueError로 보고하는 경우
        raise PacketCaptureError(
            f"packet capture failed on interface {interface}: {exc}"
        ) from exc
