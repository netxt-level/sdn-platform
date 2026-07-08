#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def build_security_gateway_topo():
    # 네트워크 인스턴스 생성 (대역폭 제한 등 고급 링크(TCLink) 사용 가능하도록 설정)
    net = Mininet(switch=OVSKernelSwitch, link=TCLink, controller=None)

    info('*** 1. 컨트롤러 추가 (Docker Ryu와 연결)\n')
    # 호스트(WSL2)에서 도커 내부의 Ryu를 바라보도록 설정 (기본 포트 6633)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info('*** 2. 스위치 추가 (DPID를 명시적으로 고정)\n')
    # dpid를 16진수 문자열로 고정
    s1 = net.addSwitch('s1', dpid='0000000000000001', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', dpid='0000000000000002', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', dpid='0000000000000003', protocols='OpenFlow13')
    s4 = net.addSwitch('s4', dpid='0000000000000004', protocols='OpenFlow13')
    s5 = net.addSwitch('s5', dpid='0000000000000005', protocols='OpenFlow13')
    info('*** 3. 호스트 및 서버 추가 (고정 IP와 MAC 할당)\n')
    # 보안 정책(ACL/DDoS 탐지)을 위해 MAC 주소를 고정해두는 것이 필수입니다.
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01') # 사용자
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02') # 관리자
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03') # 공격자
    s_web = net.addHost('s_web', ip='10.0.0.100/24', mac='00:00:00:00:01:00')

    info('*** 4. 포트 맵핑 및 링크 연결\n')
    # --- [S1 하위 연결] ---
    net.addLink(h1, s1, port1=0, port2=1) # h1의 0번 포트 <-> s1의 1번 포트
    net.addLink(h2, s1, port1=0, port2=2)
    net.addLink(h3, s1, port1=0, port2=3)
    
    # --- [스위치 간 코어 망 연결 (루프 구조)] ---
    # S1 -> S2, S3
    net.addLink(s1, s2, port1=4, port2=1) 
    net.addLink(s1, s3, port1=5, port2=1) 
    
    # S2, S3 -> S4
    net.addLink(s2, s4, port1=2, port2=1)
    net.addLink(s3, s4, port1=2, port2=2)

    # --- [S4 하위 연결] ---
    net.addLink(s4, s_web, port1=3, port2=0)

    info('*** 5. 네트워크 시작\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])

    info('*** 6. Mininet CLI 진입\n')
    CLI(net)

    info('*** 7. 네트워크 종료\n')
    net.stop()

if __name__ == '__main__':
    # 로그 레벨을 info로 설정하여 실행 과정을 화면에 출력
    setLogLevel('info')
    build_security_gateway_topo()