from os import link

from ryu.base import app_manager
from ryu.controller import ofp_event # 이벤트들을 정의한 모듈
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3 # OpenFlow 1.3 ver
from ryu.lib.packet import packet, ethernet, ipv4
import heapq # Dijkstra 알고리즘을 위한 우선순위 Queue
import requests
from datetime import datetime

from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from webob import Response
import json
from datetime import datetime

class MyRyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'wsgi': WSGIApplication} # [방화벽] WSGI 서버 컨텍스트 변수 추가
    
    def __init__(self, *args, **kwargs):
        super(MyRyuApp, self).__init__(*args, **kwargs)
        self.logger.info(">> Ryu Controller is Running!")
    
        # 물리 구조를 동적으로 저장할 가상 그래프
        self.network_graph = {
            1: {2: 4, 3: 5},
            2: {1: 1, 4: 2},
            3: {1: 1, 4: 2},
            4: {2: 1, 3: 2}
        }

        self.host_mac_to_port = {
            '00:00:00:00:00:01': (1, 1), # Host 1
            '00:00:00:00:00:02': (1, 2), # Host 2
            '00:00:00:00:00:03': (1, 3), # Host 3
            '00:00:00:00:01:00': (4, 3), # Web 서버
            '00:00:00:00:01:01': (4, 4), # DB 서버
            '00:00:00:00:01:02': (4, 5)  # 보안 서버
        }
    
        # [방화벽] 연결된 스위치 객체 저장소 및 API 라우터 등록
        self.datapaths = {}
        wsgi = kwargs['wsgi']
        wsgi.register(FirewallController, {'my_app': self})

    # [방화벽] 스위치 연결 상태 추적 (모든 스위치에 차단 룰 적용)
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def add_flow(self, datapath, priority, match, actions): # datapath: 명령 받을 스위치 객체
                                                            # priority: 규칙 우선순위
                                                            # match: 조건문
                                                            # action: 행동 지침
        ofproto = datapath.ofproto  # OpenFlow 프로토콜 1.3 ver
        parser = datapath.ofproto_parser 

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] # action을 instruction 포맷으로 저장
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst) # 스위치로 보낼 규칙 수정 정보를 mod에 저장
        datapath.send_msg(mod) # 규칙 수정 요청 스위치로 전송

    # [Priority 1] 루프 제어 및 브로드캐스트 스톰 방지 규칙
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Switch connected: datapath_id=%016x", ev.msg.datapath_id)

        match = parser.OFPMatch() # 조건문: 매치되지 않는 모든 패킷은 컨트롤러로 Packet-In (Priority: 0)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        self.add_flow(datapath, 0, match, actions) 
        self.logger.info(">> [Rule 1] 스위치 %d에 Table_Miss Flow (Priority: 0) 주입 완료", datapath.id) 

    # [Priority 2] Dijkstra 최단 경로 라우팅 알고리즘
    def dijkstra(self, source, target):
        """
        인프라의 물리적 구조가 변경되더라도 self.network_graph 데이터만 바뀌면
        알고리즘 코드의 수정 필요 없이 최단 경로를 탐색함.
        """
        if source == target:
            return []

        distances = {node: float('inf') for node in self.network_graph}
        distances[source] = 0
        queue = [(0, source, [])]

        while queue:
            current_distance, current_node, path = heapq.heappop(queue)

            if current_node == target:
                return path + [current_node]
            
            if current_distance > distances[current_node]:
                continue

            for neighbor in self.network_graph.get(current_node, {}):
                new_dist = current_distance + 1 # 모든 링크 가중치를 1로 가정한 기본 다익스트라
                if new_dist < distances[neighbor]:
                    distances[neighbor] = new_dist
                    heapq.heappush(queue, (new_dist, neighbor, path + [current_node]))

        return []
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        src_mac = eth.src
        dst_mac = eth.dst

        # Debuging1: 패킷이 스위치를 거쳐 컨트롤러로 들어오는지 확인하는 로그
        print(f"\n [Packet-In] 스위치 ID: {datapath.id} | 입력 Port: {in_port}")
        print(f"    MAC 경로: {src_mac} -> {dst_mac} | Ether Type: {eth.ethertype}")

        try:
            # ISO 8601 형식의 현재 시간 생성
            current_time = datetime.now().isoformat() + "+09:00"
            
            # 'packet-summary' 규격에 맞춘 Payload 빌드
            payload = {
                "timestamp": current_time,
                "analyzer_id": "mininet-ryu-controller",
                "window_sec": 1,
                "total_packets": 1, # 실시간 발생 건별 전송이므로 1로 지정
                "total_bits": len(msg.data) * 8, # 패킷 바이트를 비트 단위로 변환
                "protocol_stats": {
                    "TCP": 1 if eth.ethertype == 2048 else 0, # 임시 프로토콜 판별
                    "UDP": 0,
                    "UNKNOWN": 0 if eth.ethertype == 2048 else 1
                },
                "host_stats": [
                    {
                        "src_host": "Host-1" if src_mac == "00:00:00:00:00:01" else None,
                        "src_ip": "10.0.0.1", # 실제 구동 환경에 맞게 맵핑
                        "dst_host": "Web-Server" if dst_mac == "00:00:00:00:01:00" else None,
                        "dst_ip": "10.0.0.100",
                        "protocol": "TCP" if eth.ethertype == 2048 else "UNKNOWN",
                        "packet_count": 1,
                        "bit_count": len(msg.data) * 8
                    }
                ]
            }
            
            # 백엔드 실제 IP를 [IP] 에 써야함. (현재 로컬 IP)
            backend_url = "http://host.docker.internal:8000/api/backend/analyzer/packet-summary"
            
            # Debuging2: 백엔드로 전송하기 직전 상태 알림
            print(f"    백엔드 수신기({backend_url})로 데이터 전송 시도 중..")

            # 타임아웃 0.05초 제한
            requests.post(backend_url, json=payload, timeout=0.05)
            self.logger.info(">> [백엔드 전송 완료] %s -> %s", src_mac, dst_mac)
            
        except Exception as e:
            print(f"    [warning] 백엔드 전송 실패: {e}")


        # LLDP 프로토콜 패킷은 일반 라우팅에서 제외함 -> 탐지 로직용 패킷.
        if eth.ethertype == 35020:
            return

        # Broadcast(ARP) 패킷의 경우: 스위치의 모든 포트로 Flooding해서 호스트를 찾게 함.
        if dst_mac == 'ff:ff:ff:ff:ff:ff':
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=msg.data)
            
            datapath.send_msg(out)
            return

        # Dst 호스트의 위치를 모른다면 Drop or 호스트 탐색
        if dst_mac not in self.host_mac_to_port:
            return
        
        # Src 스위치 (현재 패킷이 들어와 있는 스위치)와 Dst 호스트가 물린 스위치 확보
        this_sw = datapath.id
        
        target_sw, target_port = self.host_mac_to_port[dst_mac]

        # 목적지가 현재 자신과 같은 스위치에 있는 경우
        if this_sw == target_sw:
            out_port = target_port
        else:
            # 다른 스위치망에 있다면 다익스트라 알고리즘을 가동하여 다음 경로를 탐색
            path = self.dijkstra(this_sw, target_sw)
            if not path or len(path) < 2:
                return
            
            next_sw = path[1]
            out_port = self.network_graph[this_sw][next_sw]

        # 스위치에 최단 경로 라우팅 규칙 동적 삽입 (Priority: 10)
        match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
        actions = [parser.OFPActionOutput(out_port)]
        

        self.add_flow(datapath, 10, match, actions) 
        self.logger.info(">> [규칙 2] 스위치 %d에 라우팅 규칙 삽입 (Dst MAC: %s -> Out Port: %d)", this_sw, dst_mac, out_port)

        # 현재 들어온 패킷도 유실되지 않도록 목적지 포트로 즉시 발송
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


# REST API 요청을 처리할 외부 컨트롤러 클래스

class FirewallController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FirewallController, self).__init__(req, link, data, **config)
        self.my_app = data['my_app']
            
    @route('firewall', '/firewall/blocked', methods=['POST'])
    def block_ip(self, req, **kwargs):
        try:
            body = req.json if req.body else {}
            target_ip = body.get('ip')

            if not target_ip:
                return Response(status=400, body="차단할 IP 주소 없음.")
                    
            # 연결된 모든 스위치에 Rule 전송
            for dp_ip, datapath in self.my_app.datapaths.items():
                parser = datapath.ofproto_parser

                # IPv4 통신 중 출발지 IP가 target_ip인 패킷 매칭 (ethertype=0x0800)
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=target_ip)

                # actions 리스트가 비어있으면 DROP
                actions = []

                # 라우팅보다 높은 Priority로 설정 (100)
                self.my_app.add_flow(datapath, 100, match, actions)

            print(f"\n [방화벽] 악성 IP {target_ip} 차단 규칙을 전체 스위치에 적용 완료")
            return Response(status=200, body=json.dumps({"status": "success", "message": f"IP {target_ip} blocked."}))
        except Exception as e:
            return Response(status=500, body=str(e))