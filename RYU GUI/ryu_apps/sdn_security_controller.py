"""
Custom Ryu controller app — Ryu_SDN_IoT_Security_Controller.

Run on Ubuntu:
    ryu-manager --observe-links \
        ryu.app.ofctl_rest \
        ryu.app.rest_topology \
        ryu_apps/sdn_security_controller.py

This app:
  • Acts as a simple_switch_13 learning switch (L2 forwarding)
  • Collects flow stats every FLOW_STATS_INTERVAL seconds
  • Forwards features to the Django GNN inference endpoint
  • Receives mitigation rules over its REST API and installs them
  • Pushes events / threats to Django via Channels (WebSocket) or HTTP

REST endpoints exposed on http://localhost:8081/sdn/:
  GET  /sdn/threats                    list recent threats
  POST /sdn/mitigate                   install drop rule (body: {src_ip, dpid?})
  POST /sdn/install_meter              install rate-limiting meter
"""
import json
import logging
import time
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    DEAD_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from ryu.lib import hub
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import requests

log = logging.getLogger("sdn_security")
INSTANCE_NAME = "sdn_security_app"
URL_PREFIX = "/sdn"

DJANGO_INGEST_URL = "http://127.0.0.1:8000/api/threats/"   # POST detected threats (optional)
GNN_INFERENCE_URL = "http://127.0.0.1:8000/api/gnn/infer/"  # local Django inference endpoint
FLOW_STATS_INTERVAL = 5  # seconds


class SDNSecurityController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]
        wsgi.register(SecurityRestController,
                      {INSTANCE_NAME: self})
        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_history = defaultdict(lambda: deque(maxlen=20))
        self.recent_threats = deque(maxlen=200)
        self.monitor_thread = hub.spawn(self._monitor_loop)

    # ---------------- topology / learning switch ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)
        log.info("Switch %s connected", dp.id)

    def _add_flow(self, dp, priority, match, actions, idle_timeout=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout,
        )
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            self._add_flow(dp, 10, match, actions, idle_timeout=30)

        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
        )
        dp.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER and dp.id in self.datapaths:
            del self.datapaths[dp.id]

    # ---------------- periodic flow stats collection ----------------
    def _monitor_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)
            hub.sleep(FLOW_STATS_INTERVAL)

    def _request_flow_stats(self, dp):
        parser = dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(dp)
        dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        features = self._extract_features(dpid, body)
        if features:
            self._invoke_gnn(features)

    def _extract_features(self, dpid, body):
        """Convert raw flow stats into per-flow feature vectors for the GNN."""
        feats = []
        for stat in body:
            if stat.priority == 0:
                continue
            try:
                m = stat.match
                feats.append({
                    "dpid": dpid,
                    "src_ip": m.get("ipv4_src", "0.0.0.0"),
                    "dst_ip": m.get("ipv4_dst", "0.0.0.0"),
                    "proto": int(m.get("ip_proto", 0)),
                    "src_port": int(m.get("tcp_src", m.get("udp_src", 0))),
                    "dst_port": int(m.get("tcp_dst", m.get("udp_dst", 0))),
                    "packet_count": int(stat.packet_count),
                    "byte_count": int(stat.byte_count),
                    "duration_sec": int(stat.duration_sec),
                    "table_id": int(stat.table_id),
                })
            except Exception:  # noqa: BLE001
                continue
        return feats

    def _invoke_gnn(self, features):
        try:
            resp = requests.post(GNN_INFERENCE_URL, json={"flows": features},
                                 timeout=2.0)
            if resp.ok:
                for threat in resp.json().get("threats", []):
                    self.recent_threats.appendleft({
                        "timestamp": time.time(),
                        **threat,
                    })
                    # auto-mitigate if the inference engine flagged high confidence
                    if threat.get("auto_mitigate") and threat.get("src_ip"):
                        self._install_drop(threat["dpid"], threat["src_ip"])
        except Exception as exc:  # noqa: BLE001
            log.debug("GNN inference call failed: %s", exc)

    # ---------------- mitigation actions ----------------
    def _install_drop(self, dpid, src_ip, idle_timeout=60, priority=65000):
        dp = self.datapaths.get(int(dpid)) if dpid else next(iter(self.datapaths.values()), None)
        if dp is None:
            return False
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = []  # empty action list = drop
        self._add_flow(dp, priority, match, actions, idle_timeout=idle_timeout)
        log.warning("Mitigation: DROP from %s on dpid %s", src_ip, dp.id)
        return True

    def _install_meter(self, dpid, src_ip, rate_kbps=500):
        dp = self.datapaths.get(int(dpid)) if dpid else next(iter(self.datapaths.values()), None)
        if dp is None:
            return False
        ofp, parser = dp.ofproto, dp.ofproto_parser
        # add meter
        bands = [parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=0)]
        meter_mod = parser.OFPMeterMod(
            datapath=dp, command=ofp.OFPMC_ADD, flags=ofp.OFPMF_KBPS,
            meter_id=int(dpid) % 1000 + 1, bands=bands,
        )
        dp.send_msg(meter_mod)
        log.info("Meter %skbps installed for %s on %s", rate_kbps, src_ip, dp.id)
        return True


# -----------------------------------------------------------------------------
# REST CONTROLLER
# -----------------------------------------------------------------------------
class SecurityRestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app: SDNSecurityController = data[INSTANCE_NAME]

    @route("threats", URL_PREFIX + "/threats", methods=["GET"])
    def threats(self, req, **_):
        body = json.dumps(list(self.app.recent_threats))
        return Response(content_type="application/json", body=body)

    @route("mitigate", URL_PREFIX + "/mitigate", methods=["POST"])
    def mitigate(self, req, **_):
        try:
            body = json.loads(req.body.decode() or "{}")
        except Exception:
            body = {}
        src_ip = body.get("src_ip")
        dpid = body.get("dpid")
        action = body.get("action", "drop")
        if action == "drop":
            ok = self.app._install_drop(dpid, src_ip)
        elif action == "meter":
            ok = self.app._install_meter(dpid, src_ip, body.get("rate_kbps", 500))
        else:
            ok = False
        return Response(content_type="application/json",
                        body=json.dumps({"ok": bool(ok)}))

    @route("status", URL_PREFIX + "/status", methods=["GET"])
    def status(self, req, **_):
        body = json.dumps({
            "datapaths": list(self.app.datapaths.keys()),
            "n_threats": len(self.app.recent_threats),
        })
        return Response(content_type="application/json", body=body)
