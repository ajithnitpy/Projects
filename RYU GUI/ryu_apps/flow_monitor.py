"""
Optional standalone Ryu app — flow_monitor.

A lighter-weight monitor app to be used alongside ryu.app.ofctl_rest if the
operator does not want the full security controller running. Periodically logs
flow counts to stdout.
"""
from operator import attrgetter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (MAIN_DISPATCHER, DEAD_DISPATCHER,
                                    set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub


class FlowMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER and dp.id in self.datapaths:
            del self.datapaths[dp.id]

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                dp.send_msg(parser.OFPFlowStatsRequest(dp))
            hub.sleep(10)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply(self, ev):
        body = ev.msg.body
        self.logger.info("Switch %s — %d flows",
                         ev.msg.datapath.id,
                         sum(1 for s in body if s.priority > 0))
