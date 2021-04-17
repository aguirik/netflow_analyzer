#
#   Simple DDoS detector for netflow analyzer
#
#   Detects simple cases of DDoS
#
#   (c) Alexei Guirik, aguirik@unisnet.ru

import time
import queue
import logging as log

from collections import defaultdict

class SimpleDDoSDetector:
    def __init__(self, q, stop_event, descr, *args, **kwargs):
        self.q = q
        self.stop_event = stop_event
        self.descr = descr
        self.analysis_interval = descr['options']['analysis_interval']
        self.ips_threshold = descr['options']['ips_threshold']
        self.max_avg_packet_size  = descr['options']['max_avg_packet_size']
        self.min_packets_per_source = descr['options']['min_packets_per_source']
        self.ips_state = defaultdict(int)

    def update_state(self, pack):
        for f in pack['flows']:
            npackets, nbytes = f['npackets'], f['nbytes']
            avg_packet_size = nbytes/npackets
            if avg_packet_size < self.max_avg_packet_size:
                dst_addr, src_addr = f['dst_addr'], f['src_addr']
                if dst_addr not in self.ips_state:
                    self.ips_state[dst_addr] = defaultdict(int)
                self.ips_state[dst_addr][src_addr] += npackets

    def detect_ddos_targets(self):
        targets = []
        for dst_addr in self.ips_state.keys():
            if len(self.ips_state[dst_addr]) > self.ips_threshold:
                this_is_it = True
                for src_addr in self.ips_state[dst_addr].keys():
                    if self.ips_state[dst_addr][src_addr] < self.min_packets_per_source:
                        this_is_it = False
                        break
                if this_is_it:
                    targets.append(dst_addr)
        return targets

    def report_ddos_targets(self, targets):
        for t in targets:
            log.info(f'{type(self).__name__}: Detected DDoS target: {t}')

    def run(self):
        try:
            self.start_ts = time.time()
            while not self.stop_event.is_set():
                try:
                    pack = self.q.get(timeout=1.0)
                except queue.Empty:
                    pass
                else:
                    self.update_state(pack)

                if time.time() - self.start_ts > self.analysis_interval:
                    ddos_targets = self.detect_ddos_targets()
                    if len(ddos_targets) > 0:
                        self.report_ddos_targets(ddos_targets)
                    self.ips_state = defaultdict(int)
                    self.start_ts = time.time()
        except Exception as e:
            log.error(f'{type(self).__name__}: Exited with exception {type(e).__name__}: {e}')