#
#   Example analysis module for netflow analyzer
#
#   Detects most frequently used ports
#
#   (c) Alexei Guirik, aguirik@unisnet.ru

import queue
import logging as log

from collections import defaultdict

# Instance of this class is returned by get_module_object()
#   function in __init__.py
#
# The only requirement for the class is that it must have a
#  method with the name 'run', taking arguments:
#   * q: multiprocessing.Queue - a queue for input netflow packets
#   * stop_event : multiprocessing.Event - an events that is set when it
#   * descr: OrderedDict - description from module.descr (can contain module options)
class ExampleAnalysisModule:
    def __init__(self, q, stop_event, descr, *args, **kwargs):
        self.q = q
        self.stop_event = stop_event
        self.descr = descr

    def run(self):
        # Dictionary for port:num_of_flows matching
        port_freq_map = defaultdict(int)

        try:
            # Main processing loop
            while not self.stop_event.is_set():
                try:
                    # Get next packet ...
                    pack = self.q.get(timeout=1.0)
                except queue.Empty:
                    pass
                else:
                    # ... and process it
                    if pack:
                        # Update our frequency map
                        for f in pack['flows']:
                            if f['proto'] in [6, 17]: # TCP, UDP
                                port_freq_map[f['src_port']] += 1
                                port_freq_map[f['dst_port']] += 1

                    # Do something useful with that info...

            # About to finish
            top_count = 10
            ports_by_freq = sorted(port_freq_map.items(), reverse=True, key=lambda item: item[1])
            port_list = ', '.join(map(lambda pair: str(pair[0]), ports_by_freq[:top_count]))
            log.info(f'{type(self).__name__}: Top {top_count} most frequently used ports: {port_list}')

        except Exception as e:
            log.error(f'{type(self).__name__}: Exited with exception {type(e).__name__}: {e}')