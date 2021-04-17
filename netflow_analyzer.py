#
#   Netflow analysis service prototype
#
#   (c) Alexei Guirik, aguirik@unisnet.ru
#

import os
import sys
import signal
import struct
import time
import multiprocessing as mp
import logging as log
import logging.handlers
import socket
import selectors
import hjson
import importlib.util

from netflow_analyzer_config import gcfg


#
# Netflow parser
#

class NetflowParser:
    def __init__(self, *args, **kwargs):
        # For netflow v5 only
        self.header_fmt = '!HHLLLLL'
        self.header_len = struct.calcsize(self.header_fmt)
        self.flow_fmt = '!LLLHHLLLLHHBBBBHHBBH'
        self.flow_len = struct.calcsize(self.flow_fmt)

    def parse_netflow_packet(self, recv_data):
        ret = None
        if recv_data:
            # https://netflow.caligare.com/netflow_v5.htm
            # v5 Header structure (24 bytes):
            # 0 version                     2 bytes
            # 1 number of flows             2 bytes
            # 2 device uptime               4 bytes
            # 3 UNIX timestamp              4 bytes
            # 4 UNIX nanoseconds            4 bytes
            # 5 Flow sequence counter       4 bytes
            # --- rest is irrelevant ---    4 bytes
            header_unpacked = struct.unpack(self.header_fmt, recv_data[:self.header_len])
            header = {
                'version' : header_unpacked[0],
                'nflows' : header_unpacked[1],
                # Skipping the rest for now
            }

            if header['version'] != 5:
                log.error(f'Wrong netflow packet version: {header["version"]}')
                return ret

            # v5 Flow structure (48 bytes):
            #  0 src address               4 bytes
            #  1 dst address               4 bytes
            #  2 next hop address          4 bytes
            #  3 input iface SNMP index    2 bytes
            #  4 ouptut iface SNMP index   2 bytes
            #  5 packets in this flow      4 bytes
            #  6 bytes in this flow        4 bytes
            #  7 flow start ts             4 bytes
            #  8 flow end ts               4 bytes
            #  9 src port                  2 bytes
            # 10 dst port                  2 bytes
            # 11 padding                   1 byte
            # 12 tcp flags                 1 byte
            # 13 ip protocol type          1 byte
            # 14 ToS                       1 byte
            # 15 src AS                    2 bytes
            # 16 dst AS                    2 bytes
            # 17 src mask                  1 byte
            # 18 dst mask                  1 byte
            # 19 padding                   2 bytes

            if len(recv_data) != self.header_len + header['nflows'] * self.flow_len:
                    log.error('Malformed packet received')

            flows = []
            for i in range(header['nflows']):
                flow_offset = self.header_len + i * self.flow_len
                flow_unpacked = struct.unpack(self.flow_fmt, recv_data[flow_offset:flow_offset + self.flow_len])
                flow = {
                    'src_addr' : flow_unpacked[0],
                    'dst_addr' : flow_unpacked[1],
                    'src_port' : flow_unpacked[9],
                    'dst_port' : flow_unpacked[10],
                    'npackets' : flow_unpacked[5],
                    'nbytes' : flow_unpacked[6],
                    'tcpflags' : flow_unpacked[12],
                    'proto' : flow_unpacked[13],
                }
                flows.append(flow)

            ret = {'header' : header, 'flows' : flows}
        return ret

#
# Main
#

if __name__ == '__main__':
    # Setup log
    log.basicConfig(
        level=gcfg.log_level,
        format='%(asctime)s %(levelname)s: %(message)s',
        # handlers = [logging.handlers.RotatingFileHandler(gcfg.LOG_FILE, maxBytes=50, backupCount=5)]
        handlers=[logging.handlers.WatchedFileHandler(gcfg.log_file)]
    )
    log.info('Starting applicaton...')

    # Setup signal handlers
    def quit_signal_handler(signal, frame):
        gcfg.stop_event.set()

    for sig in ('QUIT', 'TERM', 'INT'):
        signal.signal(getattr(signal, 'SIG' + sig), quit_signal_handler)

    # Search for analysis modules
    modules_to_load = []
    # By default search modules in './modules' subdirectory
    # of the netflow_analyzer.py script; otherwise search in
    # gcfg.modules_directory (it should contain full path in this case)
    if not hasattr(gcfg, 'modules_directory') or gcfg.modules_directory == '':
        gcfg.modules_directory = 'modules'
    if '/' not in gcfg.modules_directory:
        mpath = os.path.join(os.path.dirname(os.path.realpath(__file__)), gcfg.modules_directory)
    else:
        mpath = gcfg.modules_directory

    # Module directory should contain 'module.descr' file in hjson format
    for d in os.listdir(mpath):
        d = os.path.join(mpath, d)
        if os.path.isdir(d):
            descr_path = os.path.join(d, 'module.descr')
            if os.path.isfile(descr_path):
                try:
                    descr_hjson = hjson.load(open(os.path.join(d, 'module.descr')))
                except Exception as e:
                    log.error(f'Failed to parse {descr_path}: {e}')
                else:
                    if 'enabled' in descr_hjson and descr_hjson['enabled']:
                        modules_to_load.append((d, descr_hjson))

    # Try to load found modules, get module objects and run them
    module_objects = {}
    for (d, descr) in modules_to_load:
        try:
            # Import module/__init__.py
            mod_name = descr['module_name'] if 'module_name' in descr else os.path.basename(d)
            spec = importlib.util.spec_from_file_location(mod_name, os.path.join(d, '__init__.py'))
            mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = mod
            spec.loader.exec_module(mod)
        except Exception as e:
            log.error(f'Failed to load module from {d}: {type(e).__name__}: {e}')
        else:
            try:
                outq = mp.Queue()
                stop_event = mp.Event()
                mo = mod.get_module_object(outq, stop_event, descr)
                p = mp.Process(target=mo.run, args=())
                p.start()
                module_objects[mod_name] = {
                    'name' : mod_name,
                    'module_object' : mo,
                    'module' : mod,
                    'module_path' : d,
                    'module_descr' : descr,
                    'module_output_queue' : outq,
                    'module_stop_event' : stop_event,
                    'module_process' : p,
                }
                log.info(f'Loaded and launched module {type(mo).__name__} from {d}')
            except Exception as e:
                log.error(f'Failed to run module from {d}: {type(e).__name__}: {e}')

    gcfg.module_objects = module_objects
    if len(gcfg.module_objects) == 0:
        log.warning('No analysis modules loaded')

    # Receive and analyze netflow
    try:
        sel = selectors.DefaultSelector()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((gcfg.netflow_sock_addr, gcfg.netflow_sock_port))
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ, data=None)
    except Exception as e:
        log.error(f'Exception: {e}')
        sys.exit(1)

    nfp = NetflowParser()

    # Process netflow packets
    while not gcfg.stop_event.is_set():
        try:
            events = sel.select(timeout=gcfg.select_loop_timeout)
            for key, ev_mask in events:
                try:
                    # recv/recvfrom guarantees that a single packet will be received
                    (recv_data, recv_from) = key.fileobj.recvfrom(2048)
                    gcfg.packets_total += 1
                except BlockingIOError:
                    pass
                else:
                    pack = nfp.parse_packet(recv_data)
                    if pack:
                        gcfg.packets_processed += 1
                        # Send this packet to all active modules
                        for mod_name in gcfg.module_objects.keys():
                            try:
                                gcfg.module_objects[mod_name]['module_output_queue'].put(pack)
                            except Exception as e:
                                log.error(f'Failed to add packet to module "{mod_name}" output queue: {type(e).__name__}: {e}')
        except Exception as e:
            log.error(f'Exception: {e}')

    sel.unregister(sock)
    sock.close()

    # Signal analysis modules to finish their job
    for mod_name in gcfg.module_objects.keys():
        gcfg.module_objects[mod_name]['module_stop_event'].set()
        gcfg.module_objects[mod_name]['module_process'].join()

    runtime = int(time.time() - gcfg.app_start_ts)
    log.info(f'Exiting application... (handled {gcfg.packets_processed} out of {gcfg.packets_total} packets in {runtime} seconds)')
