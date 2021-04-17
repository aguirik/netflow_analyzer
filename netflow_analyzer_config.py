#
#   Netflow analysis service prototype
#
#   (c) Alexei Guirik, aguirik@unisnet.ru
#

import time
import threading
import logging

#
# Global configuration
#

class GlobalConfig:
    #
    # Startup settings
    #

    # Path to main app log
    log_file = 'netflow_analyzer.log'

    # Log verbosity
    log_level = logging.INFO

    # Socket for netflow
    netflow_sock_addr = '0.0.0.0'
    netflow_sock_port = 9996

    # Where to search for analysis modules
    modules_directory = 'modules'

    # Main receive loop timeout (seconds)
    select_loop_timeout = 1.0

    #
    # Runtime stuff
    #

    # Global stop event
    stop_event = threading.Event()

    # Launch ts
    app_start_ts = time.time()

    # Packets statistics
    packets_processed = 0
    packets_total = 0

    # Loaded analysis module objects
    module_objects = {}

gcfg = GlobalConfig()