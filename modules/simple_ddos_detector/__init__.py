#
#   Simple DDoS detector for netflow analyzer
#
#   (c) Alexei Guirik, aguirik@unisnet.ru

from . import main

def get_module_object(*args, **kwargs):
    return main.SimpleDDoSDetector(*args, **kwargs)