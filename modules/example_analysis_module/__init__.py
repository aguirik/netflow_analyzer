#
#   Example analysis module for netflow analyzer
#
#   (c) Alexei Guirik, aguirik@unisnet.ru

from . import main

#
#   Analysis module is a package with __init__.py module
#   that has get_module_object() function and module.descr file
#   in package root folder.
#   get_module_object() should return instance of class with
#   run() method. This method will be called by main app
#   in separate process using multiprocessing.Process.
#

def get_module_object(*args, **kwargs):
    return main.ExampleAnalysisModule(*args, **kwargs)