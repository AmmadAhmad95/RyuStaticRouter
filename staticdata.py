import json
import logging
import sys

"""
Static Data Structures | SCC365

This file provides the functionality to load in the static data files.
You can use it as it is, or you can add your own helper functions
to each table.

Example use in Router file:

    routerData = StaticRoutingTable(debug=True)


"""

class StaticTable:

    FILE_PATH = ""

    def __init__(self, debug=False):
        logging.basicConfig(stream=sys.stdout, level=(logging.DEBUG if debug else logging.ERROR))
        self._logger = logging.getLogger(self.__class__.__name__)
        self.table = {}
        self.__loadData()

    def __loadData(self):
        try:
            if not self.FILE_PATH == "":
                with open(self.FILE_PATH, 'r') as staticfile:
                    self.table = json.load(staticfile)
                    self._logger.debug(self.table)
        except Exception as e:
            self._logger.error("Could not load the static data")
            self._logger.debug(e)
            sys.exit(1)

class StaticRoutingTable(StaticTable):

    FILE_PATH = "./routing.json"

    def __init__(self, debug=False):
        super().__init__(debug=debug)

    def getRoutingTable(self, datapath_id):
        return self.table.get(datapath_id, None)

    def getNextHop(self, dpid, ip):
        raise NotImplementedError

class StaticARPTable(StaticTable):

    FILE_PATH = "./arp.json"

    def __init__(self, debug=False):
        super().__init__(debug=debug)

    def getArpTable(self, datapath_id):
        return self.table.get(datapath_id, None)

    def getIP(self, dpid, mac):
        raise NotImplementedError