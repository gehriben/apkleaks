import traceback

from icmplib import ping

class PingCheck():
    def __init__(self):
        pass

    def check_ping(self, ip):
        host = self.__ping_host(ip)
        return host.is_alive

    def __ping_host(self, ip):
        try:
            return ping(ip, count=2, interval=0.2, privileged=False)
        except:
            print(traceback.format_exc())