import threading
import socket
import re


class SyslogServer:
    def run_async(self):
        print("Syslog server started")
        while True:
            data, addr = self.s.recvfrom(4096)
            data = data.decode()
            if self.name in data:
                self.s.close()
                self.filename = re.findall(r"Completed file upload to path: (.*) name:", data)[0]
                return

    def __init__(self, name):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("0.0.0.0", 514))
        self.name = name
        t = threading.Thread(None, SyslogServer.run_async, None, (self,))
        t.start()
        self.t = t
        self.filename = ""

    def wait(self):
        self.t.join()

