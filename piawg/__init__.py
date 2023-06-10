import json
import subprocess
from importlib import resources
from pathlib import Path
from typing import Any

import requests
from requests_toolbelt.adapters import host_header_ssl

CERT_URL = "http://www.privateinternetaccess.com/openvpn/ca.rsa.4096.crt"
CERT_PATH = Path("ca.rsa.4096.crt")


class PiaWg:
    region: str
    token: str
    publickey: str
    privatekey: str
    connection: dict

    def __init__(self):
        self._server_list = None
        self.get_server_list()

    @property
    def cert_path(self):
        if not CERT_PATH.exists():
            r = requests.get(CERT_URL, stream=True)
            r.raise_for_status()

            with open(CERT_PATH, "wb") as f:
                for chunk in r.iter_content():
                    f.write(chunk)
        return CERT_PATH.name

    @property
    def server_list(self) -> dict[str, Any]:
        if self._server_list is None:
            self.get_server_list()
        return self._server_list

    def get_server_list(self):
        r = requests.get("https://serverlist.piaservers.net/vpninfo/servers/v4")
        # Only process first line of response, there's some base64 data at the end we're ignoring
        data = json.loads(r.text.partition("\n\n")[0])
        self._server_list = {server["name"]: server for server in data["regions"]}

    def set_region(self, region_name):
        self.region = region_name

    def get_token(self, username: str, password: str):
        # Get common name and IP address for metadata endpoint in region
        meta = self.server_list[self.region]["servers"]["meta"][0]
        meta_cn = meta["cn"]
        meta_ip = meta["ip"]

        # Some tricks to verify PIA certificate, even though we're sending requests to an IP and not a proper domain
        # https://toolbelt.readthedocs.io/en/latest/adapters.html#requests_toolbelt.adapters.host_header_ssl.HostHeaderSSLAdapter
        with requests.Session() as s:
            s.mount("https://", host_header_ssl.HostHeaderSSLAdapter())
            s.verify = self.cert_path

            r = s.get(
                f"https://{meta_ip}/authv3/generateToken",
                headers={"Host": meta_cn},
                auth=(username, password),
            )
            r.raise_for_status()
            self.token = r.json()["token"]

    def generate_keys(self):
        self.privatekey = subprocess.run(
            ["wg", "genkey"], stdout=subprocess.PIPE, encoding="utf-8"
        ).stdout.strip()
        self.publickey = subprocess.run(
            ["wg", "pubkey"],
            input=self.privatekey,
            stdout=subprocess.PIPE,
            encoding="utf-8",
        ).stdout.strip()

    def add_key(self):
        # Get common name and IP address for wireguard endpoint in region
        wg = self.server_list[self.region]["servers"]["wg"][0]
        cn = wg["cn"]
        ip = wg["ip"]

        with requests.Session() as s:
            s.mount("https://", host_header_ssl.HostHeaderSSLAdapter())
            s.verify = self.cert_path

            r = s.get(
                f"https://{ip}:1337/addKey",
                params={"pt": self.token, "pubkey": self.publickey},
                headers={"Host": cn},
            )
            r.raise_for_status()
            self.connection = r.json()

    def generate_conf(self):
        with resources.as_file(
            resources.files("piawg") / "wg.conf.template"
        ) as p, open(p) as g:
            template = g.read()
        return template.format(
            if_addr=self.connection["peer_ip"],
            private_key=self.privatekey,
            dns=",".join(self.connection["dns_servers"]),
            public_key=self.connection["server_key"],
            endpoint=f'{self.connection["server_ip"]}:1337',
        )
