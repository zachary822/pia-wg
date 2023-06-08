import json
import subprocess
import urllib.parse

import requests
from requests_toolbelt.adapters import host_header_ssl


class piawg:
    def __init__(self):
        self.server_list = {}
        self.get_server_list()
        self.region = None
        self.token = None
        self.publickey = None
        self.privatekey = None
        self.connection = None

    def get_server_list(self):
        r = requests.get("https://serverlist.piaservers.net/vpninfo/servers/v4")
        # Only process first line of response, there's some base64 data at the end we're ignoring
        data = json.loads(r.text.partition("\n\n")[0])
        for server in data["regions"]:
            self.server_list[server["name"]] = server

    def set_region(self, region_name):
        self.region = region_name

    def get_token(self, username, password):
        # Get common name and IP address for metadata endpoint in region
        meta_cn = self.server_list[self.region]["servers"]["meta"][0]["cn"]
        meta_ip = self.server_list[self.region]["servers"]["meta"][0]["ip"]

        # Some tricks to verify PIA certificate, even though we're sending requests to an IP and not a proper domain
        # https://toolbelt.readthedocs.io/en/latest/adapters.html#requests_toolbelt.adapters.host_header_ssl.HostHeaderSSLAdapter
        with requests.Session() as s:
            s.mount("https://", host_header_ssl.HostHeaderSSLAdapter())
            s.verify = "ca.rsa.4096.crt"

            r = s.get(
                "https://{}/authv3/generateToken".format(meta_ip),
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

    def addkey(self):
        # Get common name and IP address for wireguard endpoint in region
        cn = self.server_list[self.region]["servers"]["wg"][0]["cn"]
        ip = self.server_list[self.region]["servers"]["wg"][0]["ip"]

        with requests.Session() as s:
            s.mount("https://", host_header_ssl.HostHeaderSSLAdapter())
            s.verify = "ca.rsa.4096.crt"

            r = s.get(
                "https://{}:1337/addKey?pt={}&pubkey={}".format(
                    ip,
                    urllib.parse.quote(self.token),
                    urllib.parse.quote(self.publickey),
                ),
                headers={"Host": cn},
            )
            r.raise_for_status()
            self.connection = r.json()
