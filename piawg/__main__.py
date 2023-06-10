from datetime import datetime
from getpass import getpass
from operator import itemgetter
from pydantic import ValidationError

import requests
from pick import Option, pick
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sr

from piawg import PiaWg
from piawg.settings import Settings

pia = PiaWg()

# Generate public and private key pair
pia.generate_keys()

# Select region
title = "Please choose a region: "

server_ips = {
    c["ip"]: n for n, s in pia.server_list.items() for c in s["servers"]["wg"]
}
print("checking response times...")
ans, unans = sr([IP(dst=ip) / ICMP() for ip in server_ips], timeout=5, retry=3)

region_time = sorted(
    (
        (server_ips[a.query.dst], (a.answer.time - a.query.sent_time) * 1000)
        for a in ans
    ),
    key=itemgetter(1),
)

options = [Option(label=f"{r[0]} ({r[1]:.1f}ms)", value=r[0]) for r in region_time]

option, index = pick(options, title)
pia.set_region(option.value)
print(f"Selected '{option.value}'")


try:
    settings = Settings()

    username = settings.PIA_USERNAME
    password = settings.PIA_PASSWD
    pia.get_token(username, password.get_secret_value())
    print("Login successful!")
except ValidationError:
    while True:
        username = input("Enter PIA username: ")
        password = getpass()
        try:
            pia.get_token(username, password)
            print("Login successful!")
            break
        except requests.HTTPError:
            print("Error logging in, please try again...")

# Add key
pia.add_key()
print("Added key to server!")

# Build config
location = pia.region.replace(" ", "-")
config_file = "PIA-{}-{:%Y%m%dT%H%M%S}.conf".format(location, datetime.now())
print("Saving configuration file {}".format(config_file))

with open(config_file, "w") as f:
    f.write(pia.generate_conf())
