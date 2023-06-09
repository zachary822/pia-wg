from datetime import datetime
from getpass import getpass

import requests
from pick import pick

from piawg import PiaWg

pia = PiaWg()
pia.download_cert()

# Generate public and private key pair
pia.generate_keys()

# Select region
title = "Please choose a region: "
options = sorted(pia.server_list.keys())
option, index = pick(options, title)
pia.set_region(option)
print("Selected '{}'".format(option))

# Get token
while True:
    username = input("\nEnter PIA username: ")
    password = getpass()
    try:
        pia.get_token(username, password)
        print("Login successful!")
        break
    except requests.HTTPError:
        print("Error logging in, please try again...")

# Add key
pia.addkey()
print("Added key to server!")

# Build config
location = pia.region.replace(" ", "-")
config_file = "PIA-{}-{:%Y%m%dT%H%M%S}.conf".format(location, datetime.now())
print("Saving configuration file {}".format(config_file))

with open(config_file, "w") as f:
    f.write(pia.generate_conf())
