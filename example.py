#! /usr/bin/env python3
"""
Uncomment the example methods in the if statement at the bottom of this script, as needed.

The "os.environ.get()" references used below call variables that are set in the ".env" file you create.

Example .env file contents:
zia_cloud = "zscalerthree.net"
zia_username = "you@you.com"
zia_password = "you_password"
zia_api_key = "you_api_key"

zcc_cloud = "zscalerthree.net"
zcc_client_id = "you_client_id"
zcc_secret_key = "you_secret_key"

zdx_username = "you@you.com"
zdx_password = "you_password"
zdx_zia_cloud = "zscalerthree.net"

zpa_customer_id = "you_customer_id"
zpa_client_id = "you_client_id"
zpa_client_secret = "you_client_secret"
zpa_username = "you@you.com"
zpa_password = "you_password"

bac_cloud = "zscalerthree.net"
bac_api_key = "you_api_key"
bac_username = "you@you.com"
bac_password = "you_password"
"""

import os

# `pyp install python-dotenv` to load this package
from dotenv import load_dotenv

from zscaler_api_talkers import (
    ClientConnectorTalker,
    #ZdxPortalTalker,
    #ZiaPortalTalker,
    ZiaTalker,
    #ZpaPortalTalker,
    ZpaTalker,
    CloudConnectorTalker,
)

#  Load user variables from ".env" file or from OS.
load_dotenv()


def zia_talker_example():
    print("Example of using ZiaTalker")
    zia = ZiaTalker(
        cloud_name=os.environ.get("zia_cloud"),
        api_key=os.environ.get("zia_api_key"),
        username=os.environ.get("zia_username"),
        password=os.environ.get("zia_password"),
    )
    print(f"{zia.get_status()=}")


def client_connector_talker_example():
    print("Example of using ClientConnectorTalker")
    zcc = ClientConnectorTalker(
        cloud=os.environ.get("zcc_cloud"),
        client_id=os.environ.get("zcc_client_id"),
        secret_key=os.environ.get("zcc_secret_key"),
    )

    company_id = int(os.environ.get("zcc_company_id"))
    print(f"{zcc.list_devices(company_id)}")

def zpa_talker_example():
    print("Example of using ZpaTalker")
    zpa = ZpaTalker(
        customer_id=int(os.environ.get("zpa_customer_id")),
        client_id=os.environ.get("zpa_client_id"),
        client_secret=os.environ.get("zpa_client_secret"),
    )
    print(f"{zpa.list_application_segments()=}")

def cloud_connector_talker_example():
    print("Example of using CloudConnectorTalker")
    bac = CloudConnectorTalker(
        cloud_name=os.environ.get("bac_cloud"),
        api_key=os.environ.get("bac_api_key"),
        username=os.environ.get("bac_username"),
        password=os.environ.get("bac_password"),
    )
    print(f"Connector Groups: {bac.list_cloud_branch_connector_groups()}")


if __name__ == "__main__":
    print(
        "Uncomment one or more of the following to test/see example of that API Talker."
    )
    #zia_talker_example()
    # client_connector_talker_example()
    #zpa_talker_example()
    cloud_connector_talker_example()
