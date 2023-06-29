#! /usr/bin/env python3
"""
Uncomment the example methods in the if statement at the bottom of this script, as needed.

The "os.environ.get()" references used below call variables that are set in the ".env" file you create.

Example .env file contents:
zia_cloud = "zscalerthree.net"
zia_username = "you@you.com"
zia_password = "asdfasdfasdf"
zia_api_key = "asdfasdfasdf"

zcc_cloud = "zscalerthree.net"
zcc_client_id = "asdfasdfasdf"
zcc_secret_key = "asdfasdfasdf"

zdx_username = "you@you.com"
zdx_password = "asdfasdfasdf"
zdx_zia_cloud = "zscalerthree"

zpa_customer_id = "asdfasdfasdf"
zpa_client_id = "asdfasdfasdf"
zpa_client_secret = "asdfasdfasdf"
zpa_username = "you@you.com"
zpa_password = "asdfasdfasdf"
"""

import os

# `pyp install python-dotenv` to load this package
from dotenv import load_dotenv

from zscaler_api_talkers import (ZccTalker, ZdxPortalTalker, ZiaPortalTalker,
                                 ZiaTalker, ZpaPortalTalker, ZpaTalker)

#  Load user variables from ".env" file or from OS.
load_dotenv()


def zia_talker_example():
    # Example of using ZiaTalker
    zia = ZiaTalker(cloud_name=os.environ.get("zia_cloud"))
    zia.authenticate(
        apikey=os.environ.get("zia_api_key"),
        username=os.environ.get("zia_username"),
        password=os.environ.get("zia_password"),
    )
    print(f"{zia.get_status()=}")


def zia_portal_talker_example():
    # Example of using ZiaPortalTalker
    zia_portal = ZiaPortalTalker(cloud_name=os.environ.get("zia_cloud"))
    zia_portal.authenticate(
        apikey=os.environ.get("zia_api_key"),
        username=os.environ.get("zia_username"),
        password=os.environ.get("zia_password"),
    )
    print(f"{zia_portal.list_apiKeys()=}")


def zcc_talker_example():
    # Example of using ZccTalker
    zcc = ZccTalker(cloud=os.environ.get("zcc_cloud"))
    zcc.authenticate(
        clientid=os.environ.get("zcc_client_id"),
        secretkey=os.environ.get("zcc_secret_key"),
    )
    print(f"{zcc.list_devices(companyID='asdf', username='asdf', osType='asdf',)=}")


def zdx_portal_talker_example():
    # Example of using ZdxPortalTalker
    zdx = ZdxPortalTalker(
        username=os.environ.get("zdx_username"),
        password=os.environ.get("zdx_password"),
        zia_cloud=os.environ.get("zdx_zia_cloud"),
    )
    print(f"{zdx.zia_get_admin_roles()=}")


def zpa_talker_example():
    # Example of using ZpaTalker
    zpa = ZpaTalker(customerID=os.environ.get("zpa_customer_id"))
    zpa.authenticate(
        client_id=os.environ.get("zpa_client_id"),
        client_secret=os.environ.get("zpa_client_secret"),
    )
    print(f"{zpa.list_application_segments()=}")


def zpa_portal_talker_example():
    # Example of using ZpaPortalTalker
    zpa_portal = ZpaPortalTalker(customerId=os.environ.get("zpa_customer_id"))
    zpa_portal.authenticate(
        username=os.environ.get("zpa_username"),
        password=os.environ.get("zpa_password"),
    )
    print(f"{zpa_portal.list_admin_users()=}")


if __name__ == "__main__":
    print("Uncomment the following to test/see example of that API Talker.")
    zia_talker_example()
    # zia_portal_talker_example()
    # zcc_talker_example()
    # zdx_portal_talker_example()
    # zpa_talker_example()
    # zpa_portal_talker_example()
