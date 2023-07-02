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
"""

import os

# `pyp install python-dotenv` to load this package
from dotenv import load_dotenv

from zscaler_api_talkers import (ZccTalker, ZdxPortalTalker, ZiaPortalTalker,
                                 ZiaTalker, ZpaPortalTalker, ZpaTalker)

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


def zia_portal_talker_example():
    print("Example of using ZiaPortalTalker")
    zia_portal = ZiaPortalTalker(
        cloud_name=os.environ.get("zia_cloud"),
        username=os.environ.get("zia_username"),
        password=os.environ.get("zia_password"),
    )
    print(f"{zia_portal.list_api_keys()=}")


def zcc_talker_example():
    print("Example of using ZccTalker")
    zcc = ZccTalker(
        cloud=os.environ.get("zcc_cloud"),
        client_id=os.environ.get("zcc_client_id"),
        secret_key=os.environ.get("zcc_secret_key"),
    )
    print(f"{zcc.list_devices(company_id=10, username='asdf', os_type='asdf',)=}")


def zdx_portal_talker_example():
    print("Example of using ZdxPortalTalker")
    zdx = ZdxPortalTalker(
        username=os.environ.get("zdx_username"),
        password=os.environ.get("zdx_password"),
        zia_cloud=os.environ.get("zdx_zia_cloud"),
    )
    print(f"ZDX Alerts: {zdx.list_alerts()}")
    zdx.zia_authenticate()  # Cross authenticate to ZIA for user/admin/role functions.
    print(f"Admin Roles: {zdx.zia_list_admin_roles()}")


def zpa_talker_example():
    print("Example of using ZpaTalker")
    zpa = ZpaTalker(
        customer_id=int(os.environ.get("zpa_customer_id")),
        client_id=os.environ.get("zpa_client_id"),
        client_secret=os.environ.get("zpa_client_secret"),
    )
    print(f"{zpa.list_application_segments()=}")


def zpa_portal_talker_example():
    print("Example of using ZpaPortalTalker")
    zpa_portal = ZpaPortalTalker(
        customer_id=int(os.environ.get("zpa_customer_id")),
        username=os.environ.get("zpa_username"),
        password=os.environ.get("zpa_password"),
    )
    result = zpa_portal.list_admin_roles()
    print(f"ZPA Admin Roles{result.json()}")


if __name__ == "__main__":
    print(
        "Uncomment one or more of the following to test/see example of that API Talker."
    )
    zia_talker_example()
    zia_portal_talker_example()
    # zcc_talker_example()
    zdx_portal_talker_example()
    zpa_talker_example()
    zpa_portal_talker_example()
