import json
import pdb
import re
from http.cookies import SimpleCookie
import jwt
import base64
import requests
import urllib.parse

from zscaler_api_talkers.helpers import HttpCalls, request_, setup_logger

logger = setup_logger(name=__name__)


class MobilePortalTalker(object):
    """
    Mobile Portal API talker
    Documentation: https://help.zscaler.com/zia/zia-api/api-developer-reference-guide
    """

    def __init__(
        self,
        cloud_name: str,
        api_id: int = None,
        auth_token: str = "",
        saml_response: json = None,
    ):
        """
        Method to start the class

        :param cloud_name: (str) Example: zscalerbeta.net, zscalerone.net, zscalertwo.net, zscalerthree.net,
        zscaler.net, zscloud.net
        :param api_id: (str) Client API ID
        :param auth_token: (str) Secret Key
        :param saml_response: str (sam response from ZiaPortalTalker)
        """
        self.base_uri = f"https://mobileadmin.{cloud_name}"
        self.hp_http = HttpCalls(
            host=self.base_uri,
            verify=True,
        )
        if api_id and auth_token:
            self.headers = {
                "API-Id": api_id,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
                "auth-token": auth_token,
            }
        else:
            self._authenticate(saml_response)

    def _authenticate(
        self,
        saml_response,
    ):
        url = "/sso.do"
        data = {"SAMLResponse": saml_response}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        resp = self.hp_http.post_call(
            url=url, headers=headers, payload=data, urlencoded=True
        )
        #
        regex = re.compile(r"mobile-token\"\>(.*?)<\/span\>")
        mobile_token = regex.search(resp.text).group(1)
        # now lets find the ApiHeader of  jwt token and base 64 it.
        api_header = jwt.decode(mobile_token, options={"verify_signature": False})[
            "apiHeader"
        ]
        self.headers = {
            "API-Id": base64.b64encode(api_header.encode("utf-8")).decode("utf-8"),
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "auth-token": mobile_token,
        }

    def list_forwarding_profile(self) -> json:
        """Method to retrieve forwarding profile"""
        url = "/webservice/api/web/forwardingProfile/listByCompany?page=1&pageSize=100"
        resp = self.hp_http.get_call(url=url, headers=self.headers)
        return resp.json()

    def list_app_profile(self, os_type: int = 3) -> json:
        """
        :param os_type:  1 for IOS, 2 for Android, 3 for Windows (default), 4 for macOS and 5 for Linux
        :type os_type: int
        :return: json
        """
        url = f"/webservice/api/web/policy/listByCompany?deviceType={os_type}"
        resp = self.hp_http.get_call(url=url, headers=self.headers)
        return resp.json()

    def list_update_settings(self) -> json:
        """
        Method to list update settings
        :return: json
        """
        url = "/webservice/api/web/autoupdate/getApplicationList"
        resp = self.hp_http.get_call(url=url, headers=self.headers)
        return resp.json()

    def list_trusted_networks(self) -> json:
        """Method to get trusted networks"""
        url = "/webservice/api/web/trustedNetwork/listByCompany?page=1&pageSize=100"
        resp = self.hp_http.get_call(url=url, headers=self.headers)
        return resp.json()
    
    def list_app_profile_bypass(self, id: int ) -> json:
        """
        Method to list app profile application bypasses
        :type id: app profile ID
        :return: json or [] if no application bypasses are configured
        """
        url = f"/webservice/api/web/appService/policies/{id}"
        resp = self.hp_http.get_call(url=url, headers=self.headers)
        return resp.json()
    
    def _list_download_device_url(self) -> str:
        """
        Method to get the url to download id for the device list in csv format
        :return: str 
        """
        url = f"/webservice/api/web/device/downloadDeviceUrl"
        headers = self.headers
        resp = self.hp_http.get_call(url=url, headers=headers)
        return urllib.parse.urlparse(resp.json()).query
    
    def list_devices(
            self,
            sub_query: str = "&sortBy=keepAliveTimestamp&type=0&osId=0&user=0&version=&searchProperty=id&supportedDevice=undefined"
        ):
        """
        Method to list devices in csv
        :return: 
        """
        query = "?" + self._list_download_device_url() + sub_query
        url = f"/webservice/api/webdevice/downloadDeviceList{query}"
        resp = requests.get(url=self.base_uri + url, headers={})
        return resp.text

    def list_failopen_configuration(self) -> json:
        """
        Method to list the Fail Open configuration

        :return: json or [] if no application bypasses are configured
        """
        url = f"/webservice/api/web/failOpenPolicy/listByCompany"
        resp = self.hp_http.get_call(url=url, headers=self.headers)
        return resp.json()