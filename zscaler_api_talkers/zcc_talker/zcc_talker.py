import json
import time

from zscaler_api_talkers.zscaler_helpers import HttpCalls


class ZccTalker(object):
    """
    Client Connector API talker
    Documentation: under development
    Currently in beta status
    """

    def __init__(
        self,
        cloud: str,
        client_id: str = "",
        secret_key: str = "",
    ):
        """
        :param cloud: (str) Top Level Domain (TLD) of the Zscaler cloud where tenant resides.
        :param client_id: (str) Client ID
        :param secret_key: (str) Secret Key
        """
        self.base_uri = f"https://api-mobile.{cloud}/papi"
        self.hp_http = HttpCalls(
            host=self.base_uri,
            verify=True,
        )
        self.jsessionid = None
        self.version = "beta 0.1"
        self.header = ""
        if client_id and secret_key:
            self.authenticate(
                clientid=client_id,
                secretkey=secret_key,
            )

    def authenticate(
        self,
        clientid: str,
        secretkey: str,
    ):
        """
        Method to authenticate.

        :param clientid: (str) Client id
        :param secretkey: (str) Client secret, obtained from portal.
        """
        payload = {
            "apiKey": clientid,
            "secretKey": secretkey,
        }
        url = "/auth/v1/login"
        response = self.hp_http.post_call(
            url=url,
            headers={"Accept": "*/*"},
            payload=payload,
        )
        self.header = {"auth-token": response.json()["jwtToken"]}

    def _obtain_all(
        self,
        url: str,
        cookies=None,
        params=None,
        headers=None,
    ) -> json:
        """
        Internal method that queries all pages

        :param url: (str) URL
        :param cookies: (dict?) Cookies
        :param params: (dict) Parameters to pass in request
        :param headers: (dict) Headers to pass in request

        :return: (json) JSON of results
        """
        page = 1
        result = []
        while True:
            response = self.hp_http.get_call(
                f"{url}&page={page}",
                cookies=cookies,
                params=params,
                headers=headers,
                error_handling=True,
            )
            if response.json():
                result += response.json()
                page += 1
                time.sleep(0.5)
            else:
                break

        return result

    def list_devices(
        self,
        companyID: int,
        username: str = None,
        osType: str = None,
    ) -> json:
        """
        Method to authenticate.

        :param companyID: (int) ORG ID
        :param username: (str) Username in email format
        :param osType: (str)

        :return: (json) JSON of results
        """
        # TODO: Move following logic to params.
        if username:
            url = f"/public/v1/getDevices?username={username}"
        elif osType:
            url = f"/public/v1/getDevices?osType={osType}"
        else:
            url = "/public/v1/getDevices?pagesize100"
        response = self._obtain_all(
            url=url,
            params=companyID,
            headers=self.header,
        )

        return response

    def list_OTP(
        self,
        companyID: int,
        udid: int,
    ) -> json:
        """
        Method to fetch the One Time Password for a specific device. These passwords are unique and tied to a device UDID

        :param companyID: (int) ORG ID
        :param udid: (int) User device ID

        :return: (json) JSON of results
        """
        url = f"/public/v1/getOtp?udid={udid}"
        response = self.hp_http.get_call(
            url=url,
            params=companyID,
            headers=self.header,
        )

        return response.json()

    def list_passwords(
        self,
        companyID: int,
        udid: int,
    ):
        """
        Method to fetch the One Time Password for a specific device. These passwords are unique and tied to a device UDID

        :param companyID: (int) ORG ID
        :param udid: (int) User device ID

        :return: (json) JSON of results
        """
        url = f"/public/v1/getOtp?udid={udid}"
        response = self.hp_http.get_call(
            url=url,
            params=companyID,
            headers=self.header,
        )

        return response.json()

    def remove_devices(
        self,
        companyID: int,
        udids: list,
        osType: int = 0,
    ) -> json:
        """
        Method to  mark the device for removal (Device Removal Pending).
        API currently can remove up to 30 devices per call

        :param companyID: type int. ORG ID
        :param udids: type list. List of user devices ids
        :param osType: 0 ALL OS types, 1 IOS, 2 Android, 3 Windows, 4 macOS, 5 Linux

        :return: (json) JSON of results
        """
        url = f"/public/v1/removeDevices"
        payload = {
            "companyId": companyID,
            "udids": udids,
            "osType": osType,
        }
        response = self.hp_http.post_call(
            url=url,
            headers=self.header,
            payload=payload,
        )

        return response.json()

    def force_remove_devices(
        self,
        companyID: int,
        udids: list = [],
        osType: int = 0,
    ) -> json:
        """
        Force Remove, has the same effect as Remove, though it additionally moves the device straight to Removed and also
        signals the cloud to invalidate the user’s session.
        API currently can remove up to 30 devices per call

        :param companyID: (int) ORG ID
        :param udids: (list) List of user devices ids
        :param osType: (int) 0 ALL OS types, 1 IOS, 2 Android, 3 Windows, 4 macOS, 5 Linux

        :return: (json) JSON of results
        """
        url = f"/public/v1/forceRemoveDevices"
        payload = {
            "companyId": companyID,
            "udids": udids,
            "osType": osType,
        }
        response = self.hp_http.post_call(
            url=url,
            headers=self.header,
            payload=payload,
        )

        return response.json()

    def downloadServiceStatus(
        self,
        companyID: int,
    ) -> str:
        """
        Method to download Service Status

        :param companyID: (int) ORG ID

        :return: (str) String of results
        """
        url = "/public/v1/downloadServiceStatus"
        response = self.hp_http.get_call(
            url=url,
            params=companyID,
            headers=self.header,
        )

        return response.content
