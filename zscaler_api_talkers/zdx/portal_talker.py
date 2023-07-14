import json
import urllib

import requests

from zscaler_api_talkers.helpers import get_user_agent, request_, setup_logger

logger = setup_logger(name=__name__)


class ZdxPortalTalker:
    def __init__(
        self,
        username: str,
        password: str,
        zia_cloud: str,
    ):
        """Class object to provide access to ZDX via web portal backend APIs.

        :param username: (str) Admin username
        :param password: (str) Admin password
        :param zia_cloud: (str) ZIA Portal associated with this ZDX tenant. Example: "zscalerthree.net"
        """
        logger.warning(
            "These API endpoints are unsupported and Zscaler can change at will and without notice."
        )
        self.username = username
        self.password = password
        self.base_url = "https://admin.zdxcloud.net"
        self.api_base_url = f"{self.base_url}/zdx/api/v1"
        self.headers = {
            "User-Agent": get_user_agent(),
            "X-CSRF-Token": "Fetch",
            "Referer": f"{self.base_url}/zdx/login",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "sec-ch-ua": '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"',
            "Accept": "application/json, text/plain, */*",
        }
        self.cookie_jar = requests.cookies.RequestsCookieJar()
        self._authenticate(silence_logs=True)

        # For cross function with ZIA
        self.zia_cloud = zia_cloud
        self.zia_headers = {
            "Accept": "*/*",
            "User-Agent": get_user_agent(),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        self.zia_base_url = ""  # This will be properly configured after ZIA Auth.

    def _authenticate(
        self,
        **kwargs,
    ):
        """Authenticate to ZDX Web Portal"""
        url = f"{self.api_base_url}/auth"
        #  Expect 401 status code; we just want the headers/cookies that get returned.
        result = request_(
            method="get",
            url=url,
            headers=self.headers,
            retries=1,
            wait_time=0.1,
            **kwargs,
        )
        self.cookie_jar.update(result.cookies)
        self.headers.update(
            {
                "X-CSRF-Token": result.headers["X-CSRF-Token"],
                "Origin": self.base_url,
                "Referer": f"{self.base_url}/zdx/login",
                "Content-Type": "application/json",
            }
        )
        data = {
            "username": self.username,
            "password": self.password,
        }
        result = request_(
            method="post",
            url=url,
            headers=self.headers,
            json=data,
            cookies=self.cookie_jar,
            **kwargs,
        )
        self.cookie_jar.update(result.cookies)

    def list_alerts(
        self,
        **kwargs,
    ) -> json:
        """
        Collect a list of ZDX Alerts.

        :return: (json)
        """
        result = request_(
            method="get",
            url=f"{self.api_base_url}/alerts/summaries",
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def delete_alert(
        self,
        data: dict,
        **kwargs,
    ) -> json:
        """
        Delete Alert.

        :param data: (dict) Dict of select Alert.  # TODO: Can this just be the alert_id?

        :return: (json)
        """
        result = request_(
            method="delete",
            url=f"{self.api_base_url}/alerts/{data['id']}",
            json=data,
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def activate(
        self,
        **kwargs,
    ) -> json:
        """
        Activate Changes.

        :return: (json)
        """
        result = request_(
            method="put",
            url=f"{self.api_base_url}/activate",
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def list_applications(
        self,
        **kwargs,
    ) -> json:
        """
        Collect a list of ZDX Applications

        :return: (json)
        """
        result = request_(
            method="get",
            url=f"{self.api_base_url}/applications",
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def update_application(
        self,
        data: dict,
        **kwargs,
    ) -> json:
        """
        Update an Application

        :return: (json)
        """
        result = request_(
            method="put",
            url=f"{self.api_base_url}/applications/{data['id']}",
            json=data,
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def deactivate_application(
        self,
        app_id: str,
        **kwargs,
    ) -> json:
        """
        Deactivate an Application

        :return: (json)
        """
        result = request_(
            method="put",
            url=f"{self.api_base_url}/applications/{app_id}/deactivate",
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def delete_application(
        self,
        data: dict,
        **kwargs,
    ) -> json:
        """
        Delete a ZDX Application

        :param data: (dict) Dict of Application  # TODO: Can this be changed to just be the app_id?

        :return: json
        """
        result = request_(
            method="delete",
            url=f"{self.api_base_url}/applications/{data['id']}",
            json=data,
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def list_probes(
        self,
        **kwargs,
    ) -> json:
        """
        Collect a list of ZDX Probes

        :return: (json)
        """
        parameters = {
            "pageName": "PROBES",
        }
        result = request_(
            method="get",
            url=f"{self.api_base_url}/monitors/summary",
            params=parameters,
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def delete_probe(
        self,
        app_id: str,
        probe_id: str,
        **kwargs,
    ) -> json:
        """
        Delete specific Application's Probe

        :param app_id: (str) ID of Application
        :param probe_id: (str) ID of Probe

        :return: (json)
        """
        result = request_(
            method="delete",
            url=f"{self.api_base_url}/applications/{app_id}/monitors/{probe_id}",
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def zia_authenticate(
        self,
        **kwargs,
    ):
        """Cross authentication into ZIA to work on user and roles."""
        logger.warning(
            "Regular ZDX methods will no longer work after ZIA auth.  Create a new ZdxPortalTalker object "
            "if further access is needed."
        )
        result = request_(
            method="post",
            url=f"{self.api_base_url}/auth/token",
            headers=self.headers,
            data=f'["{self.zia_cloud}"]',
            cookies=self.cookie_jar,
            **kwargs,
        )
        saml = result.json()

        payload = (
            f"SAMLResponse={urllib.parse.quote(saml['token'])}"
            f"&source=SMFALCONUI"
            f"&relay={urllib.parse.quote('#administration/admin-management')}"
        )
        sso = request_(
            method="post",
            url=saml["acceptedTargets"][0]["url"],
            headers=self.zia_headers,
            data=payload,
            cookies=self.cookie_jar,
            allow_redirects=False,
            **kwargs,
        )

        self.cookie_jar.update(sso.cookies)
        del self.zia_headers["Content-Type"]
        self.zia_headers.update(
            {
                "ZS_CUSTOM_CODE": self.cookie_jar.get_dict(
                    domain=f".admin.{self.zia_cloud}"
                )["ZS_SESSION_CODE"],
            }
        )
        self.zia_base_url = f"https://admin.{saml['cloud']}/zsapi/v1"

    def zia_upload_certificate(
        self,
        filename: str,
        certificate: str,
        **kwargs,
    ) -> json:
        """
        Upload a certificate to ZIA (for ZDX Admin auth)

        :param filename: (str) Name representation of this cert.
        :param certificate: (str) x509-ca-cert formatted cert.

        :return: (json)
        """
        file = [
            (
                "fileUpload",
                (
                    filename,
                    certificate,
                    "application/x-x509-ca-cert",
                ),
            )
        ]
        result = request_(
            method="post",
            url=f"{self.zia_base_url}/samlAdminSettings/uploadCert/text",
            files=file,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def zia_enable_saml_sso(
        self,
        data: dict,
        **kwargs,
    ) -> json:
        """
        Enable SAML SSO

        :param data: (dict)

        :return: (json)
        """
        self.zia_headers.update(
            {
                "Content-Type": "application/json",
            }
        )
        result = request_(
            method="put",
            url=f"{self.zia_base_url}/samlAdminSettings",
            json=data,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def zia_activate(
        self,
        **kwargs,
    ) -> json:
        """
        Activate changes in ZIA Portal

        :return: (json)
        """
        result = request_(
            method="put",
            url=f"{self.zia_base_url}/orgAdminStatus/activate",
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def zia_list_admin_roles(
        self,
        **kwargs,
    ) -> json:
        """
        Collect a list of Admin Roles.

        :return: (json)
        """
        parameters = {
            "includeAuditorRole": False,
            "includePartnerRole": False,
            "includeApiRole": False,
        }
        result = request_(
            method="get",
            url=f"{self.zia_base_url}/adminRoles",
            params=parameters,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def zia_add_admin_role(
        self,
        data: dict,
        **kwargs,
    ) -> json:
        """
        Add an Admin Role

        :param data: (dict) Admin role configuration

        :return: (json)
        """
        result = request_(
            method="post",
            url=f"{self.zia_base_url}/adminRoles",
            json=data,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def zia_delete_admin_role(
        self,
        role_id: int,
        **kwargs,
    ) -> json:
        """
        Delete an Admin Role

        :param role_id: (int) ID of role

        :return: (json)
        """
        result = request_(
            method="delete",
            url=f"{self.zia_base_url}/adminRoles/{role_id}",
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def zia_list_admin_users(
        self,
        **kwargs,
    ) -> json:
        """
        Collect a list of ZDX Admin Users

        :return: (json)
        """
        parameters = {
            "page": 1,  # TODO: Change this and pageSize to an interator
            "pageSize": 100,
            "includeAuditorUsers": False,
            "includeAdminUsers": True,
        }
        result = request_(
            method="get",
            url=f"{self.zia_base_url}/adminUsers",
            params=parameters,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def zia_delete_admin_user(
        self,
        user_id: int,
        **kwargs,
    ) -> json:
        """
        Delete a ZDX Admin User

        :param user_id: (int) ID of User

        :return: (json)
        """
        result = request_(
            method="delete",
            url=f"{self.zia_base_url}/adminUsers/{user_id}",
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def zia_add_admin_user(
        self,
        data: dict,
        **kwargs,
    ) -> json:
        """
        Add a ZDX Admin User

        :param data: (dict) Dict of Admin user settings

        :return: (json)
        """
        result = request_(
            method="post",
            url=f"{self.zia_base_url}/adminUsers",
            json=data,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()

    def zia_update_admin_user(
        self,
        data: dict,
        user_id: int,
        **kwargs,
    ) -> json:
        """
        Update settings for a ZDX Admin User

        :param data: (dict) Settings for this admin user
        :param user_id: (int) ID of this user  # TODO: Can't this just be in the data var?

        :return: (json)
        """
        result = request_(
            method="put",
            url=f"{self.zia_base_url}/adminUsers/{user_id}",
            json=data,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result.json()
