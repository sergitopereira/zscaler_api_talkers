import urllib

import requests
from zscaler_helpers import _request, get_user_agent, setup_logger

logger = setup_logger(name=__name__)


class ZdxPortalTalker:
    def __init__(
        self,
        username: str,
        password: str,
        zia_cloud: str,
    ):
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
        url = f"{self.api_base_url}/auth"
        #  Expect 401 status code; we just want the headers/cookies that get returned.
        result = _request(
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
            "username": f"zdx-{self.username}",
            "password": self.password,
        }
        result = _request(
            method="post",
            url=url,
            headers=self.headers,
            json=data,
            cookies=self.cookie_jar,
            **kwargs,
        )
        self.cookie_jar.update(result.cookies)

    def get_alerts(
        self,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="get",
            url=f"{self.api_base_url}/alerts/summaries",
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def delete_alert(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="delete",
            url=f"{self.api_base_url}/alerts/{data['id']}",
            json=data,
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def activate(
        self,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="put",
            url=f"{self.api_base_url}/activate",
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def get_applications(
        self,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="get",
            url=f"{self.api_base_url}/applications",
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def update_application(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="put",
            url=f"{self.api_base_url}/applications/{data['id']}",
            json=data,
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def deactivate_application(
        self,
        app_id: str,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="put",
            url=f"{self.api_base_url}/applications/{app_id}/deactivate",
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def delete_application(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="delete",
            url=f"{self.api_base_url}/applications/{data['id']}",
            json=data,
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def get_probes(
        self,
        **kwargs,
    ) -> requests.Response:
        parameters = {
            "pageName": "PROBES",
        }
        result = _request(
            method="get",
            url=f"{self.api_base_url}/monitors/summary",
            params=parameters,
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def delete_probe(
        self,
        app_id: str,
        probe_id: str,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="delete",
            url=f"{self.api_base_url}/applications/{app_id}/monitors/{probe_id}",
            headers=self.headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def zia_authenticate(
        self,
        **kwargs,
    ):
        """You need to cross authenticate into ZIA to work on the Admin accounts."""
        result = _request(
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
        sso = _request(
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
    ) -> requests.Response:
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
        result = _request(
            method="post",
            url=f"{self.zia_base_url}/samlAdminSettings/uploadCert/text",
            files=file,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def zia_enable_saml_sso(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        self.zia_headers.update(
            {
                "Content-Type": "application/json",
            }
        )
        result = _request(
            method="put",
            url=f"{self.zia_base_url}/samlAdminSettings",
            json=data,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def zia_activate(
        self,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="put",
            url=f"{self.zia_base_url}/orgAdminStatus/activate",
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def zia_get_admin_roles(
        self,
        **kwargs,
    ) -> requests.Response:
        parameters = {
            "includeAuditorRole": False,
            "includePartnerRole": False,
            "includeApiRole": False,
        }
        result = _request(
            method="get",
            url=f"{self.zia_base_url}/adminRoles",
            params=parameters,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def zia_create_admin_role(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="post",
            url=f"{self.zia_base_url}/adminRoles",
            json=data,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def zia_delete_admin_role(
        self,
        role_id: int,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="delete",
            url=f"{self.zia_base_url}/adminRoles/{role_id}",
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def zia_get_admin_users(
        self,
        **kwargs,
    ) -> requests.Response:
        parameters = {
            "page": 1,
            "pageSize": 100,
            "includeAuditorUsers": False,
            "includeAdminUsers": True,
        }
        result = _request(
            method="get",
            url=f"{self.zia_base_url}/adminUsers",
            params=parameters,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def zia_delete_admin_user(
        self,
        user_id: int,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="delete",
            url=f"{self.zia_base_url}/adminUsers/{user_id}",
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def zia_create_admin_user(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="post",
            url=f"{self.zia_base_url}/adminUsers",
            json=data,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result

    def zia_update_admin_user(
        self,
        data: dict,
        user_id: str,
        **kwargs,
    ) -> requests.Response:
        result = _request(
            method="put",
            url=f"{self.zia_base_url}/adminUsers/{user_id}",
            json=data,
            headers=self.zia_headers,
            cookies=self.cookie_jar,
            **kwargs,
        )
        return result
