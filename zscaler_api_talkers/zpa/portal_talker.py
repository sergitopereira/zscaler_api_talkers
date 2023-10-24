import requests
import json
from zscaler_api_talkers.helpers import HttpCalls, request_, setup_logger
import time

logger = setup_logger(name=__name__)


class ZpaPortalTalker(object):
    def __init__(
        self,
        customer_id: int,
        cloud: str = "https://api.private.zscaler.com",
        username: str = "",
        password: str = "",
    ):
        """
        Method to start the class

        :param customer_id: (int)
        :param cloud: (str) Default = "https://api.private.zscaler.com"
        :param username: (str)
        :param password: (str)
        """
        logger.warning(
            "These API endpoints are unsupported and Zscaler can change at will and without notice."
        )
        self.base_uri = cloud
        self.version = "1.0"
        self.cookies = None
        self.bear = None
        self.token = None
        self.headers = None
        self.customer_id = customer_id
        self.hp_http = HttpCalls(
            host=self.base_uri,
            verify=True,
        )
        if username and password:
            self.authenticate(
                username=username,
                password=password,
            )
        self.hp_http_druid = None

    def _obtain_all_pages(
        self,
        url: str,
    ) -> list:
        result = []
        if "?pagesize" not in url:
            url = f"{url}?page=1&pagesize=500"
        response = self.hp_http.get_call(
            url,
            headers=self.headers,
            error_handling=True,
        )
        if "list" not in response.json().keys():
            return []
        if int(response.json()["totalPages"]) > 1:
            i = 0
            while i <= int(response.json()["totalPages"]):
                result = (
                    result
                    + self.hp_http.get_call(
                        f"{url}&page={i}",
                        headers=self.headers,
                        error_handling=True,
                    ).json()["list"]
                )
                i += 1
        else:
            result = response.json()["list"]

        return result

    def authenticate(
        self,
        username: str,
        password: str,
        bearer_token: str = None,
    ):
        """
        Method to obtain authorization token for subsequent calls.

        :param username: Email address
        :param password: Password for given user
        :param bearer_token: Optional. Bearer token
        """
        if bearer_token:
            self.headers = {
                "Content-Type": "application/json text/javascript, */*; q=0.01",
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate, br",
                "Authorization": f"Bearer {bearer_token}",
            }
            self.hp_http_druid = HttpCalls(
                host=self._list_zone_details()["serviceEndpoints"]["service.zpa.druid"],
                verify=True,
            )
            return
        url = "/base/api/zpa/signin"
        payload = {
            "username": username,
            "password": password,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self.hp_http.post_call(
            url=url,
            payload=payload,
            headers=headers,
            urlencoded=True,
        )
        self.token = response.json()["Z-AUTH-TOKEN"]
        self.headers = {
            "Content-Type": "application/json text/javascript, */*; q=0.01",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Authorization": f"Bearer {self.token}",
        }
        self.druid_service = self._list_zone_details()["serviceEndpoints"][
            "service.zpa.druid"
        ]
        self.hp_http_druid = HttpCalls(
            host=self._list_zone_details()["serviceEndpoints"]["service.zpa.druid"],
            verify=True,
        )

    def list_admin_users(self) -> json:
        """
        List admins users

        :return: (list)
        """
        url = f"/shift/api/v2/admin/customers/{self.customer_id}/users"
        response = self._obtain_all_pages(url)
        return response

    def list_admin_roles(self) -> json:
        """
        List admins roles

        :return: (requests.Response Object)
        """
        url = f"/zpn/api/v1/admin/customers/{self.customer_id}/roles"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
        )

        return response.json()

    def list_application_segments(
        self,
        **kwargs,
    ) -> json:
        """
        List Applications Segments

        :return: (requests.Response object)
        """
        url = f"/zpn/api/v1/admin/customers/{self.customer_id}/v2/application"
        response = self._obtain_all_pages(url)
        return response

    def list_segment_groups(
        self,
        **kwargs,
    ) -> json:
        """
        List Segment Groups

        :return: (requests.Response object)
        """
        url = f"/zpn/api/v1/admin/customers/{self.customer_id}/applicationGroup"
        response = self._obtain_all_pages(url)
        return response

    def list_server_groups(
        self,
        **kwargs,
    ) -> json:
        """
        List Server Groups
        :return: (list)
        """
        url = f"/zpn/api/v1/admin/customers/{self.customer_id}/serverGroup"
        response = self._obtain_all_pages(url)
        return response

    def list_sso_login_options(self) -> json:
        """
        List SSO login options

        :return: (json)
        """
        url = f"/zpn/api/v1/admin/customers/{self.customer_id}/v2/ssoLoginOptions"
        response = self.hp_http.get_call(url=url, headers=self.headers)
        return response.json()

    def list_session_timeout(self) -> json:
        """
        List session timeout

        :return: (json)
        """
        url = f"/zpn/api/v1/admin/customers/{self.customer_id}/v2/ssoLoginOptions"
        response = self.hp_http.get_call(url=url, headers=self.headers)
        return response.json()

    def list_config_overrides(self) -> json:
        """
        List session timeout

        :return: (json)
        """
        url = f"/zpn/api/v1/admin/customers/{self.customer_id}/configOverrides"
        response = self.hp_http.get_call(url=url, headers=self.headers)
        return response.json()

    def list_app_connector_groups(self) -> json:
        """
        List APP Connector Groups
        :return: (json)
        """
        url = f"/zpn/api/v1/admin/customers/{self.customer_id}/assistantGroup"
        response = self._obtain_all_pages(url)
        return response

    def list_app_connectors(self) -> json:
        """
        List App Connector
        :return: (json)
        """
        url = f"/zpn/api/v1/admin/customers/{self.customer_id}/assistant"
        response = self._obtain_all_pages(url)
        return response

    def list_policies(self, policy_type: str = "GLOBAL_POLICY") -> json:
        """
        List App Connector
        :param policy_type: string. possible values GLOBAL_POLICY, REAUTH_POLICY,BYPASS_POLICY, ISOLATION_POLICY,INSPECTION_POLICY
        """
        url = f"/zpn/api/v1/admin/customers/{self.customer_id}/policySet/rules/policyType/{policy_type}"
        response = self._obtain_all_pages(url)
        return response

    def _list_zone_details(
        self,
    ) -> json:
        """
        Internal Method to obtain service endpoints, server configurations etc
        """
        url = f"/zpn/api/v1/admin/zoneDetails?accessingCustomerId={self.customer_id}"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
        )

        return response.json()

    def list_sso_login_options(
        self,
    ) -> json:
        """
        Method to obtain SSO login for admins >Authentication?Settings>Enforce SS) loging for admins
        """
        url = f"/zpn/api/v1/admin/customers/{self.customer_id}/v2/ssoLoginOptions"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
        )

        return response.json()

    def list_druidget_highest_healthcheck_appconnectors(
        self,
        starttime: time = int(time.time()) - 86400 * 14,  # 14 Days ago
        endtime: time = int(time.time()),
        query: str = False,
    ) -> json:
        """
        Get the top 100 of Application Connectors with the highest Health Check count

        :param query: (str) Example ?page=1&pagesize=20&search=consequat
        :param starttime: (time) Unix Timestamp, Example 14 days ago -> time.time() - 86400 * 14
        :param endtime: (time) Unix Timestamp, Example now -> time.time()
        :return: (json)
        """
        if not query:
            query = "?limit=100&order=DESC"
        url = f"/druidservice/zpn/aggregates/{self.customer_id}/api/v1/aggs/topByMetric/target_count/func/MAX/startTime/{starttime}/endTime/{endtime}{query}"
        response = self.hp_http_druid.get_call(
            url,
            headers=self.headers,
            error_handling=True,
        )
        return response.json()
