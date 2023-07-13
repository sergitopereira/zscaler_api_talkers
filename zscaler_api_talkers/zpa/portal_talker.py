import requests
import json
from zscaler_api_talkers.helpers import HttpCalls, setup_logger, request_

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

    def _obtain_all_pages(
        self,
        url: str,
    ) -> list:
        result = []
        response = requests.request(
            "GET",
            url,
            headers=self.token,
        )
        if int(response.json()["totalPages"]) > 1:
            i = 1
            while i <= int(response.json()["totalPages"]):
                result = (  # FIXME: I think this should be an list append instead of a string add.
                    result
                    + requests.request(
                        "GET",
                        url,
                        headers=self.token,
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
    ):
        """
        Method to obtain authorization token for subsequent calls.

        :param username: Email address
        :param password: Password for given user
        """
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
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Authorization": f"Bearer {self.token}",
        }

    def list_admin_users(self) -> list:
        """
        List admins users

        :return: (list)
        """
        url = f"/shift/api/v2/admin/customers/{self.customer_id}/users"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
        )
        if int(response.json()["totalPages"]) > 1:
            response = self._obtain_all_pages(
                url
            )  # FIXME: url isn't the whole URL thus _obtain_all_pages is failing
        else:
            response = response.json()["list"]

        return response

    def list_admin_roles(self) -> requests.Response:
        """
        List admins roles

        :return: (requests.Response Object)
        """
        url = f"/zpn/api/v1/admin/customers/{self.customer_id}/roles"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
        )

        return response

    def list_api_key(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        List the configured API Keys

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/clientCredentials",
            **kwargs,
        )

        return result

    def create_api_key(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Create an API Key

        :param data: (dict) Dict of API Key configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="post",
            url=f"{self.base_uri}/clientCredentials",
            json=data,
            **kwargs,
        )

        return result

    def update_api_key(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Update an API Key

        :param data: (dict) Dict of API Key configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="put",
            url=f"{self.base_uri}/clientCredentials/{data.get('id')}",
            json=data,
            **kwargs,
        )

        return result

    def delete_api_key(
        self,
        key_id: str,
        **kwargs,
    ) -> requests.Response:
        """
        Delete an API Key.

        :param key_id: (int) ID of the API Key

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/clientCredentials/{key_id}",
            **kwargs,
        )

        return result

    def list_application(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        List Applications

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/v2/application",
            **kwargs,
        )

        return result

    def delete_application(
        self,
        application_id: str,
        **kwargs,
    ) -> requests.Response:
        """
        Delete an Application.

        :param application_id: (int) ID of the application

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/v2/application/{application_id}",
            **kwargs,
        )

        return result

    def list_application_group(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        List Application Groups

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/applicationGroup",
            **kwargs,
        )

        return result

    def delete_application_group(
        self,
        group_id: str,
        **kwargs,
    ) -> requests.Response:
        """
        Delete an Application Group.

        :param group_id: (int) ID of the application group

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/applicationGroup/{group_id}",
            **kwargs,
        )

        return result

    def list_assistant_group(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        List Assistant Groups

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/assistantGroup",
            **kwargs,
        )

        return result

    def delete_assistant_group(
        self,
        group_id,
        **kwargs,
    ) -> requests.Response:
        """
        Delete an Assistant Group.

        :param group_id: (int) ID of the assitant group

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/assistantGroup/{group_id}",
            **kwargs,
        )

        return result

    def list_clientless_certificate(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        List Clientless Certificates

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/clientlessCertificate",
            **kwargs,
        )

        return result

    def delete_clientless_certificate(
        self,
        cert_id: str,
        **kwargs,
    ) -> requests.Response:
        """
        Delete a Clientless Certificate

        :param cert_id: (int) ID of the Clientless Certificate

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/clientlessCertificate/{cert_id}",
            **kwargs,
        )

        return result

    def list_role(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        List Roles

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/roles",
            **kwargs,
        )

        return result

    def delete_role(
        self,
        role_id: str,
        **kwargs,
    ) -> requests.Response:
        """
        Delete a Role

        :param role_id: (int) ID of the Role

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/roles/{role_id}",
            **kwargs,
        )

        return result

    def create_role(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Create a Role

        :param data: (dict) Dict of Role configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="post",
            url=f"{self.base_uri}/roles",
            json=data,
            **kwargs,
        )

        return result

    def create_search_suffix(self, data: dict, **kwargs,) -> requests.Response:
        """
        Create a Search Suffix

        :param data: (dict) Dict of Search Suffix configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="post",
            url=f"{self.base_uri}/v2/associationtype/SEARCH_SUFFIX/domains",
            json=data,
            **kwargs,
        )

        return result
