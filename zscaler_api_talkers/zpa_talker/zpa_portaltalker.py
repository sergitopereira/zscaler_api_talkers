import requests
from zscaler_api_talkers.zscaler_helpers import HttpCalls, setup_logger

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
