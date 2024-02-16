import requests
from requests.adapters import HTTPAdapter, Retry
from .logger import setup_logger

logger = setup_logger(name=__name__)


def _zia_http_codes(response: requests.Response):
    """
    Internal method to display HTTP error handling and response codes. For more information, please refer to
    https://help.zscaler.com/zia/about-error-handling

    :param response: (requests.Response Object)
    """
    if response.status_code in [200, 201, 202, 204]:
        return
    elif response.status_code == 401:
        raise ValueError(
            f"{response.status_code} :Session is not authenticated or timed out"
        )
    elif response.status_code == 403:
        raise ValueError(
            f"{response.status_code} :API key disabled or SKU subscription missing or user role has not access"
        )
    elif response.status_code == 404:
        raise ValueError("Resource does not exist")
    elif response.status_code == 409:
        raise ValueError(
            "Request could not be processed because of possible edit conflict occurred"
        )
    elif response.status_code == 415:
        raise ValueError("Unsupported media type")
    elif response.status_code == 429:
        raise ValueError("Exceeded the rate limit or quota")
    elif response.status_code == 500:
        raise ValueError("Unexpected error")
    elif response.status_code == 503:
        raise ValueError("Service is temporarily unavailable")
    else:
        print(response.content)
        raise ValueError(f"Unexpected HTTP response code: {response.status_code}")


class HttpCalls(object):
    """
    class to Perform HTTP calls
    """

    def __init__(
        self,
        host: str,
        header: dict = None,
        verify: bool = True,
    ):
        """
        to start this instance, host IP address or fqdn is required

        :param host: (str) IP address or fqdn
        :param header: (dict) HTTP header
        :param verify: (bool) True to verify ssl cert with in HTTP call
        """
        self.version = "1.1"
        self.host = host
        self.headers = {"Content-type": "application/json", "Cache-Control": "no-cache"}
        if header:
            self.headers.update(header)
        self.cookies = None
        self.verify = verify
        self.requests = requests.Session()
        retries = Retry(total=12,  # 2^12 = 4096 sec so max wait time in last retry 1.1 h
                        backoff_factor=2,
                        status_forcelist=[429],
                        allowed_methods=["GET", "PUT", "DELETE", "POST"])
        self.requests.mount('https://', HTTPAdapter(max_retries=retries))

    def get_call(
        self,
        url: str,
        cookies: dict = None,
        headers: dict = None,
        params: dict = None,
        error_handling: bool = False,
    ) -> requests.Response:
        """
        Method to perform a GET HTTP  call

        :param url: (str) url
        :param cookies: (str) cookies
        :param headers: (dict) Additional HTTP headers
        :param params: (dict) Key,Value parameters in the URL after a question mark
        :param error_handling: (bool) when TRUE will use Zscaler HTTP codes

        :return: (requests.Response Object)
        """
        full_url = f"{self.host}{url}"
        if headers:
            self.headers.update(headers)
        try:
            response = requests.get(
                url=full_url,
                headers=self.headers,
                cookies=cookies,
                params=params,
                verify=self.verify,
            )
            if error_handling:
                _zia_http_codes(response)
            else:
                if response.status_code not in [200, 201, 204]:
                    raise ValueError(f"{response.status_code} -> {response.content}")
            return response
        except requests.HTTPError as e:
            raise ValueError(e)

    def post_call(
        self,
        url: str,
        payload: dict,
        params: dict = None,
        headers: dict = None,
        cookies: dict = None,
        error_handling: bool = False,
        urlencoded: bool = False,
    ) -> requests.Response:
        """
        Method to perform an HTTP POST call

        :param url: (str) url
        :param payload: (dict)
        :param params: (dict)
        :param headers: (dict)
        :param cookies: (str) cookies
        :param error_handling: (bool) when TRUE will use Zscaler HTTP codes
        :param urlencoded: (bool)

        :return: (requests.Response Object)
        """
        full_url = f"{self.host}{url}"
        try:
            if urlencoded:
                url_encoded_headers = headers
                response = requests.post(
                    url=full_url,
                    params=params,
                    headers=url_encoded_headers,
                    cookies=cookies,
                    data=payload,
                    verify=self.verify,
                )
            else:
                if headers:
                    self.headers.update(headers)
                response = requests.post(
                    url=full_url,
                    params=params,
                    headers=self.headers,
                    cookies=cookies,
                    json=payload,
                    verify=self.verify,
                )
            if error_handling:
                _zia_http_codes(response)
            else:
                if response.status_code not in [200, 201, 204]:
                    raise ValueError(f"{response.status_code} -> {response.content}")
            return response
        except requests.HTTPError as e:
            raise ValueError(e)

    def patch_call(
        self,
        url: str,
        payload: dict,
        cookies: dict = None,
    ) -> requests.Response:
        """
        Method to perform an HTTP PATH call

        :param url: (str) url
        :param payload: (dict)
        :param cookies: (str) cookies

        :return: (requests.Response Object)
        """
        full_url = f"{self.host}{url}"
        try:
            response = requests.patch(
                url=full_url,
                headers=self.headers,
                cookies=cookies,
                json=payload,
                verify=self.verify,
            )
            if response.status_code not in [200, 201, 204]:
                raise ValueError(response.status_code)
            return response
        except requests.HTTPError as e:
            raise ValueError(e)

    def put_call(
        self,
        url: str,
        payload: dict,
        params: dict = None,
        headers: dict = None,
        cookies: dict = None,
        error_handling: bool = False,
    ) -> requests.Response:
        """
        Method to perform an HTTP PUT call

        :param url: (str) url
        :param params: (dict) Parameters to add to url
        :param payload: (dict)
        :param headers: (dict)
        :param cookies: (str) cookies
        :param error_handling: (bool) when TRUE will use Zscaler HTTP codes

        :return: (requests.Response Object)
        """
        full_url = f"{self.host}{url}"
        if headers:
            self.headers.update(headers)
        try:
            response = requests.put(
                url=full_url,
                params=params,
                headers=self.headers,
                cookies=cookies,
                json=payload,
                verify=self.verify,
            )
            if error_handling:
                _zia_http_codes(response)
            else:
                if response.status_code not in [200, 201, 204]:
                    try:
                        raise ValueError(
                            f"HTTPS Response code {response.status_code} : {response.json()}"
                        )
                    except ValueError:
                        raise ValueError(response.status_code)
            return response
        except requests.HTTPError as e:
            raise ValueError(e)

    def delete_call(
        self,
        url: str,
        payload: dict = None,
        headers: dict = None,
        cookies: dict = None,
        error_handling: bool = False,
    ) -> requests.Response:
        """
        Method to perform an HTTP DELETE call

        :param url: (str) url
        :param payload: (dict) json payload
        :param headers: (dict)
        :param cookies: (str) cookies
        :param error_handling: (bool) when TRUE will use Zscaler HTTP codes

        :return: (requests.Response Object)
        """
        full_url = f"{self.host}{url}"
        if headers:
            self.headers.update(headers)
        try:
            response = requests.delete(
                url=full_url,
                headers=self.headers,
                cookies=cookies,
                json=payload,
                verify=self.verify,
            )
            if error_handling:
                _zia_http_codes(response)
            else:
                if response.status_code not in [200, 201, 204]:
                    raise ValueError(response.status_code)
            return response
        except requests.HTTPError as e:
            raise ValueError(e)
