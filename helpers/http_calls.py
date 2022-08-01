import pdb

import requests


class HttpCalls(object):
    """
    class to Perform HTTP calls
    """

    def __init__(self, host, header=None, verify=True):
        """
        to start this instance, host IP address or fqdn is required
        :param host: IP address or fqdn
        :param header: dictionary. HTTP header
        :param verify: Boolean. True to verify ssl cert with in HTTP call
        """
        self.version = '1.1'
        self.host = host
        self.headers = {'Content-type': 'application/json',
                        'Cache-Control': 'no-cache'
                        }
        if header:
            self.headers.update(header)
        self.cookies = None
        self.verify = verify

    def get_call(self, url, cookies=None, headers=None, params=None, error_handling=False):
        """
        Method to perform a GET HTTP  call
        :param url: url
        :param cookies: cookies
        :param headers: Additional HTTP headers
        :param params: Key,Value parameters in the URL after a question mark
        :param error_handling: Boolean, when TRUE will use Zscaler HTTP codes
        :return: response
        """
        full_url = f'{self.host}{url}'
        if headers:
            self.headers.update(headers)
        try:
            response = requests.get(url=full_url, headers=self.headers, cookies=cookies, params=params,
                                    verify=self.verify)
            if error_handling:
                self._zia_http_codes(response)
            else:
                if response.status_code not in [200, 201, 204]:
                    raise ValueError(f'{response.status_code} -> {response.content}')
            return response
        except requests.HTTPError as e:
            raise ValueError(e)

    def post_call(self, url, payload, headers=None, cookies=None, error_handling=False, urlencoded=False):
        """
        Method to perform an HTTP POST call
        :param url: url
        :param cookies: cookies
        :param error_handling: Boolean, when TRUE will use Zscaler HTTP codes
        :return: response
        """
        full_url = f'{self.host}{url}'
        try:
            if urlencoded:
                url_encoded_headers = headers
                response = requests.post(url=full_url, headers=url_encoded_headers, cookies=cookies, data=payload,
                                         verify=self.verify)
            else:
                if headers:
                    self.headers.update(headers)
                response = requests.post(url=full_url, headers=self.headers, cookies=cookies, json=payload,
                                         verify=self.verify)
            if error_handling:
                self._zia_http_codes(response)
            else:
                if response.status_code not in [200, 201, 204]:
                    raise ValueError(response.status_code)
            return response
        except requests.HTTPError as e:
            raise ValueError(e)

    def patch_call(self, url, payload, cookies=None, ):
        """
        Method to perform an HTTP PATH call
        :param url: url
        :param cookies: cookies
        :return: response
        """
        full_url = f'{self.host}{url}'
        try:
            response = requests.patch(url=full_url, headers=self.headers, cookies=cookies, json=payload,
                                      verify=self.verify)
            if response.status_code not in [200, 201, 204]:
                raise ValueError(response.status_code)
            return response
        except requests.HTTPError as e:
            raise ValueError(e)

    def put_call(self, url, payload, cookies=None, error_handling=False):
        """
        Method to perform an HTTP PUT call
        :param url: url
        :param cookies: cookies
        :param error_handling: Boolean, when TRUE will use Zscaler HTTP codes
        :return: response
        """
        full_url = f'{self.host}{url}'
        try:
            response = requests.put(url=full_url, headers=self.headers, cookies=cookies, json=payload,
                                    verify=self.verify)
            if error_handling:
                self._zia_http_codes(response)
            else:
                if response.status_code not in [200, 201, 204]:
                    raise ValueError(response.status_code)
            return response
        except requests.HTTPError as e:
            raise ValueError(e)

    def delete_call(self, url, payload=None, cookies=None, error_handling=False):
        """
        Method to perform an HTTP DELETE call
        :param url: url
        :param payload: json payload
        :param cookies: cookies
        :param error_handling: Boolean, when TRUE will use Zscaler HTTP codes
        :return: response
        """
        full_url = f'{self.host}{url}'
        try:
            response = requests.delete(url=full_url, headers=self.headers, cookies=cookies, json=payload,
                                       verify=self.verify)
            if error_handling:
                self._zia_http_codes(response)
            else:
                if response.status_code not in [200, 201, 204]:
                    raise ValueError(response.status_code)
            return response
        except requests.HTTPError as e:
            raise ValueError(e)

    def _zia_http_codes(self, response):
        """
        Internal method to display HTTP error handling and response codes
        For more information, please refer to https://help.zscaler.com/zia/about-error-handling
        :param response:
        :return: None
        """
        if response.status_code in [200, 201, 202, 204]:
            return
        elif response.status_code == 401:
            raise ValueError(f'{response.status_code} :Session is not authenticated or timed out')
        elif response.status_code == 403:
            raise ValueError(
                f'{response.status_code} :API key disabled or SKU subscription missing or user role has not access')
        elif response.status_code == 404:
            raise ValueError('Resource does not exist')
        elif response.status_code == 409:
            raise ValueError('Request could not be processed because of possible edit conflict occurred')
        elif response.status_code == 415:
            raise ValueError('Unsupported media type')
        elif response.status_code == 429:
            raise ValueError('Exceeded the rate limit or quota')
        elif response.status_code == 500:
            raise ValueError('Unexpected error')
        elif response.status_code == 503:
            raise ValueError('Service is temporarily unavailable')
        else:
            print(response.content)
            raise ValueError(f'Unexpected HTTP response code: {response.status_code}')
