import pdb

import requests

from helpers.http_calls import HttpCalls


class ZpaPortalTalker(object):

    def __init__(self, customerId, cloud='https://api.private.zscaler.com'):
        self.base_uri = cloud
        self.version = '1.0'
        self.cookies = None
        self.bear = None
        self.token = None
        self.headers = None
        self.customerId = customerId
        self.hp_http = HttpCalls(host=self.base_uri, verify=True)

    def _obtain_all_pages(self, url):
        result = []
        response = requests.request("GET", url, headers=self.token)
        if int(response.json()['totalPages']) > 1:
            i = 1
            while i <= int(response.json()['totalPages']):
                result = result + requests.request("GET", url, headers=self.token).json()['list']
                i += 1
        else:
            result = response.json()['list']
        return result

    def authenticate(self, username, password):
        """
        Method to obtain authorization token for subsequent calls.
        :param username: Email address
        :param password: Password for given user
        """
        url = "/base/api/zpa/signin"
        payload = {'username': username,
                   'password': password}
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = self.hp_http.post_call(url=url, payload=payload, headers=headers, urlencoded=True)
        self.token = response.json()['Z-AUTH-TOKEN']
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Authorization': 'Bearer ' + self.token
        }
        return


    def list_admin_users(self):
        """List admins users"""
        url = f'/shift/api/v2/admin/customers/{self.customerId}/users'
        response = self.hp_http.get_call(url=url, headers=self.headers)

        if int(response.json()['totalPages']) > 1:
            response = self._obtain_all_pages(url)
        else:
            response = response.json()['list']
        return response

    def list_admin_roles(self):
        """List admins roles"""
        url = f'/zpn/api/v1/admin/customers/{self.customerId}/roles'
        response = self.hp_http.get_call(url=url, headers=self.headers)
        return response
