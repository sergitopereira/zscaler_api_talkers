import pdb
import time

from helpers.http_calls import HttpCalls


class ZccTalker(object):
    """
    Client Connector API talker
    Documentation: under development
    Currently in beta status
    """

    def __init__(self, cloud):
        self.base_uri = f'https://api-mobile.{cloud}/papi'
        self.hp_http = HttpCalls(host=self.base_uri, verify=True)
        self.jsessionid = None
        self.version = 'beta 0.1'

    def authenticate(self, clientid, secretkey):
        """
        Method to authenticate.
        :param clientid: Client id
        :param secretkey: client secret, obtained from portal
        :return:  None
        """
        payload = {
            "apiKey": clientid,
            "secretKey": secretkey
        }
        url = '/auth/v1/login'
        response = self.hp_http.post_call(url=url, headers={'Accept': '*/*'}, payload=payload)
        self.header = {
            'auth-token': response.json()['jwtToken']
        }

    def _obtain_all(self, url, cookies=None, params=None, headers=None):
        """
        Internal method that queries all pages
        :param url:  URL
        :return:
        """
        page = 1
        result = []
        while True:
            response = self.hp_http.get_call(f'{url}&page={page}', cookies=cookies, params=params, headers=headers,
                                             error_handling=True)
            if response.json():
                result += response.json()
                page += 1
                time.sleep(0.5)
            else:
                break
        return result

    def list_devices(self, companyID, username=None, osType=None):
        """
        Method to authenticate.
        :param companyID: type int. ORG ID
        :param username: type string. Username in email format
        :param osType  type int.
        :return:  type list
        """
        if username:
            url = f'/public/v1/getDevices?username={username}'
        elif osType:
            url = f'/public/v1/getDevices?osType={osType}'
        else:
            url = '/public/v1/getDevices?pagesize100'
        response = self._obtain_all(url=url, params=companyID, headers=self.header)
        return response

    def list_OTP(self, companyID, udid):
        """
        Method to fetch the One Time Password for a specific device. These passwords are unique and tied to a device UDID
        :param companyID: type int. ORG ID
        :param udid: type int. User device ID
        :return: type list
        """
        url = f'/public/v1/getOtp?udid={udid}'
        response = self.hp_http.get_call(url=url, params=companyID, headers=self.header)
        return response.json()

    def list_passwords(self, companyID, udid):
        """
        Method to fetch the One Time Password for a specific device. These passwords are unique and tied to a device UDID
        :param companyID: type int. ORG ID
        :param udid: type int. User device ID
        :return: type list
        """
        url = f'/public/v1/getOtp?udid={udid}'
        response = self.hp_http.get_call(url=url, params=companyID, headers=self.header)
        return response.json()

    def remove_devices(self, companyID, udids):
        """
        Method to  mark the device for removal (Device Removal Pending).
        :param companyID: type int. ORG ID
        :param udids: type list. List of user devices ids
        :return: type list
        """
        url = f'/public/v1/removeDevices'
        payload = {"companyId": companyID,
                   "udids": udids
                   }
        response = self.hp_http.post_call(url=url, headers=self.header, payload=payload)
        return response.json()

    def force_remove_devices(self, companyID, udids):
        """
        Force Remove, has the same effect as Remove, though it additionally moves the device straight to Removed and also
        signals the cloud to invalidate the user’s session.
        :param companyID: type int. ORG ID
        :param udids: type list. List of user devices ids
        :return: type list
        """
        url = f'/public/v1/forceRemoveDevices'
        payload = {"companyId": companyID,
                   "udids": udids
                   }
        response = self.hp_http.post_call(url=url, headers=self.header, payload=payload)
        return response.json()
