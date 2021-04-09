from helpers.http_calls import HttpCalls
import time
from getpass import getpass
from models.models import valid_category_ids
from models.models import super_categories


class ZiaTalker(object):
    """
    ZIA API talker
    Documentation: https://help.zscaler.com/zia/api
    https://help.zscaler.com/zia/6.1/api
    """

    def __init__(self, cloud_name):
        self.base_uri = f'https://{cloud_name}/api/v1'
        self.hp_http = HttpCalls(host=self.base_uri, verify=True)
        self.jsessionid = None
        self.version = '1.0'

    def _obfuscateApiKey(self, seed):
        """
        Internal method to Obfuscate the API key
        :param seed: API key
        :return: timestamp,obfuscated key
        """
        now = int(time.time() * 1000)
        n = str(now)[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ""
        for i in range(0, len(str(n)), 1):
            key += seed[int(str(n)[i])]
        for j in range(0, len(str(r)), 1):
            key += seed[int(str(r)[j]) + 2]
        return now, key

    def authenticate(self, apikey, username, password=None, ):
        """
        Method to authenticate.
        :param apikey: API key
        :param username: A string that contains the email ID of the API admin
        :param password: A string that contains the password for the API admin
        :return:  JSESSIONID. This cookie expires by default 30 minutes from last request
        """
        if not password:
            password = getpass(" Introduce password: ")
        timestamp, key = self._obfuscateApiKey(apikey)

        payload = {
            "apiKey": key,
            "username": username,
            "password": password,
            "timestamp": timestamp
        }
        url = '/authenticatedSession'
        response = self.hp_http.post_call(url=url, payload=payload)
        self.jsessionid = response.cookies['JSESSIONID']

    def authenticated_session(self):
        """
        Checks if there is an authenticated session
        :return: json
        """
        url = '/authenticatedSession'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid}, error_handling=True, )
        print(response)
        return response.json()

    def end_session(self):
        """
        Menthod to enf an authenticated session
        :return: None
        """
        url = '/authenticatedSession'
        response = self.hp_http.delete_call(url, cookies={'JSESSIONID': self.jsessionid}, error_handling=True,
                                            payload={})
        return response.json()

    def get_status(self):
        """
        Method to obtain the activation status for a configuration change
        :return: json object with the status
        """
        url = '/status'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid}, error_handling=True)
        return response.json()

    def activate_status(self):
        """
        Method to activate configuration changes
        :return: json object with the status
        """
        url = '/status/activate'
        response = self.hp_http.post_call(url, payload={}, cookies={'JSESSIONID': self.jsessionid}, error_handling=True)
        return response.json()

    # URL Categories
    def list_url_categories(self, custom=False):
        """
        Gets information about all or custom URL categories
        :param custom: Boolean, if True it will return custom categories only
        :return: json
        """
        url = '/urlCategories'
        if custom:
            response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                             params={'customonly': 'true'},
                                             error_handling=True)
        else:
            response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid}, error_handling=True)
        return response.json()

    def add_url_categories(self, name, supercategory, keywords=None, urls=None):
        """

        :param name: Name of the custom category
        :param supercategory: super category
        :param keywords: list of key works
        :param urls: list of urls
        :return:  json
        """
        if keywords is None:
            keywords = [""]

        if supercategory not in super_categories:
            print(f'Error -> Invalid Super Category')
            print(f'{super_categories}')
            raise ValueError("Invalid super category")

        url = '/urlCategories'
        payload = {
            "configuredName": name,
            "customCategory": "true",
            "superCategory": supercategory,
            "keywords": keywords,
            "urls": urls
        }
        response = self.hp_http.post_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                          error_handling=True)
        return response.json()

    def list_url_categories_urlquota(self):
        """
        Gets information on the number of unique URLs that are currently provisioned for your organization as well as
        how many URLs you can add before reaching that number.
        :return: json
        """
        url = '/urlCategories/urlQuota'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        print(response.json())
        return response.json()

    def list_url_categories_id(self, category_id):
        """
        Gets the URL category information for the specified ID
        :param category_id:
        :return:
        """

        url = f"/urlCategories/{category_id}"

        if category_id not in valid_category_ids:
            print(f'Error -> Invalid Category ID')
            print(f'{valid_category_ids}')
            raise ValueError("Invalid Category ID")
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def url_lookup(self, url_list):
        """
        Method to look up the categorization of the given list of URLs, ["abc.com","zyz.com"]
        :param url_list: list of urls
        :return:  json
        """
        url = '/urlLookup'
        response = self.hp_http.post_call(url, payload=url_list, cookies={'JSESSIONID': self.jsessionid},
                                          error_handling=True)
        return response.json()

    # User Management
    def list_departments(self, department_id=""):
        """
        Gets a list of departments. The search parameters find matching values within the "name" or "comments"
        attributes.
        if ID, gets the department for the specified ID

        :param id: department ID
        :return:json()
        """

        if department_id:
            url = "/departments"
        else:
            url = f'/departments/{department_id}'

        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def list_groups(self, group_id=""):
        """
        Gets a list of groups
        if ID, gets the group for the specified ID
        :param group_id: group ID
        :return:json()
        """
        if group_id:
            url = "/groups"
        else:
            url = f'/groups/{group_id}'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def list_users(self, user_id=""):
        """
        Gets a list of users
        if ID, gets user information for the specified ID
        :param user_id: user ID
        :return:json()
        """
        if user_id:
            url = "/users"
        else:
            url = f'/users/{user_id}'
        print(url)
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def add_users(self, name, email, groups, department, comments, password, adminuser=False, ):
        """
        Adds a new user. A user can belong to multiple groups, but can only belong to one department.

        :param name: string, user name
        :param email: string user email address
        :param groups: list. each member is a dictionary, key id, value name [{"id":1234, "name":"guest-wifi"}]
        :param department: dictionary, key is the id and value is the name {"id":1234, "name":"guests"}
        :param comments: string, comments
        :param password: string password,
        :param adminuser: True if user is admin user. default False
        :return: Json
        """
        url = '/users'
        payload = {
            "name": name,
            "email": email,
            "groups": groups,
            "department": department,
            "comments": comments,
            "adminUser": adminuser,
            "password": password
        }
        response = self.hp_http.post_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                          error_handling=True)
        return response.json()
