import re

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

    def delete_url_categories(self, categoryid):
        """
        Deletes the custom URL category for the specified ID.
        You cannot delete a custom category while it is being used by a URL policy or NSS feed. Also, predefined
        categories cannot be deleted.
        :param categoryid: Category ID
        :return: json response
        """
        url = f'/urlCategories/{categoryid}'
        response = self.hp_http.delete_call(url, cookies={'JSESSIONID': self.jsessionid},
                                            error_handling=True)
        return response.json()

    def update_url_categories(self, categoryid, supercategory, urls, description, cat_id):
        """
        Updates the URL category for the specified ID. You can perform a full update for the specified URL category.
        However, if attributes are omitted within the update request, the values for those attributes are cleared.
        :param categoryid: Category ID
        :return: json response
        """

        if supercategory not in super_categories:
            print(f'Error -> Invalid Super Category')
            print(f'{super_categories}')
            raise ValueError("Invalid super category")

        if categoryid not in valid_category_ids:
            print(f'Error -> Invalid Category ID')
            print(f'{valid_category_ids}')
            raise ValueError("Invalid super category")

        url = f'/urlCategories/{categoryid}'
        payload = {
            "customCategory": "false",
            "superCategory": supercategory,
            "urls": urls,
            "description": description,
            "id": cat_id
        }
        response = self.hp_http.put_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
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
        result = []
        url = '/urlLookup'
        # Verify urls format
        list(set(url_list))
        urls = []
        urls = []
        for i in url_list:
            if '[' not in i:
                if not re.search(r'http', i):
                    if '*' in i:
                        if re.search(r'^\*', i):
                            if len(re.findall(r'\.', i)) < 2:
                                urls.append(i)
                    else:
                        urls.append(i)

        # Rate limit 1/sec  and 400 hr and 100 URLs per call
        list_of_lists = [urls[i:i + 100] for i in range(0, len(urls), 100)]
        for item in list_of_lists:
            print(item)
            response = self.hp_http.post_call(url, payload=item, cookies={'JSESSIONID': self.jsessionid},
                                              error_handling=True)
            print(response.json())
            result.append(response.json())
            time.sleep(5)
        return result

    # URL filtering Policies
    def list_url_filtering_rules(self, ):
        """
        Gets a list of all of URL Filtering Policy rules
        :return:
        """
        url = 'urlFilteringRules'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    '''def add_url_filtering_rules(self, name, order, state, action, protocols, urlcategories,
                                admin_rack=7):
        """
         Adds a URL Filtering Policy rule.
         If you are using the Admin Rank feature, refer to About Admin Rank to determine which value to provide for rank
         when adding a policy rule. If you are not using Admin Rank, the rank value must be 7.
        :param name:  Name of the rule
        :param order: Rule order
        :param state: enabled/disabled
        :param action: Allow, Caution, Block
        :param protocols: list [ SMRULEF_ZPA_BROKERS_RULE, ANY_RULE, TCP_RULE, UDP_RULE, DOHTTPS_RULE, TUNNELSSL_RULE,
        HTTP_PROXY, FOHTTP_RULE, FTP_RULE, HTTPS_RULE, HTTP_RULE, SSL_RULE, TUNNEL_RULE ]
        :param locations: Name-ID pairs of locations for which rule must be applied
        :param groups: Name-ID pairs of groups for which rule must be applied
        :param departments: Name-ID pairs of departments for which rule will be applied
        :param users: Name-ID pairs of users for which rule must be applied
        :param urlcategories: List of URL categories for which rule must be applied
        :param admin_rack:Admin rank of the admin who creates this rule
        :param timewindows: Name-ID pairs of time interval during which rule must be enforced.
        :param requestmethods: Request method for which the rule must be applied. If not set, rule will be applied to all
         methods
        :param eun: URL of end user notification page to be displayed when the rule is matched. Not applicable if either
        'overrideUsers' or 'overrideGroups' is specified.
        :param overrideusers: Name-ID pairs of users for which this rule can be overridden. Applicable only if
         blockOverride is set to 'true', action is 'BLOCK' and overrideGroups is not set.If this overrideUsers is not
         set, 'BLOCK' action can be overridden for any user.
        :param overridegroups: Name-ID pairs of groups for which this rule can be overridden. Applicable only if
        blockOverride is set to 'true' and action is 'BLOCK'. If this overrideGroups is not set, 'BLOCK' action can be
        overridden for any group
        :param blockOverride: boolean: When set to true, a 'BLOCK' action triggered by the rule could be overridden.
        If true and both overrideGroup and overrideUsers are not set, the BLOCK triggered by this rule could be
        overridden for any users. If blockOverride is not set, 'BLOCK' action cannot be overridden.
        :param description: Additional information about the URL Filtering rule
        :return:
        """

        payload = {
            "id": 0,
            "name": name,
            "order": order,
            "protocols": protocols,
            "locations": location,
            "groups": groups,
            "departments": departments,
            "users": users,
            "urlCategories": urlcategories,
            "state": state,
            "timeWindows": timewindoes,
            "rank": rank,
            "requestMethods": requestmethods,
            "endUserNotificationUrl": eun,
            "overrideUsers": overrideusers,
            "overrideGroups": overridegroups,
            "blockOverride": blockoverride,
            "timeQuota": timequota,
            "sizeQuota": sizequota,
            "description": description,
            "locationGroups": locationgroups,
            "validityStartTime": 0,
            "validityEndTime": 0,
            "validityTimeZoneId": "string",
            "lastModifiedTime": 0,
            "lastModifiedBy": lastmodified
            },'''

    # User Management

    def list_departments(self, department_id=""):
        """
        Gets a list of departments. The search parameters find matching values within the "name" or "comments"
        attributes.
        if ID, gets the department for the specified ID
        :param department_id: department ID
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

    def list_users(self, user_id=None):
        """
        Gets a list of users
        if ID, gets user information for the specified ID
        :param user_id: user ID
        :return:json()
        """
        if user_id:
            url = f'/users/{user_id}'
        else:
            url = "/users"
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

    def delete_bulk_users(self, user_ids):
        """
        Bulk delete users up to a maximum of 500 users per request. The response returns the user IDs that were
        successfully deleted.
        :param user_ids:  List of user IDS to be deleted
        """
        url = '/users/bulkDelete'
        if len(user_ids) < 500:
            payload = {
                "ids": user_ids
            }
            response = self.hp_http.post_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                              error_handling=True)
            return response.json()
        else:
            raise ValueError("Maximum 500 users per request")


    # Location Management

    def list_locations(self, locationId=None):
        """
        Gets locations only, not sub-locations. When a location matches the given search parameter criteria only its
        parent location is included in the result set, not its sub-locations.
        """
        if locationId:
            url = f'/locations/{locationId}'
        else:
            url = f'/locations'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()