import pdb

from helpers.http_calls import HttpCalls
import time
from getpass import getpass
from models.models import valid_category_ids
from models.models import super_categories
from models.models import valid_countries


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
        self.version = '1.1'

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

        if custom:
            url = '/urlCategories?customOnly=true'
        else:
            url = '/urlCategories'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid}, error_handling=True)
        return response.json()

    def add_url_categories(self, name, superCategory, urls, catID, keywords=None, customCategory=False):
        """
         Adds a new custom URL category.
        :param name: Name of the custom category
        :param superCategory: super category
        :param urls: list of urls
        :param catID: Category id
        :param keywords: list of key works
        :param customCategory: Default False. Set to Tye for custom category

        :return:  json
        """
        if keywords is None:
            keywords = [""]

        if superCategory not in super_categories:
            print(f'Error -> Invalid Super Category')
            print(f'{super_categories}')
            raise ValueError("Invalid super category")

        url = '/urlCategories'
        payload = {
            "configuredName": name,
            "customCategory": customCategory,
            "superCategory": superCategory,
            "keywords": keywords,
            "urls": urls,
            "id": catID
        }
        print(payload)
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
        # Rate limit 1/sec  and 400 hr and 100 URLs per call
        list_of_lists = [url_list[i:i + 100] for i in range(0, len(url_list), 100)]
        for item in list_of_lists:
            print(item)
            response = self.hp_http.post_call(url, payload=item, cookies={'JSESSIONID': self.jsessionid},
                                              error_handling=True)
            print(response.json())
            result.append(response.json())
            time.sleep(10)
        final_result = []
        for i in result:
            for j in i:
                final_result.append(j)
        return final_result

    # URL filtering Policies
    def list_url_filtering_rules(self, ):
        """
        Gets a list of all of URL Filtering Policy rules
        :return:
        """
        url = '/urlFilteringRules'
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
        payload = {"name": name,
                   "email": email,
                   "groups": groups,
                   "department": department,
                   "comments": comments,
                   "password": password,
                   "adminUser": adminuser}
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
        :param locationId: Location id
        """
        if locationId:
            url = f'/locations/{locationId}'
        else:
            url = f'/locations'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def list_sublocations(self, locationId):
        """
        Gets the sub-location information for the location with the specified ID
        :param locationId: Location id
        """
        if locationId:
            url = f'/locations/{locationId}'
        else:
            url = f'/locations'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def delete_bulk_locations(self, locationIds):
        """
        Bulk delete locations up to a maximum of 100 users per request. The response returns the location IDs that were successfully deleted..
        :param locationIds: list of location IDs
        """
        url = '/locations/bulkDelete'
        if len(locationIds) < 100:
            payload = {
                "ids": locationIds
            }
            response = self.hp_http.post_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                              error_handling=True)
            return response.json()
        else:
            raise ValueError("Maximum 100 users per request")

    def delete_locations(self, locationId):
        """
        Deletes the location or sub-location for the specified ID
        :param locationId: location ID
        """
        url = f'/locations/{locationId}'

        response = self.hp_http.delete_call(url, cookies={'JSESSIONID': self.jsessionid},
                                            error_handling=True)
        return response.json()

    #   Traffic Forwarding

    def list_greTunnels(self, greTunnelId=None):
        """
        Gets the GRE tunnel information for the specified ID
        :param greTunnelId: Optional. The unique identifier for the GRE tunnel
        """
        if greTunnelId:
            url = f'/greTunnels/{greTunnelId}'
        else:
            url = f'/greTunnels'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def list_vpnCredentials(self, vpnId=None):
        """
        Gets VPN credentials that can be associated to locations.
        :param vpnId: Optional. If specified, get VPN credentials for the specified ID.
        """
        if vpnId:
            url = f'/vpnCredentials/{vpnId}'
        else:
            url = f'/vpnCredentials'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def list_staticIP(self, IPId=None):
        """
        Gets all provisioned static IP addresses.
        :param IPId: Optional. If specified, get IP address for the specified id
        """
        if IPId:
            url = f'/staticIP/{IPId}'
        else:
            url = f'/staticIP'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def add_staticIP(self, ipAddress, geoOverrride=False, routableIP=True, latitude=0, longitude=0, comment=''):
        """
        Adds a static IP address
        :param ipAddress: String. The satic IP address
        :param geoOverrride: Boolean. If not set, geographic coordinates and city are automatically determined from
        the IP address. Otherwise, the latitude and longitude coordinates must be provided.
        :param routableIP: Boolean. Indicates whether a non-RFC 1918 IP address is publicly routable. This attribute is
        ignored if there is no ZIA Private Service Edge associated to the organization.
        :param latitude: Required only if the geoOverride attribute is set. Latitude with 7 digit precision after
        decimal point, ranges between -90 and 90 degrees.
        :param longitude: Required only if the geoOverride attribute is set. Longitude with 7 digit precision after
        decimal point, ranges between -180 and 180 degrees.
        :param comment: String Additional information about this static IP address
        """
        url = '/staticIP'

        payload = {
            "ipAddress": ipAddress,
            "latitude": latitude,
            "longitude": longitude,
            "routableIP": routableIP,
            "comment": comment
        }
        if geoOverrride:
            payload.update(geoOverrride=geoOverrride)
            payload.update(latitude=latitude)
            payload.update(longitude=longitude)

        response = self.hp_http.post_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                          error_handling=True)
        return response.json()

    # User Authentication Settings
    def list_exemptedUrls(self):
        """
        Gets a list of URLs that were exempted from cookie authentication
        """
        url = '/authSettings/exemptedUrls'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def add_exemptedUrls(self, urls):
        """
        Adds URLs to the cookie authentication exempt list to the list
        :param urls: List of urls. Example ['url1','url2']
        """
        url = '/authSettings/exemptedUrls?action=ADD_TO_LIST'
        payload = {"urls": urls}
        response = self.hp_http.post_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                          error_handling=True)
        return response.json()

    def delete_exemptedUrls(self, urls):
        """
        Adds URLs to the cookie authentication exempt list to the list
        :param urls: List of urls. Example ['url1','url2']
        """
        url = '/authSettings/exemptedUrls?action=REMOVE_FROM_LIST'
        payload = {"urls": urls}
        response = self.hp_http.post_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                          error_handling=True)
        return response.json()

    # Security Policy Settings
    def list_security_whitelisted_urls(self):
        """
        Gets a list of white-listed URLs
        """
        url = '/security'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def update_security_whitelisted_urls(self, urls):
        """
        Updates the list of white-listed URLs. This will overwrite a previously-generated white list.
        If you need to completely erase the white list, submit an empty list.
        :param urls: list of urls ['www.zscaler.com', 'www.example.com']
        """
        url = '/security'
        payload = {
            "whitelistUrls": urls
        }
        response = self.hp_http.put_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def list_security_blacklisted_urls(self):
        """
        Gets a list of white-listed URLs
        """
        url = '/security/advanced'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def update_security_blacklisted_urls(self, urls):
        """
       Updates the list of black-listed URLs. This will overwrite a previously-generated black list.
       If you need to completely erase the black list, submit an empty list.
        """
        url = '/security/advanced'
        payload = {
            "blacklistUrls": urls
        }
        response = self.hp_http.put_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def add_security_blacklistUrls(self, urls):
        """
        :param url: list of urls
        Adds a URL from the black list. To add a URL to the black list.
        """
        url = '/security/advanced/blacklistUrls?action=ADD_TO_LIST'
        payload = {
            "blacklistUrls": urls
        }
        response = self.hp_http.post_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                          error_handling=True)
        return response.text

    def remove_security_blacklistUrls(self, urls):
        """
        Removes a URL from the black list.
        :param urls: List of urls
        """
        url = '/security/advanced/blacklistUrls?action=REMOVE_FROM_LIST'
        payload = {
            "blacklistUrls": urls
        }
        response = self.hp_http.post_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                          error_handling=True)
        return response.json()

    # Firewall Policies

    def list_networkServices(self):
        """
        Gets a list of all network service groups. The search parameters find matching values within the "name" or
        "description" attributes.
        """
        url = '/networkServices'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def list_ipSourceGroups(self, ipGroupId=None):
        """
        Gets a list of all IP source groups. The search parameters find matching values within the "name" or
        "description" attributes.
        :param ipGroupId: Option ip group id
        """
        if ipGroupId:
            url = f'/ipSourceGroups/{ipGroupId}'
        else:
            url = '/ipSourceGroups'
        response = self.hp_http.get_call(url, cookies={'JSESSIONID': self.jsessionid},
                                         error_handling=True)
        return response.json()

    def add_ipSourceGroups(self, name, ipAddresses, description=None):
        """
        :param name: mame
        :param ipAddresses: list of IP addresses
        :param description: description
        """

        url = '/ipSourceGroups'
        payload = {
            "name": name,
            "ipAddresses": ipAddresses,
            "description": description
        }
        response = self.hp_http.post_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                          error_handling=True)
        return response.json()

    def add_ipSourceGroups(self, name, ipAddresses, description=None):
        """
        :param name: mame
        :param ipAddresses: list of IP addresses
        :param description: description
        """

        url = '/ipSourceGroups'
        payload = {
            "name": name,
            "ipAddresses": ipAddresses,
            "description": description
        }
        response = self.hp_http.post_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                          error_handling=True)
        return response.json()

    def add_ipDestinationGroups(self, name, type, addresses, ipCategories=None, countries=None, description=None):
        """
        :param name: mame
        :param type: Destination IP group type. Either DSTN_IP or DSTN_FQDN
        :param addresses: List of Destination IP addresses within the group.
        :param description: description
        :param ipCategories: List of Destination IP address URL categories. You can identify destination based
        on the URL category of the domain. Default value ANY
        :param countries: list of destination IP address countries. You can identify destinations based on the location
        of a server.Default value ANY
        """
        if type not in ["DSTN_IP", "DSTN_FQDN"]:
            raise ValueError("Invalid destination type ")
        if countries:
            for i in countries:
                if i not in valid_countries:
                     raise ValueError("Invalid country ")
        else:
            countries=[]

        if ipCategories:
            for j in ipCategories:
                if j  not in valid_category_ids:
                     raise ValueError("Invalid country ")
        else:
            ipCategories=[]

        url = '/ipDestinationGroups'
        payload = {
            "name": name,
            "type": type,
            "addresses": addresses,
            "ipCategories": ipCategories,
            "countries": countries,
            "description": description
        }
        print(payload)
        response = self.hp_http.post_call(url, payload=payload, cookies={'JSESSIONID': self.jsessionid},
                                          error_handling=True)
        return response.json()
