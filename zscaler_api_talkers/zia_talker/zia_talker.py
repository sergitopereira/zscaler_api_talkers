import json
import pdb  # noqa
import time
from getpass import getpass

import requests
from zia_talker.models import (super_categories, valid_category_ids,
                               valid_countries)
from zscaler_helpers import HttpCalls


class ZiaTalker(object):
    """
    ZIA API talker
    Documentation:
    https://help.zscaler.com/zia/zia-api/api-developer-reference-guide
    """

    def __init__(
        self,
        cloud_name: str,
        bearer: str = None,
        api_key: str = "",
        username: str = "",
        password: str = "",
    ):
        """
        Method to start the class

        :param cloud_name: (str) Example: zscalerbeta.net, zscalerone.net, zscalertwo.net, zscalerthree.net,
            zscaler.net, zscloud.net
        :param bearer: (str) OAuth2.0 Bear token
        """
        self.base_uri = f"https://zsapi.{cloud_name}/api/v1"
        self.hp_http = HttpCalls(
            host=self.base_uri,
            verify=True,
        )
        self.cookies = None
        self.headers = None
        if bearer:
            self.headers = {"Authorization": f"Bearer {bearer}"}
        if username and any([password, api_key]):
            self.authenticate(
                username=username,
                apikey=api_key,
                password=password,
            )

    def _obfuscateApiKey(  # TODO: This should be abstracted out along with the one in zia_portaltalker.
        self,
        seed: str,
    ) -> (time, str):
        """
        Internal method to Obfuscate the API key

        :param seed: (str) API key

        :return: (str, str) timestamp,obfuscated key
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

    def authenticate(
        self,
        apikey: str,
        username: str,
        password: str = None,
    ):
        """
        Method to authenticate.

        :param apikey: API key
        :param username: A string that contains the email ID of the API admin
        :param password: A string that contains the password for the API admin
        """
        if not password:
            password = getpass(" Introduce password: ")
        timestamp, key = self._obfuscateApiKey(apikey)

        payload = {
            "apiKey": key,
            "username": username,
            "password": password,
            "timestamp": timestamp,
        }
        url = "/authenticatedSession"
        response = self.hp_http.post_call(
            url=url,
            payload=payload,
        )
        self.cookies = {"JSESSIONID": response.cookies["JSESSIONID"]}

    def authenticated_session(self) -> json:
        """
        Checks if there is an authenticated session

        :return: (json)
        """
        url = "/authenticatedSession"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
        )

        return response.json()

    def end_session(self) -> json:
        """
        Method to end an authenticated session

        :return: (json)
        """
        url = "/authenticatedSession"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            payload={},
        )

        return response.json()

    def _obtain_all(
        self,
        url: str,
    ) -> json:
        """
        Internal method that queries all pages

        :param url: (str) URL

        :return: (json) JSON of result
        """
        page = 1
        result = []
        while True:
            response = self.hp_http.get_call(
                f"{url}&page={page}",
                cookies=self.cookies,
                error_handling=True,
                headers=self.headers,
            )
            if response.json():
                result += response.json()
                page += 1
                time.sleep(1)
            else:
                break

        return result

    def get_status(self) -> json:
        """
        Method to obtain the activation status for a configuration change

        :return: (json) JSON object with the status
        """
        url = "/status"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
        )

        return response.json()

    def activate_status(self) -> json:
        """
        Method to activate configuration changes

        :return: (json) JSON object with the status
        """
        url = "/status/activate"
        response = self.hp_http.post_call(
            url,
            payload={},
            cookies=self.cookies,
            error_handling=True,
        )
        return response.json()

    # Admin Audit Logs

    def list_auditlogEntryReport(self) -> json:
        """
        Gets the status of a request for an audit log report.  After sending a POST request to /auditlogEntryReport
        to generate a report, you can continue to call GET /auditlogEntryReport to check whether the report has
        finished generating. Once the status is COMPLETE, you can send another GET request to
        /auditlogEntryReport/download to download the report as a CSV file.

        :return: (json)
        """

        url = "/auditlogEntryReport"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            headers=self.headers,
            error_handling=True,
        )

        return response.json()

    def download_auditlogEntryReport(self) -> requests.Response:
        """
        Gets the status of a request for an audit log report. After sending a POST request to /auditlogEntryReport
        to generate a report, you can continue to call GET /auditlogEntryReport to check whether the report has
        finished generating. Once the status is COMPLETE, you can send another GET request to
        /auditlogEntryReport/download to download the report as a CSV file.

        :return: (request.Response)
        """
        url = "/auditlogEntryReport/download"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            headers=self.headers,
            error_handling=True,
        )

        return response

    def add_auditlogEntryReport(
        self,
        startTime: int,
        endTime: int,
        actionTypes: list = None,
        category: str = None,
        subcategories: list = None,
        actionInterface: str = None,
    ) -> requests.Response:
        """
         Creates an audit log report for the specified time period and saves it as a CSV file. The report includes
         audit information for every call made to the cloud service API during the specified time period. Creating a
         new audit log report will overwrite a previously-generated report.

        :param startTime: (int) The timestamp, in epoch, of the admin's last login
        :param endTime: (int) The timestamp, in epoch, of the admin's last logout.
        :param actionTypes: (list) The action performed by the admin in the ZIA Admin Portal or API
        :param category: (str) The location in the Zscaler Admin Portal (i.e., Admin UI) where the actionType was
        performed.
        :param subcategories: (list) The area within a category where the actionType was performed.
        :param actionInterface: (str) The interface (i.e., Admin UI or API) where the actionType was performed.

        :return: 204 Successfull Operation
        """
        url = "/auditlogEntryReport"
        payload = {
            "startTime": startTime,
            "endTime": endTime,
        }
        if category:
            payload.update(category=category)
        if subcategories:
            payload.update(subcategories=subcategories)
        if actionInterface:
            payload.update(actionInterface=actionInterface)
        if actionTypes:
            payload.update(actionTypes=actionTypes)

        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    # Admin & Role Management
    def list_adminUsers(
        self,
        userId: int = None,
        query: str = None,
    ) -> json:
        """
        Gets a list of admin users. By default, auditor user information is not included.

        :param userId: (int) user ID
        :param query: (str) HTTP query

        :return: (json) JSON of results
        """
        if userId:
            url = f"/adminUsers/{userId}"
            return self.hp_http.get_call(
                url,
                cookies=self.cookies,
                error_handling=True,
                headers=self.headers,
            ).json()
        else:
            if query:
                url = f"/adminUsers?{query}?pageSize=1000"
            else:
                url = "/adminUsers?pageSize=1000"

        return self._obtain_all(url)

    def list_adminRoles(
        self,
        query: str = None,
    ) -> json:
        """
        Gets a name and ID dictionary of al admin roles

        :param query: (str) HTTP query

        :return: (json)
        """
        if query:
            url = f"/adminRoles/lite?{query}"
        else:
            url = "/adminRoles/lite"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    # URL Categories
    def list_url_categories(
        self,
        custom: bool = False,
    ) -> json:
        """
        Gets information about all or custom URL categories

        :param custom: (bool) If True it will return custom categories only.  Default is False.

        :return: (json)
        """

        if custom:
            url = "/urlCategories?customOnly=true"
        else:
            url = "/urlCategories"
        # return self._obtain_all(url)
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_url_categories_lite(self) -> json:
        """
        Gets a lightweight key-value list of all or custom URL categories.

        :return: (json)
        """
        url = "/urlCategories/lite"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_url_categories(
        self,
        name: str,
        superCategory: str,
        type: list = ["URL_CATEGORY"],  # FIXME: Shadows built-in name.
        urls: list = None,
        dbCategorizedUrls: list = None,
        keywordsRetainingParentCategory: list = [],
        keywords: list = [],
        customCategory: bool = False,
        ipRanges: list = [],
        ipRangesRetainingParentCategory: list = [],
    ) -> json:
        """
         Adds a new custom URL category.

        :param name: (str) Name of the custom category. Possible values URL_CATEGORY, TLD_CATEGORY, ALL
        :param superCategory: (str) super category
        :param urls: (list) List of urls
        :param dbCategorizedUrls: (list) URL retaining parent category
        :param keywordsRetainingParentCategory: (list) Retained custom keywords from the parent URL category that is
        associated to a URL category.
        :param keywords: (list) Custom keywords associated to a URL category.
        :param customCategory: (bool) Default False. Set to True for custom category
        :param ipRanges: (list) Custom IP address ranges associated to a URL category
        :param ipRangesRetainingParentCategory: (list) The retaining parent custom IP address ranges associated to a
        URL category.

        :return:  json
        """
        if keywordsRetainingParentCategory is None:
            keywordsRetainingParentCategory = []

        if superCategory not in super_categories:
            print("Error -> Invalid Super Category")  # TODO: Move to logging
            print(f"{super_categories}")  # TODO: Move to logging
            raise ValueError("Invalid super category")

        url = "/urlCategories"
        payload = {
            "configuredName": name,
            "customCategory": customCategory,
            "superCategory": superCategory,
            "keywordsRetainingParentCategory": keywordsRetainingParentCategory,
            "keywords": keywords,
            "urls": urls,
            "dbCategorizedUrls": dbCategorizedUrls,
            "ipRanges": ipRanges,
            "ipRangesRetainingParentCategory": ipRangesRetainingParentCategory,
            "type": type,
        }
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_url_categories1(
        self,
        payload: dict,
    ) -> json:
        """
         Adds a new custom URL category.

        :param payload: (dict)

        :return: (json)
        """
        url = "/urlCategories"
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def update_url_categories(
        self,
        categoryId: str,
        action: str = None,
        configuredName: str = None,
        urls: list = None,
        dbCategorizedUrls: list = None,
        keywords: list = None,
        keywordsRetainingParentCategory: list = None,
    ) -> json:
        """
         Updates the URL category for the specified ID. If keywords are included within the request, then they will
         replace existing ones for the specified URL category . If the keywords attribute is not included the
         request, the existing keywords are retained. You can perform a full update for the specified URL category.
         However, if attributes are omitted within the  update request, the values for those attributes are cleared.

        You can also perform an incremental update, to add or remove URLs for the specified URL category using the
        action parameter.

        :param categoryId: (str) URL id
        :param action: (str) Optional parameter. ADD_TO_LIST or REMOVE_FROM_LIST
        :param configuredName: (str) Name of the custom category
        :param urls: (list) List of urls
        :param dbCategorizedUrls: (list) URL retaining parent category
        :param keywordsRetainingParentCategory: (list) List of key works

        :return:  (json)
        """
        """if categoryId not in valid_category_ids:
            print(f'Error -> Invalid category id')
            raise ValueError("Invalid category id")"""

        if action == "ADD_TO_LIST":
            url = f"/urlCategories/{categoryId}?action=ADD_TO_LIST"
        elif action == "REMOVE_FROM_LIST":
            url = f"/urlCategories/{categoryId}?action=REMOVE_FROM_LIST"
        elif not action:
            url = f"/urlCategories/{categoryId}"
        else:
            print("Error -> Invalid action")
            print(f"{action}")
            raise ValueError("Invalid action")

        payload = {
            "configuredName": configuredName,
        }
        if keywordsRetainingParentCategory:
            payload.update(
                keywordsRetainingParentCategory=keywordsRetainingParentCategory
            )
        if keywords:
            payload.update(keywords=keywords)
        if configuredName:
            payload.update(configuredName=configuredName)
        if urls:
            payload.update(urls=urls)
        if dbCategorizedUrls:
            payload.update(dbCategorizedUrls=dbCategorizedUrls)

        response = self.hp_http.put_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_url_categories(
        self,
        categoryid: int,
    ) -> requests.Response:
        """
        Deletes the custom URL category for the specified ID. You cannot delete a custom category while it is being
        used by a URL policy or NSS feed. Also, predefined categories cannot be deleted.

        :param categoryid: (inst) Category ID

        :return: (requests.Response)
        """
        url = f"/urlCategories/{categoryid}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def delete_urlFilteringRules(
        self,
        ruleId: int,
    ) -> requests.Response:
        """
        Deletes the custom URL category for the specified ID. You cannot delete a custom category while it is being
        used by a URL policy or NSS feed. Also, predefined categories cannot be deleted.

        :param ruleId: (int) Rule Id

        :return: (request.Response)
        """
        url = f"/urlFilteringRules/{ruleId}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def list_url_categories_urlquota(self) -> json:
        """
        Gets information on the number of unique URLs that are currently provisioned for your organization as well as
        how many URLs you can add before reaching that number.

        :return: (json)
        """
        url = "/urlCategories/urlQuota"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )
        print(response.json())

        return response.json()

    def list_url_categories_id(
        self,
        category_id: int,
    ) -> json:
        """
        Gets the URL category information for the specified ID

        :param category_id: (int)

        :return: (json)
        """
        url = f"/urlCategories/{category_id}"
        if category_id not in valid_category_ids:
            print("Error -> Invalid Category ID")
            print(f"{valid_category_ids}")
            raise ValueError("Invalid Category ID")
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def url_lookup(
        self,
        url_list: list,
    ) -> list:
        """
        Method to look up the categorization of the given list of URLs, ["abc.com","zyz.com"]

        :param url_list: (list) List of urls
        :return: (list)
        """
        result = []
        url = "/urlLookup"
        # Verify urls format
        list(set(url_list))
        # Rate limit 1/sec  and 400 hr and 100 URLs per call
        list_of_lists = [url_list[i : i + 100] for i in range(0, len(url_list), 100)]
        for item in list_of_lists:
            response = self.hp_http.post_call(
                url,
                payload=item,
                cookies=self.cookies,
                headers=self.headers,
                error_handling=True,
            )
            result.append(response.json())
            time.sleep(1)
        final_result = []
        for i in result:
            for j in i:
                final_result.append(j)

        return final_result

    # URL filtering Policies
    def list_url_filtering_rules(self) -> json:
        """
        Gets a list of all of URL Filtering Policy rules

        :return: (json)
        """
        url = "/urlFilteringRules"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )
        return response.json()

    def add_url_filtering_rules(  # FIXME: docstring lists params that aren't options and some params I don't know what their typehint should be.
        self,
        name: str,
        order: int,
        protocols: str,
        state: str,
        action: str,
        urlcategories: list = [],
        requestMethods: list = None,
        description=None,
        groups: list = None,
        locations: list = None,
        departments: list = None,
        users: list = None,
        rank: int = 7,
        locationGroups=None,
        enforceTimeValidity: bool = False,
        validityEndTime=None,
        validityStartTime=None,
        validityTimeZoneId=None,
        cbiProfileId: int = 0,
        blockOverride: bool = False,
    ) -> json:
        """
         Adds a URL Filtering Policy rule. If you are using the Rank feature, refer to About Admin Rank to
         determine which value to provide for rank when adding a policy rule. If you are not using Admin Rank,
         the rank value must be 7.

        :param name: (str)  Name of the rule
        :param order: (int) Rule order
        :param protocols: (str) Possible values: SMRULEF_ZPA_BROKERS_RULE, ANY_RULE, TCP_RULE, UDP_RULE,
        DOHTTPS_RULE, TUNNELSSL_RULE, HTTP_PROXY, FOHTTP_RULE, FTP_RULE, HTTPS_RULE, HTTP_RULE, SSL_RULE, TUNNEL_RULE
        :param state: (str) enabled/disabled
        :param action: (str) Allow, Caution, Block
        :param urlcategories: (list) List of URL categories for which rule must be applied
        :param requestMethods: (list) Request method for which the rule must be applied. If not set, rule will be
        applied to all methods
        :param description: (str) Additional information about the URL Filtering rule
        :param groups: (list) Name-ID pairs of groups for which rule must be applied
        :param locations: (list) Each element is a dictionary: Name-ID pairs of locations for which rule must be applied
        :param departments: (list) Name-ID pairs of departments for which rule will be applied
        :param users: (list) Name-ID pairs of users for which rule must be applied
        :param rank: (int) Admin rank of the admin who creates this rule
        :param locationGroups:
        :param enforceTimeValidity: (bool)
        :param validityEndTime:
        :param validityStartTime:
        :param validityTimeZoneId:
        :param cbiProfileId: (int)
        :param blockOverride: (bool) When set to true, a 'BLOCK' action triggered by the rule could be overridden.
        If true and both overrideGroup and overrideUsers are not set, the BLOCK triggered by this rule could be
        overridden for any users. If blockOverride is not set, 'BLOCK' action cannot be overridden.

        :param timewindows: (list) Name-ID pairs of time interval during which rule must be enforced.
        :param endUserNotificationUrl: (str) URL of end user notification page to be displayed when the rule
        is matched. Not applicable if either 'overrideUsers' or 'overrideGroups' is specified.
        :param overrideusers: Name-ID pairs of users for which this rule can be overridden. Applicable only if
        blockOverride is set to 'true', action is 'BLOCK' and overrideGroups is not set.If this overrideUsers is not
        set, 'BLOCK' action can be overridden for any user.
        :param overridegroups: Name-ID pairs of groups for which this rule can be overridden. Applicable only if
        blockOverride is set to 'true' and action is 'BLOCK'. If this overrideGroups is not set, 'BLOCK' action can
        be overridden for any group

        :return:
        """
        url = "/urlFilteringRules"
        payload = {
            "blockOverride": blockOverride,
            "cbiProfileId": cbiProfileId,
            "description": description,
            "enforceTimeValidity": enforceTimeValidity,
            "name": name,
            "order": order,
            "protocols": protocols,
            "urlCategories": urlcategories,
            "state": state,
            "rank": rank,
            "action": action,
        }
        if locations:
            payload.update(locations=locations)
        if locationGroups:
            payload.update(locationGroups=locationGroups)
        if groups:
            payload.update(groups=groups)
        if departments:
            payload.update(departments=departments)
        if users:
            payload.update(users=users)
        if requestMethods:
            payload.update(requestMethods=requestMethods)
        if enforceTimeValidity:
            payload.update(validityStartTime=validityStartTime)
            payload.update(validityEndTime=validityEndTime)
            payload.update(validityTimeZoneId=validityTimeZoneId)

        print(payload)

        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    # User Management

    def list_departments(
        self,
        department_id: str = "",
    ) -> json:
        """
        Gets a list of departments. The search parameters find matching values within the "name" or "comments"
        attributes. if ID, gets the department for the specified ID

        :param department_id: (str) department ID

        :return: (json)
        """

        if department_id:
            url = "/departments"
        else:
            url = f"/departments/{department_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_groups(
        self,
        group_id: int = None,
    ) -> json:
        """
        Gets a list of groups if ID, gets the group for the specified ID

        :param group_id: group ID

        :return: (json)
        """
        if not group_id:
            url = "/groups?pageSize=10000"
            return self._obtain_all(url)
        else:
            url = f"/groups/{group_id}"
            response = self.hp_http.get_call(
                url,
                cookies=self.cookies,
                error_handling=True,
                headers=self.headers,
            )

        return response.json()

    def list_users(
        self,
        user_id: int = None,
        query: str = None,
    ):
        """
        Gets a list of all users and allows user filtering by name, department, or group. The name search parameter
        performs a partial match. The dept and group parameters perform a 'starts with' match. if ID,
        gets user information for the specified ID

        :param user_id: (int) user ID
        :param query: (str)

        :return: (json)
        """
        if user_id:
            url = f"/users/{user_id}"
            return self.hp_http.get_call(
                url,
                cookies=self.cookies,
                error_handling=True,
                headers=self.headers,
            ).json()
        else:
            if query:
                url = f"/users?{query}&pageSize=1000"
                return self.hp_http.get_call(
                    url,
                    cookies=self.cookies,
                    error_handling=True,
                    headers=self.headers,
                ).json()
            else:
                url = "/users?pageSize=1000"

        return self._obtain_all(url)

    def add_users(
        self,
        name: str,
        email: str,
        groups: list,
        department: dict,
        comments: str,
        password: str,
        adminuser: bool = False,
    ) -> json:
        """
        Adds a new user. A user can belong to multiple groups, but can only belong to one department.

        :param name: (str) user name
        :param email: (str) user email address
        :param groups: (list) List each member is a dictionary, key id, value name [{"id":1234, "name":"guest-wifi"}]
        :param department: (dict) key is the id and value is the name {"id":1234, "name":"guests"}
        :param comments: (str) Comments
        :param password: (str) Password,
        :param adminuser: (bool) True if user is admin user. default False

        :return: (json)
        """
        url = "/users"
        payload = {
            "name": name,
            "email": email,
            "groups": groups,
            "department": department,
            "comments": comments,
            "password": password,
            "adminUser": adminuser,
        }
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_bulk_users(
        self,
        user_ids: list,
    ) -> json:
        """
        Bulk delete users up to a maximum of 500 users per request. The response returns the user IDs that were
        successfully deleted.

        :param user_ids: (list) List of user IDS to be deleted.  Max 500 per bulk delete.

        :return: (json)
        """
        url = "/users/bulkDelete"
        if len(user_ids) < 500:
            payload = {"ids": user_ids}
            response = self.hp_http.post_call(
                url,
                payload=payload,
                cookies=self.cookies,
                error_handling=True,
                headers=self.headers,
            )
            return response.json()
        else:
            raise ValueError("Maximum 500 users per request")

    # Location Management

    def list_locations(
        self,
        locationId: int = None,
    ) -> json:
        """
        Gets locations only, not sub-locations. When a location matches the given search parameter criteria only its
        parent location is included in the result set, not its sub-locations.

        :param locationId: (int) Location id

        :return: (json)
        """
        if locationId:
            url = f"/locations/{locationId}"
        else:
            url = "/locations"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_sublocations(
        self,
        locationId: int,
    ) -> json:
        """
        Gets the sub-location information for the location with the specified ID

        :param locationId: (int) Location id

        :return: (json)
        """
        if locationId:
            url = f"/locations/{locationId}/sublocations"
        else:
            url = "/locations"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_locationsgroups(self) -> json:
        """
        Gets information on location groups

        :return: (json)
        """
        url = "/locations/groups"
        print(url)
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_bulk_locations(
        self,
        locationIds: list,
    ) -> json:
        """
        Bulk delete locations up to a maximum of 100 users per request. The response returns the location IDs that
        were successfully deleted.

        :param locationIds: (list) List of location IDs

        :return: (json)
        """
        url = "/locations/bulkDelete"
        if len(locationIds) < 100:
            payload = {"ids": locationIds}
            response = self.hp_http.post_call(
                url,
                payload=payload,
                cookies=self.cookies,
                error_handling=True,
                headers=self.headers,
            )
            return response.json()
        else:
            raise ValueError("Maximum 100 locations per request")

    def delete_locations(
        self,
        locationId: int,
    ) -> requests.Response:
        """
        Deletes the location or sub-location for the specified ID

        :param locationId: (int) location ID

        :return: (request.Response object)
        """
        url = f"/locations/{locationId}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    #   Traffic Forwarding

    def list_greTunnels(
        self,
        greTunnelId: int = None,
    ) -> json:
        """
        Gets the GRE tunnel information for the specified ID

        :param greTunnelId: (int) Optional. The unique identifier for the GRE tunnel

        :return: (json)
        """
        if greTunnelId:
            url = f"/greTunnels/{greTunnelId}"
        else:
            url = "/greTunnels"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_greTunnels(
        self,
        sourceIp: str,
        primaryDestVip: dict,
        secondaryDestVip: dict,
        internalIpRange: str,
        withinCountry: bool,
        comment: str,
        ipUnnumbered: bool,
    ) -> json:
        """
        Adds a GRE tunnel configuration.

        :param sourceIp: (str) The source IP address of the GRE tunnel. This is typically a static IP address in the
        organization or SD-WAN. This IP address must be provisioned within the Zscaler service using the /staticIP
        endpoint.
        :param primaryDestVip: (dict) {id:value} where value is integer: Unique identifier of the GRE primary VIP
        :param secondaryDestVip: (dict) {id:value} where value is integer: Unique identifier of the GRE secondary VIP
        :param internalIpRange: (str) The start of the internal IP address in /29 CIDR range
        :param withinCountry: (bool) Restrict the data center virtual IP addresses (VIPs) only to those within the
        same country as the source IP address
        :param comment: (str) Additional information about this GRE tunnel
        :param ipUnnumbered: (bool?) This is required to support the automated SD-WAN provisioning of GRE tunnels,
        when set to True gre_tun_ip and gre_tun_id are set to null

        :return: (json)
        """
        url = "/greTunnels"
        payload = {
            "sourceIp": sourceIp,
            "primaryDestVip": primaryDestVip,
            "secondaryDestVip": secondaryDestVip,
            "internalIpRange": internalIpRange,
            "withinCountry": withinCountry,
            "comment": comment,
            "ipUnnumbered": ipUnnumbered,
        }
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_gre_validateAndGetAvailableInternalIpRanges(self) -> json:
        """
        Gets the next available GRE tunnel internal IP address ranges

        :return: (json) List of available IP addresses
        """
        url = "/greTunnels/availableInternalIpRanges"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_gre_recommended_vips(
        self,
        query: str,
    ) -> json:
        """
        Gets a list of recommended GRE tunnel virtual IP addresses (VIPs), based on source IP address or
        latitude/longitude coordinates.

        :param query: (str) URL query. Example:

        :return: (json) List of available IP addresses
        """
        url = f"/vips/recommendedList?{query}"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_gre_validate_ip(
        self,
        ip: str,
    ) -> json:
        """
        Gets the static IP address and location mapping information for the specified GRE tunnel IP address

        :param ip: (str) IP address of the GRE tunnel.

        :return: (json)
        """
        url = f"/greTunnels/validateIP/{ip}"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_vpnCredentials(
        self,
        vpnId: int = None,
    ) -> json:
        """
        Gets VPN credentials that can be associated to locations.

        :param vpnId: (int) Optional. If specified, get VPN credentials for the specified ID.
        """
        if vpnId:
            url = f"/vpnCredentials/{vpnId}"
        else:
            url = "/vpnCredentials"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_vpnCredentials(
        self,
        fqdn: str,
        preSharedKey: str,
        type: str = "UFQDN",  # FIXME: Shadows built-in
        comments: str = None,
    ) -> json:
        """
        Adds VPN credentials that can be associated to locations.

        :param fqdn: (str) Example abc@domain.com
        :param preSharedKey: (str) Pre-shared key. This is a required field for UFQDN and IP auth type
        :param type: (str) VPN authentication type.
        valid options CN, IP, UFQDN,XAUTH
        :param comments: (str) Additional information about this VPN credential.

        :return: (json)
        """
        url = "/vpnCredentials"
        payload = {
            "type": type,
            "fqdn": fqdn,
            "preSharedKey": preSharedKey,
        }
        if comments:
            payload.update(comments=comments)
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_vpnCredentials(
        self,
        vpnId: int,
    ) -> requests.Response:
        """
        Deletes the VPN credentials for the specified ID.

        :param vpnId: (int) The unique identifier for the VPN credential.

        :return: (requests.Response object)
        """
        url = f"/vpnCredentials/{vpnId}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def list_staticIP(
        self,
        IPId: int = None,
    ) -> json:
        """
        Gets all provisioned static IP addresses.

        :param IPId: (str) Optional. If specified, get IP address for the specified id

        :return: (json)
        """
        if IPId:
            url = f"/staticIP/{IPId}"
        else:
            url = "/staticIP"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_staticIP(
        self,
        ipAddress: str,
        geoOverrride: bool = False,
        routableIP: bool = True,
        latitude: float = 0,
        longitude: float = 0,
        comment: str = "",
    ) -> json:
        """
        Adds a static IP address

        :param ipAddress: (str) The static IP address
        :param geoOverrride: (bool) If not set, geographic coordinates and city are automatically determined from the
        IP address. Otherwise, the latitude and longitude coordinates must be provided.
        :param routableIP: (bool) Indicates whether a non-RFC 1918 IP address is publicly routable. This attribute is
        ignored if there is no ZIA Private Service Edge associated to the organization.
        :param latitude: (float) Required only if the geoOverride attribute is set. Latitude with 7 digit precision
        after decimal point, ranges between -90 and 90 degrees.
        :param longitude: (float) Required only if the geoOverride attribute is set. Longitude with 7 digit precision
        after decimal point, ranges between -180 and 180 degrees.
        :param comment: (str) Additional information about this static IP address

        :return: (json)
        """
        url = "/staticIP"
        payload = {
            "ipAddress": ipAddress,
            "latitude": latitude,
            "longitude": longitude,
            "routableIP": routableIP,
            "comment": comment,
        }
        if geoOverrride:
            payload.update(geoOverrride=geoOverrride)
            payload.update(latitude=latitude)
            payload.update(longitude=longitude)

        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_staticIP(
        self,
        Id: int,
    ) -> requests.Response:
        """
        Deletes the static IP address for the specified ID.

        :param Id: (int) The unique identifier for the provisioned static IP address.

        :return: (request.Response object))
        """
        url = f"/staticIP/{Id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    # User Authentication Settings
    def list_exemptedUrls(self) -> json:
        """
        Gets a list of URLs that were exempted from cookie authentication
        """
        url = "/authSettings/exemptedUrls"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_exemptedUrls(
        self,
        urls: list,
    ) -> json:
        """
        Adds URLs to the cookie authentication exempt list to the list

        :param urls: (list) List of urls. Example ['url1','url2']

        :return: (json)
        """
        url = "/authSettings/exemptedUrls?action=ADD_TO_LIST"
        payload = {"urls": urls}
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_exemptedUrls(
        self,
        urls: list,
    ) -> json:
        """
        Removed URLs to the cookie authentication exempt list to the list

        :param urls: (list) List of urls. Example ['url1','url2']

        :return: (json)
        """
        url = "/authSettings/exemptedUrls?action=REMOVE_FROM_LIST"
        payload = {"urls": urls}
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    # Security Policy Settings

    def list_security_whitelisted_urls(self) -> json:
        """
        Gets a list of white-listed URLs

        :return: (json)
        """
        url = "/security"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def update_security_whitelisted_urls(
        self,
        urls: list,
    ) -> json:
        """
        Updates the list of white-listed URLs. This will overwrite a previously-generated white list. If you need to
        completely erase the white list, submit an empty list.

        :param urls: (list) List of urls ['www.zscaler.com', 'www.example.com']

        :return: (json)
        """
        url = "/security"
        payload = {"whitelistUrls": urls}
        response = self.hp_http.put_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_security_blacklisted_urls(self) -> json:
        """
        Gets a list of white-listed URLs

        :return: (json)
        """
        url = "/security/advanced"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def update_security_blacklisted_urls(
        self,
        urls: list,
    ) -> json:
        """
        Updates the list of black-listed URLs. This will overwrite a previously-generated black list. If you need to
        completely erase the black list, submit an empty list.

        :param urls: (list)

        :return: (json)
        """
        url = "/security/advanced"
        payload = {"blacklistUrls": urls}
        response = self.hp_http.put_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_security_blacklistUrls(
        self,
        urls: list,
    ) -> requests.Response:
        """
        Adds a URL from the black list. To add a URL to the black list.

        :param urls: (list) List of urls

        :return: (request.Response object)
        """
        url = "/security/advanced/blacklistUrls?action=ADD_TO_LIST"
        payload = {"blacklistUrls": urls}
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def remove_security_blacklistUrls(
        self,
        urls: list,
    ) -> json:
        """
        Removes a URL from the black list.

        :param urls: (list) List of urls

        :return: (json)
        """
        url = "/security/advanced/blacklistUrls?action=REMOVE_FROM_LIST"
        payload = {"blacklistUrls": urls}
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    # DLP Policies

    def list_dlpDictionaries(
        self,
        dlpDicId: int = None,
    ) -> json:
        """
        Gets a list of all DLP Dictionaries.

        :param dlpDicId: (int) dlp dictionary id ( optional parameter)

        :return: (json)
        """
        if dlpDicId:
            url = f"/dlpDictionaries/{dlpDicId}"
        else:
            url = "/dlpDictionaries"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_dlpDictionaries_lite(self) -> json:
        """
        Gets a list of all DLP Dictionary names and ID's only. T

        :return: (json)
        """
        url = "/dlpDictionaries/lite"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def validateDlpPattern(
        self,
        pattern: str,
    ) -> json:
        """
        Validates the pattern used by a Pattern and Phrases DLP dictionary type, and provides error information if
        the pattern is invalid.

        :param pattern: (str) Regex pattern

        :return: (json)
        """
        payload = pattern
        url = "/dlpDictionaries/validateDlpPattern"
        response = self.hp_http.post_call(
            url,
            cookies=self.cookies,
            payload=payload,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_dlp_dictionaries(
        self,
        dlpDicId: int,
    ) -> requests.Response:
        """
        Deletes the custom DLP category for the specified ID. You cannot delete predefined DLP dictionaries. You
        cannot delete a custom dictionary while it is being used by a DLP Engine or policy. Also, predefined DLP
        dictionaries cannot be deleted.

        :param dlpDicId: (int) dlp dictionary ID

        :return: (requests.Response object)
        """
        url = f"/dlpDictionaries/{dlpDicId}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def add_dlpDictionaries(
        self,
        dlpdicname: str,
        customPhraseMatchType: str = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
        description: str = None,
        phrases: list = None,
        patterns: list = None,
    ) -> json:
        """
        Adds a new custom DLP dictionary that uses either Patterns and/or Phrases.

        :param dlpdicname: (str) Name
        :param customPhraseMatchType: (str) customPhraseMatchType
        :param description: (str) description
        :param phrases: (list) list of phrases. valid example:[
        {"action": "PHRASE_COUNT_TYPE_UNIQUE", "phrase": "string"},
        {"action": "PHRASE_COUNT_TYPE_UNIQUE", "phrase": "string"}
        ]
        :param patterns: (list) list of patterns. valid example:[
        {"action": "PATTERN_COUNT_TYPE_UNIQUE", "phrase": "string"},
        {"action": "PATTERN_COUNT_TYPE_UNIQUE", "phrase": "string"}
        ]

        :return: (json)
        """
        if phrases is not None:
            for i in phrases:
                if i["action"] not in [
                    "PHRASE_COUNT_TYPE_UNIQUE",
                    "PHRASE_COUNT_TYPE_ALL",
                ]:
                    raise ValueError("Invalid action")
        if patterns is not None:
            for k in patterns:
                if k["action"] not in [
                    "PATTERN_COUNT_TYPE_UNIQUE",
                    "PATTERN_COUNT_TYPE_ALL",
                ]:
                    raise ValueError("Invalid action")

        if customPhraseMatchType not in [
            "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY",
            "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
        ]:
            raise ValueError("Invalid customPhraseMatchType")

        url = "/dlpDictionaries"
        payload = {
            "name": dlpdicname,
            "description": description,
            "confidenceThreshold": None,
            "customPhraseMatchType": customPhraseMatchType,
            "dictionaryType": "PATTERNS_AND_PHRASES",
            "phrases": phrases,
            "patterns": patterns,
        }
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_dlpEngines(
        self,
        dlpEngineId: int = None,
    ) -> json:
        """
        Get a list of DLP engines.

        :param dlpEngineId: (int) Optional value. The unique identifier for the DLP engine

        :return: (json)
        """
        if dlpEngineId:
            url = f"/dlpEngines/{dlpEngineId}"
        else:
            url = "/dlpEngines"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_dlpExactDataMatchSchemas(self) -> json:
        """
        Exact Data Match (EDM) templates (or EDM schemas) allow the Zscaler service to identify a record from a
        structured data source that matches predefined criteria. Using the Index Tool, you can create an EDM template
        that allows you to define this criteria (i.e., define the tokens) for your data records by importing a CSV
        file. After the data is defined and submitted within the tool, you can then apply the EDM template to a custom
        DLP dictionary or engine. This endpoint gets the EDM templates for all Index Tools used by the organization

        :return: (json)
        """
        url = "/dlpExactDataMatchSchemas"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_dlpNotificationTemplates(
        self,
        templateId: int = None,
    ) -> json:
        """
        Gets a list of DLP notification templates

        :param templateId: (int) Optional value. The unique identifier for a DLP notification template

        :return: (json)
        """
        if templateId:
            url = f"/dlpNotificationTemplates/{templateId}"
        else:
            url = "/dlpNotificationTemplates"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_dlpNotificationTemplates(
        self,
        name: str,
        subject: str,
        plainTextMessage: str,
        htmlMessage: str,
        attachContent: bool = True,
        tlsEnabled: bool = True,
    ) -> json:
        """
        :param name: (str) The DLP notification template name
        :param subject: (str) The Subject line that is displayed within the DLP notification template
        :param plainTextMessage: (str) The template for the plain text UTF-8 message body that must be displayed in
        the DLP notification email.
        :param htmlMessage: (str) The template for the HTML message body that myst tbe displayed in the DLP
        notification email
        :param attachContent: (bool) if set to True, the content that is violation is attached to the DLP
        notification email
        :param tlsEnabled: (bool) If set to True tls will be used to send email.

        :return: (json)
        """
        url = "/dlpNotificationTemplates"
        payload = {
            "name": name,
            "subject": subject,
            "tlsEnabled": tlsEnabled,
            "attachContent": attachContent,
            "plainTextMessage": plainTextMessage,
            "htmlMessage": htmlMessage,
        }
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_dlpNotificationTemplates(
        self,
        templateId: int,
    ) -> requests.Response:
        """
        Deletes a DLP notification template

        :param templateId: (int) The unique identifies for the DLP notification template
        :return: (requests.Response Object)
        """
        url = f"/dlpNotificationTemplates/{templateId}"
        response = self.hp_http.delete_call(
            url=url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def list_icapServer(
        self,
        icapServerId: int = None,
    ) -> json:
        """
        Gets a list of DLP notification templates

        :param icapServerId: (int) Optional value. The unique identifier for the DLP server using ICAP

        :return: (json)
        """
        if icapServerId:
            url = f"/icapServers/{icapServerId}"
        else:
            url = "/icapServers"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_idmprofile(
        self,
        profileId: int = None,
    ) -> json:
        """
        List all the IDM templates for all Index Tools used by the organization. If profileId, it lists the IDM
        template information for the specified ID.
        :param profileId: (int) Optional value. The unique identifier for the IDM template (or profile)

        :return: (json)
        """
        if profileId:
            url = f"/idmprofile/{profileId}"
        else:
            url = "/idmprofile"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_webDlpRules(
        self,
        ruleId: int = None,
    ) -> json:
        """
        list DLP policy rules, excluding SaaS Security API DLP policy rules. If ruleId, list DLP policy rule
        information for the specified ID

        :param ruleId: (int) Optional value. The unique identifier for theDLP rule

        :return: (json)
        """
        if ruleId:
            url = f"/webDlpRules/{ruleId}"
        else:
            url = "/webDlpRules"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_webDlpRules(
        self,
        ruleId: int,
    ) -> json:
        """
        Deletes a DLP policy rule. This endpoint is not applicable to SaaS Security API DLP policy rules.

        :param ruleId: (int) The unique identifier for the DLP policy rule.

        :return: (json)
        """
        url = f"/webDlpRules/{ruleId}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    # Firewall Policies

    def list_networkServices(
        self,
        serviceId: int = None,
    ) -> json:
        """
        Gets a list of all network service groups. The search parameters find matching values within the "name" or
        "description" attributes.

        :param serviceId: (int)

        :return: (json)
        """
        if serviceId:
            url = f"/networkServices/{serviceId}"
        else:
            url = "/networkServices"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_networkServices(
        self,
        name: str,
        tag: str = None,
        srcTcpPorts: list = None,
        destTcpPorts: list = None,
        srcUdpPorts: list = None,
        destUdpPorts: list = None,
        type: str = "CUSTOM",  # FIXME: Shadows built-in
        description: str = None,
        isNameL10nTag: bool = False,
    ) -> requests.Response:
        """
        Adds a new network service.

        :param name: (str) Name
        :param tag: (str)
        :param srcTcpPorts:(list) Each element is [{"start": int, "end": int}]
        :param destTcpPorts:(list) Each element is [{"start": int, "end": int}]
        :param srcUdpPorts:(list) Each element is [{"start": int, "end": int}]
        :param destUdpPorts:(list) Each element is [{"start": int, "end": int}]
        :param type: (str) STANDARD|PREDEFINE|CUSTOM
        :param description: (str) Description
        :param isNameL10nTag: (bool)

        :return: (requests.Response Object)
        """
        url = "/networkServices"
        payload = {
            "id": 0,
            "name": name,
            "tag": tag,
            "srcTcpPorts": srcTcpPorts,
            "destTcpPorts": destTcpPorts,
            "srcUdpPorts": srcUdpPorts,
            "destUdpPorts": destUdpPorts,
            "type": type,
            "description": description,
            "isNameL10nTag": isNameL10nTag,
        }
        print(payload)
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def delete_networkServices(
        self,
        serviceid: int,
    ) -> requests.Response:
        """
        :param serviceid: (int) The unique identifier for the network service

        :return: (requests.Response Object)
        """
        url = f"/networkServices/{serviceid}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=False,
            headers=self.headers,
        )

        return response

    def list_firewallFilteringRules(
        self,
        ruleId: int = None,
    ) -> json:
        """
        Gets all rules in the Firewall Filtering policy.

        :param ruleId: (int)

        :return: (json)
        """
        if ruleId:
            url = f"/firewallFilteringRules/{ruleId}"
        else:
            url = "/firewallFilteringRules"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_firewallFilteringRules(
        self,
        name: str,
        order: int,
        state: str,
        action: str,
        description: str = None,
        defaultRule: bool = False,
        predefined: bool = False,
        srcIps: list = None,
        destAddresses: list = None,
        destIpGroups: list = None,
        srcIpGroups: list = None,
        destIpCategories: list = None,
        labels=None,
        nwServices: list = None,
        rank: int = 0,
        **kwargs,
    ) -> requests.Response:
        """
        :param name: (str) Name of the Firewall Filtering policy rule ["String"]
        :param order: (int), Rule order number of the Firewall Filtering policy rule
        :param state: (str) Possible values : DISABLED or  ENABLED
        :param action: (str) Possible values: ALLOW, BLOCK_DROP, BLOCK_RESET, BLOCK_ICMP, EVAL_NWAPP
        :param description: (str) Additional information about the rule
        :param defaultRule: (bool) Default is false.If set to true, the default rule is applied
        :param predefined: (bool)
        :param srcIps: (list) List of source IP addresses
        :param destAddresses: (list) List of destination addresses
        :param destIpGroups: (list) List of user-defined destination IP address groups
        :param srcIpGroups: (list) List of user defined source IP address groups
        :param destIpCategories:(list) list of destination IP categories
        :param labels: (?)
        :param nwServices: (list) List of user-defined network services on with the rule is applied
        :param rank: (int), Admin rank of the Firewall Filtering policy rule

        :return: (requests.Response Object)
        """
        url = "/firewallFilteringRules"
        payload = {
            "accessControl": "READ_WRITE",
            "enableFullLogging": False,
            "name": name,
            "order": order,
            "rank": rank,
            "action": action,
            "state": state,
            "predefined": predefined,
            "defaultRule": defaultRule,
            "description": description,
        }
        if srcIps:
            payload.update(srcIps=srcIps)
        if srcIpGroups:
            payload.update(srcIpGroups=srcIpGroups)
        if destAddresses:
            payload.update(destAddresses=destAddresses)
        if destIpGroups:
            payload.update(destIpGroups=destIpGroups)
        if labels:
            payload.update(labels=labels)
        if destIpCategories:
            payload.update(destIpCategories=destIpCategories)
        if nwServices:
            payload.update(nwServices=nwServices)
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def delete_firewallFIlteringRules(
        self,
        ruleId: int,
    ) -> requests.Response:
        """
        Deletes a Firewall Filtering policy rule for the specified ID.

        :param ruleId: (int) The unique identifier for the policy rule

        :return: (requests.Response Object)
        """
        url = f"/firewallFilteringRules/{ruleId}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=False,
            headers=self.headers,
        )

        return response

    def list_ipSourceGroups(
        self,
        ipGroupId: int = None,
    ) -> json:
        """
        Gets a list of all IP source groups. The search parameters find matching values within the "name" or
        "description" attributes.

        :param ipGroupId: (int) Option ip group id

        :return: (json)
        """
        if ipGroupId:
            url = f"/ipSourceGroups/{ipGroupId}"
        else:
            url = "/ipSourceGroups"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_ipSourceGroups_lite(self) -> json:
        """
        Gets a name and ID dictionary of all IP source groups

        :return: (json)
        """
        url = "/ipSourceGroups/lite"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_ipDestinationGroups(
        self,
        ipGroupId: int = None,
    ) -> json:
        """
        Gets a list of all IP source groups. The search parameters find matching values within the "name" or
        "description" attributes.

        :param ipGroupId: (int) Option ip group id

        :return: (json)
        """
        if ipGroupId:
            url = f"/ipDestinationGroups/{ipGroupId}"
        else:
            url = "/ipDestinationGroups/"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_ipDestinationGroups_lite(self) -> json:
        """
        Gets a name and ID dictionary of all IP destination groups

        :return: (json)
        """
        url = "/ipDestinationGroups/lite"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_ipSourceGroups(
        self,
        name: str,
        ipAddresses: list,
        description: str = None,
    ) -> json:
        """
        :param name: (str) Name
        :param ipAddresses: (list) List of IP addresses
        :param description: (str) description

        :return: (json)
        """
        url = "/ipSourceGroups"
        payload = {
            "name": name,
            "ipAddresses": ipAddresses,
            "description": description,
        }
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_ipSourceGroups(
        self,
        ipGroupId: int,
    ) -> requests.Response:
        """
        Deletes the IP source group for the specified ID

        :param ipGroupId: (int) The unique identifies for the IP source group

        :return: (requests.Response Object)
        """
        url = f"/ipSourceGroups/{ipGroupId}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            payload={},
            headers=self.headers,
        )

        return response

    def delete_ipDestinationGroups(
        self,
        ipGroupId: int,
    ) -> requests.Response:
        """
        Deletes the IP destination group for the specified ID

        :param ipGroupId: (int) The unique identifies for the IP source group

        :return: (requests.Response Object)
        """
        url = f"/ipDestinationGroups/{ipGroupId}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            payload={},
            headers=self.headers,
        )

        return response

    def add_ipDestinationGroups(
        self,
        name: str,
        type: str,
        addresses: list,
        ipCategories: list = None,
        countries: list = None,
        description: str = None,
    ) -> json:
        """
        :param name: (str) Name
        :param type: (str) Destination IP group type. Either DSTN_IP or  DSTN_FQDN or DSTN_DOMAIN
        :param addresses: (list) List of Destination IP addresses within the group.
        :param ipCategories: (list) List of Destination IP address URL categories. You can identify destination based
        on the URL category of the domain. Default value ANY
        :param countries: (list) List of destination IP address countries. You can identify destinations based on
        the location of a server.Default value ANY
        :param description: (str) description
        """
        if type not in [
            "DSTN_IP",
            "DSTN_FQDN",
            "DSTN_DOMAIN",
        ]:
            raise ValueError("Invalid destination type ")
        if countries:
            for i in countries:
                if i not in valid_countries:
                    raise ValueError("Invalid country ")
        else:
            countries = []

        if ipCategories:
            for j in ipCategories:
                if j not in valid_category_ids:
                    raise ValueError("Invalid country ")
        else:
            ipCategories = []

        url = "/ipDestinationGroups"
        payload = {
            "name": name,
            "type": type,
            "addresses": addresses,
            "ipCategories": ipCategories,
            "countries": countries,
            "description": description,
        }
        print(payload)
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    # Device Groups

    def list_devices_groups(
        self,
        query: str = None,
    ) -> json:
        """
        Gets a list of device groups

        :param query: (str)

        :return: (json)
        """
        if query:
            url = f"/deviceGroups?{query}"
        else:
            url = "/deviceGroups"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_devices(
        self,
        query: str = None,
    ) -> json:
        """
        Gets a list of devices. Any given search parameters will be applied during device search. Search parameters
        are based on device name, model, owner, OS type, and OS version. The devices listed can also be restricted
        to return information only for ones belonging to specific users.

        :param query: (str)

        :return: (json)
        """
        if query:
            url = f"/deviceGroups/devices?{query}"
        else:
            url = "/deviceGroups/devices"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    # Rule Labels
    def list_rule_labels(
        self,
        ruleLabelId: int = None,
    ) -> json:
        """
        Gets rule label information for the specified ID

        :param ruleLabelId: (int)

        :return: (json)
        """
        if ruleLabelId:
            url = f"/ruleLabels/{ruleLabelId}"
        else:
            url = "/ruleLabels?pageSize=1000"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_rule_label(self, payload: dict) -> json:
        """
        Adds new rule labels with the given name
        :param name: (str) name  # FIXME: Not in passed attributes.
        :param description: (str) description  # FIXME: Not in passed attributes.
        :param payload: (dict)
        """
        url = "/ruleLabels"
        response = self.hp_http.post_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
            payload=payload,
        )

        return response.json()

    def update_call(
        self,
        url: str,
        payload: json,
    ) -> json:
        """
        Generic PUT call. This call will overwrite all the configuration with the new payload

        :param url: (str) url of Zscaler API call
        :param payload: (json) Payload

        :return: (json)
        """
        response = self.hp_http.put_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_call(
        self,
        url: str,
        payload: json,
    ) -> json:
        """
        Generic POST call. This call will add all the configuration with the new payload

        :param url: (str) url of Zscaler API call
        :param payload: (json) Payload

        :return: (json)
        """
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()
