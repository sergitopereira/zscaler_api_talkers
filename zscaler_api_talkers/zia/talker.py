import json
import pdb  # noqa
import time

import requests

from zscaler_api_talkers.helpers import HttpCalls, setup_logger
from zscaler_api_talkers.zia.models import (
    super_categories,
    valid_category_ids,
    valid_countries,
)

from zscaler_api_talkers.zia.helpers import _obfuscate_api_key

logger = setup_logger(name=__name__)


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
        elif username and any([password, api_key]):
            self.authenticate(
                username=username,
                api_key=api_key,
                password=password,
            )

    def authenticate(
        self,
        api_key: str,
        username: str,
        password: str = None,
    ):
        """
        Method to authenticate.

        :param api_key: (str) API key
        :param username: (str) A string that contains the email ID of the API admin
        :param password: (str) A string that contains the password for the API admin
        """
        timestamp, key = _obfuscate_api_key(api_key)
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
    ) -> list:
        """
        Internal method that queries all pages

        :param url: (str) URL

        :return: (list) List of results
        """
        page = 1
        result = []
        while True:
            response = self.hp_http.get_call(
                url=f"{url}&page={page}",
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

    def list_auditlog_entry_report(self) -> json:
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

    def download_auditlog_entry_report(self) -> requests.Response:
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

    def add_auditlog_entry_report(
        self,
        start_time: int,
        end_time: int,
        action_types: list = None,
        category: str = None,
        subcategories: list = None,
        action_interface: str = None,
    ) -> requests.Response:
        """
         Creates an audit log report for the specified time period and saves it as a CSV file. The report includes
         audit information for every call made to the cloud service API during the specified time period. Creating a
         new audit log report will overwrite a previously-generated report.

        :param start_time: (int) The timestamp, in epoch, of the admin's last login
        :param end_time: (int) The timestamp, in epoch, of the admin's last logout.
        :param action_types: (list) The action performed by the admin in the ZIA Admin Portal or API
        :param category: (str) The location in the Zscaler Admin Portal (i.e., Admin UI) where the actionType was
        performed.
        :param subcategories: (list) The area within a category where the actionType was performed.
        :param action_interface: (str) The interface (i.e., Admin UI or API) where the actionType was performed.

        :return: (requests.Response Object) 204 Successful Operation
        """
        url = "/auditlogEntryReport"
        payload = {
            "startTime": start_time,
            "endTime": end_time,
        }
        if category:
            payload.update(category=category)
        if subcategories:
            payload.update(subcategories=subcategories)
        if action_interface:
            payload.update(actionInterface=action_interface)
        if action_types:
            payload.update(actionTypes=action_types)

        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    # Admin & Role Management
    def list_admin_users(
        self,
        user_id: int = None,
        query: str = None,
    ) -> json:
        """
        Gets a list of admin users. By default, auditor user information is not included.

        :param user_id: (int) user ID
        :param query: (str) HTTP query  # TODO: What is this?  Looks like it is just parameters

        :return: (json) JSON of results
        """
        if user_id:
            url = f"/adminUsers/{user_id}"
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

    def add_admin_users(self, loginName: str, userName: str, email: str, password: str, role: dict, comments: str = '',
                       adminScopeType: str ='ORGANIZATION',
                       adminScopeScopeEntities: list =[],
                       adminScopescopeGroupMemberEntities: list =[],
                       isNonEditable: bool = False,
                       disabled: bool = False,
                       isAuditor: bool = False,
                       isPasswordLoginAllowed: object = False,
                       isSecurityReportCommEnabled: object = False,
                       isServiceUpdateCommEnabled: object = False,
                       isProductUpdateCommEnabled: object = False,
                       isPasswordExpired: object = False,
                       isExecMobileAppEnabled: object = False,
                       execMobileAppTokens: object = []) -> json:
        """
        Adds a new Admininstrator.
               :param loginName: string. Admin or auditor's login name. loginName is in email format
               and uses the domain name associated to the Zscaler account.
               :param userName: string. UserName.
               :param email: string. Email Address.
               :param password: string. Password for administrator. If admin single sign-on (SSO) is disabled, then this field is mandatory
               :param role : Role of the Admin
               :param comments: string. Comments.
               :param adminScopeType: string. Scope of the admin.
               :param adminScopeScopeEntities: list: Department or Location when adminScopeType is set to Deportment or Location.
               :param adminScopescopeGroupMemberEntities: list. Location Groups when adminScopeType is set to Location Group.
               :param isNonEditable: boolean. Indicates whether or not the admin can be edited or deleted. default: False.
               :param disabled: boolean. If admin accounts is disabled. default: False.
               :param isAuditor:boolean. Indicates if user is auditor. default: False.
               :param isPasswordLoginAllowed: boolean. If password login is allowed. default: False.
               :param isSecurityReportCommEnabled: boolean. Communication for Security Report is enabled. default: False.
               :param isServiceUpdateCommEnabled: boolean. Communication setting for Service Update. default: False.
               :param isProductUpdateCommEnabled: boolean. Communication setting for Product Update. default: False.
               :param isPasswordExpired: boolean. Expire password to force user to change password on logon. default: False.
               :param isExecMobileAppEnabled: boolean. Indicates whether or not Executive Insights App access is enabled for the admin. default: False.
               :return:json()
               """
        url = "/adminUsers"
        payload = {
            "loginName": loginName,
            "userName": userName,
            "email": email,
            "password": password,
            "role": role,
            "comments": comments,
            "adminScopeType": adminScopeType,
            "adminScopeScopeEntities": adminScopeScopeEntities,
            "adminScopescopeGroupMemberEntities": adminScopescopeGroupMemberEntities,
            "isNonEditable": isNonEditable,
            "disabled": disabled,
            "isAuditor": isAuditor,
            "isPasswordLoginAllowed": isPasswordLoginAllowed,
            "isSecurityReportCommEnabled": isSecurityReportCommEnabled,
            "isServiceUpdateCommEnabled": isServiceUpdateCommEnabled,
            "isProductUpdateCommEnabled": isProductUpdateCommEnabled,
            "isPasswordExpired": isPasswordExpired,
            "isExecMobileAppEnabled": isExecMobileAppEnabled,
            "execMobileAppTokens": execMobileAppTokens
        }
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )
        return response.json()
    def list_admin_roles(
        self,
        query: str = None,
    ) -> json:
        """
        Gets a name and ID dictionary of al admin roles

        :param query: (str) HTTP query  # TODO: What is this?  Looks like it is just parameters

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
        super_category: str,
        type_list: str = None,
        urls: list = None,
        db_categorized_urls: list = None,
        keywords_retaining_parent_category: list = None,
        keywords: list = None,
        custom_category: bool = False,
        ip_ranges: list = None,
        ip_ranges_retaining_parent_category: list = None,
        description: str = None,
    ) -> json:
        """
         Adds a new custom URL category.

        :param name: (str) Name of the custom category. Possible values URL_CATEGORY, TLD_CATEGORY, ALL
        :param super_category: (str) super category
        :param type_list: (list)
        :param urls: (list) List of urls
        :param db_categorized_urls: (list) URL retaining parent category
        :param keywords_retaining_parent_category: (list) Retained custom keywords from the parent URL category that is
        associated to a URL category.
        :param keywords: (list) Custom keywords associated to a URL category.
        :param custom_category: (bool) Default False. Set to True for custom category
        :param ip_ranges: (list) Custom IP address ranges associated to a URL category
        :param ip_ranges_retaining_parent_category: (list) The retaining parent custom IP address ranges associated to a
        URL category.
        :param description: (str) Description or notes

        :return:  json
        """
        if not type_list:
            type_list = "URL_CATEGORY"

        if keywords_retaining_parent_category is None:
            keywords_retaining_parent_category = []

        if super_category not in super_categories:
            logger.error(f"Invalid Super Category: {super_categories}")
            raise ValueError("Invalid super category")

        if keywords is None:
            keywords = []

        if ip_ranges is None:
            ip_ranges = []

        url = "/urlCategories"
        payload = {
            "configuredName": name,
            "customCategory": custom_category,
            "superCategory": super_category,
            "keywordsRetainingParentCategory": keywords_retaining_parent_category,
            "keywords": keywords,
            "urls": urls,
            "dbCategorizedUrls": db_categorized_urls,
            "ipRanges": ip_ranges,
            "ipRangesRetainingParentCategory": ip_ranges_retaining_parent_category,
            "type": type_list,
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

    def add_raw_url_categories(
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
        category_id: str,
        action: str = None,
        configured_name: str = None,
        urls: list = None,
        db_categorized_urls: list = None,
        keywords: list = None,
        keywords_retaining_parent_category: list = None,
    ) -> json:
        """
        Updates the URL category for the specified ID. If keywords are included within the request, then they will
        replace existing ones for the specified URL category . If the keywords attribute is not included the request,
        the existing keywords are retained. You can perform a full update for the specified URL category. However,
        if attributes are omitted within the update request then clear the values for those attributes.

        You can also perform an incremental update, to add or remove URLs for the specified URL category using the
        action parameter.

        :param category_id: (str) URL id
        :param action: (str) Optional parameter. ADD_TO_LIST or REMOVE_FROM_LIST
        :param configured_name: (str) Name of the custom category
        :param urls: (list) List of urls
        :param db_categorized_urls: (list) URL retaining parent category
        :param keywords: (list)
        :param keywords_retaining_parent_category: (list) List of key works

        :return:  (json)
        """
        """if categoryId not in valid_category_ids:
            print(f'Error -> Invalid category id')
            raise ValueError("Invalid category id")"""
        url = f"/urlCategories/{category_id}"
        parameters = {}

        if action and action not in ["ADD_TO_LIST", "REMOVE_FROM_LIST"]:
            logger.error(f"Invalid action: {action}")
            raise ValueError("Invalid action")
        else:
            parameters.update({"action": action})

        payload = {
            "configuredName": configured_name,
        }
        if keywords_retaining_parent_category:
            payload.update(
                keywordsRetainingParentCategory=keywords_retaining_parent_category
            )
        if keywords:
            payload.update(keywords=keywords)
        if configured_name:
            payload.update(configuredName=configured_name)
        if urls:
            payload.update(urls=urls)
        if db_categorized_urls:
            payload.update(dbCategorizedUrls=db_categorized_urls)

        response = self.hp_http.put_call(
            url,
            params=parameters,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_url_categories(
        self,
        category_id: str,
    ) -> requests.Response:
        """
        Deletes the custom URL category for the specified ID. You cannot delete a custom category while it is being
        used by a URL policy or NSS feed. Also, predefined categories cannot be deleted.

        :param category_id: (inst) Category ID

        :return: (requests.Response)
        """
        url = f"/urlCategories/{category_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def delete_url_filtering_rules(
        self,
        rule_id: int,
    ) -> requests.Response:
        """
        Deletes the custom URL category for the specified ID. You cannot delete a custom category while it is being
        used by a URL policy or NSS feed. Also, predefined categories cannot be deleted.

        :param rule_id: (int) Rule Id

        :return: (request.Response)
        """
        url = f"/urlFilteringRules/{rule_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def list_url_categories_url_quota(self) -> json:
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
            logger.error(f"Invalid Category ID: {category_id}")
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
        url_categories: list = None,
        request_methods: list = None,
        description=None,
        groups: list = None,
        locations: list = None,
        departments: list = None,
        users: list = None,
        rank: int = 7,
        location_groups=None,
        enforce_time_validity: bool = False,
        validity_end_time=None,
        validity_start_time=None,
        validity_time_zone_id=None,
        cbi_profile_id: int = 0,
        block_override: bool = False,
        **kwargs,
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
        :param url_categories: (list) List of URL categories for which rule must be applied
        :param request_methods: (list) Request method for which the rule must be applied. If not set, rule will be
        applied to all methods
        :param description: (str) Additional information about the URL Filtering rule
        :param groups: (list) Name-ID pairs of groups for which rule must be applied
        :param locations: (list) Each element is a dictionary: Name-ID pairs of locations for which rule must be applied
        :param departments: (list) Name-ID pairs of departments for which rule will be applied
        :param users: (list) Name-ID pairs of users for which rule must be applied
        :param rank: (int) Admin rank of the admin who creates this rule
        :param location_groups:
        :param enforce_time_validity: (bool)
        :param validity_end_time:
        :param validity_start_time:
        :param validity_time_zone_id:
        :param cbi_profile_id: (int)
        :param block_override: (bool) When set to true, a 'BLOCK' action triggered by the rule could be overridden.
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
            "blockOverride": block_override,
            "cbiProfileId": cbi_profile_id,
            "description": description,
            "enforceTimeValidity": enforce_time_validity,
            "name": name,
            "order": order,
            "protocols": protocols,
            "urlCategories": url_categories,
            "state": state,
            "rank": rank,
            "action": action,
        }
        payload.update(kwargs)
        if locations:
            payload.update(locations=locations)
        if location_groups:
            payload.update(locationGroups=location_groups)
        if groups:
            payload.update(groups=groups)
        if departments:
            payload.update(departments=departments)
        if users:
            payload.update(users=users)
        if request_methods:
            payload.update(requestMethods=request_methods)
        if enforce_time_validity:
            payload.update(validityStartTime=validity_start_time)
            payload.update(validityEndTime=validity_end_time)
            payload.update(validityTimeZoneId=validity_time_zone_id)

        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def update_url_filtering_rules(
        self,
        rule_id: int,
        **kwargs,
    ) -> json:
        url = f"/urlFilteringRules/{rule_id}"
        payload = kwargs
        response = self.hp_http.put_call(
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
        department_id: int = None,
    ) -> json or list:
        """
        Gets a list of departments. The search parameters find matching values within the "name" or "comments"
        attributes. if ID, gets the department for the specified ID

        :param department_id: (int) department ID

        :return: (json or list)
        """

        if not department_id:
            url = "/departments?pageSize=10000"
            return self._obtain_all(url)
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
    ) -> json or list:
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
    ) -> json or list:
        """
        Gets a list of all users and allows user filtering by name, department, or group. The name search parameter
        performs a partial match. The dept and group parameters perform a 'starts with' match. if ID,
        gets user information for the specified ID

        :param user_id: (int) user ID
        :param query: (str)

        :return: (json or list)
        """
        url = "/users?pageSize=1000"
        if user_id:
            url = f"/users/{user_id}"
            return self.hp_http.get_call(
                url,
                cookies=self.cookies,
                error_handling=True,
                headers=self.headers,
            ).json()
        elif query:
            url = f"/users?{query}&pageSize=1000"
            return self.hp_http.get_call(
                url,
                cookies=self.cookies,
                error_handling=True,
                headers=self.headers,
            ).json()

        return self._obtain_all(url)

    def add_users(
        self,
        name: str,
        email: str,
        groups: list,
        department: dict,
        comments: str,
        password: str,
        admin_user: bool = False,
    ) -> json:
        """
        Adds a new user. A user can belong to multiple groups, but can only belong to one department.

        :param name: (str) user name
        :param email: (str) user email address
        :param groups: (list) List each member is a dictionary, key id, value name [{"id":1234, "name":"guest-wifi"}]
        :param department: (dict) key is the id and value is the name {"id":1234, "name":"guests"}
        :param comments: (str) Comments
        :param password: (str) Password,
        :param admin_user: (bool) True if user is admin user. default False

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
            "adminUser": admin_user,
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
        location_id: int = None,
    ) -> json:
        """
        Gets locations only, not sub-locations. When a location matches the given search parameter criteria only its
        parent location is included in the result set, not its sub-locations.

        :param location_id: (int) Location id

        :return: (json)
        """
        url = "/locations"
        if location_id:
            url = f"/locations/{location_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_sublocations(
        self,
        location_id: int,
    ) -> json:
        """
        Gets the sub-location information for the location with the specified ID

        :param location_id: (int) Location id

        :return: (json)
        """
        url = "/locations"
        if location_id:
            url = f"/locations/{location_id}/sublocations"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_locations_groups(self) -> json:
        """
        Gets information on location groups

        :return: (json)
        """
        url = "/locations/groups"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_bulk_locations(
        self,
        location_ids: list,
    ) -> json:
        """
        Bulk delete locations up to a maximum of 100 users per request. The response returns the location IDs that
        were successfully deleted.

        :param location_ids: (list) List of location IDs

        :return: (json)
        """
        url = "/locations/bulkDelete"
        if len(location_ids) < 100:
            payload = {"ids": location_ids}
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
        location_id: int,
    ) -> requests.Response:
        """
        Deletes the location or sub-location for the specified ID

        :param location_id: (int) location ID

        :return: (request.Response object)
        """
        url = f"/locations/{location_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    #   Traffic Forwarding

    def list_gre_tunnels(
        self,
        gre_tunnel_id: int = None,
    ) -> json:
        """
        Gets the GRE tunnel information for the specified ID

        :param gre_tunnel_id: (int) Optional. The unique identifier for the GRE tunnel

        :return: (json)
        """
        url = "/greTunnels"
        if gre_tunnel_id:
            url = f"/greTunnels/{gre_tunnel_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_gre_tunnels(
        self,
        source_ip: str,
        primary_dest_vip: dict,
        secondary_dest_vip: dict,
        internal_ip_range: str,
        within_country: bool,
        comment: str,
        ip_unnumbered: bool,
    ) -> json:
        """
        Adds a GRE tunnel configuration.

        :param source_ip: (str) The source IP address of the GRE tunnel. This is typically a static IP address in the
        organization or SD-WAN. This IP address must be provisioned within the Zscaler service using the /staticIP
        endpoint.
        :param primary_dest_vip: (dict) {id:value} where value is integer: Unique identifier of the GRE primary VIP
        :param secondary_dest_vip: (dict) {id:value} where value is integer: Unique identifier of the GRE secondary VIP
        :param internal_ip_range: (str) The start of the internal IP address in /29 CIDR range
        :param within_country: (bool) Restrict the data center virtual IP addresses (VIPs) only to those within the
        same country as the source IP address
        :param comment: (str) Additional information about this GRE tunnel
        :param ip_unnumbered: (bool?) This is required to support the automated SD-WAN provisioning of GRE tunnels,
        when set to True gre_tun_ip and gre_tun_id are set to null

        :return: (json)
        """
        url = "/greTunnels"
        payload = {
            "sourceIp": source_ip,
            "primaryDestVip": primary_dest_vip,
            "secondaryDestVip": secondary_dest_vip,
            "internalIpRange": internal_ip_range,
            "withinCountry": within_country,
            "comment": comment,
            "ipUnnumbered": ip_unnumbered,
        }
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_gre_validate_and_get_available_internal_ip_ranges(self) -> json:
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

    def list_vpn_credentials(
        self,
        vpn_id: int = None,
    ) -> json:
        """
        Gets VPN credentials that can be associated to locations.

        :param vpn_id: (int) Optional. If specified, get VPN credentials for the specified ID.
        """
        url = "/vpnCredentials"
        if vpn_id:
            url = f"/vpnCredentials/{vpn_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_vpn_credentials(
        self,
        fqdn: str,
        pre_shared_key: str,
        auth_type: str = "UFQDN",
        comments: str = None,
    ) -> json:
        """
        Adds VPN credentials that can be associated to locations.

        :param fqdn: (str) Example abc@domain.com
        :param pre_shared_key: (str) Pre-shared key. This is a required field for UFQDN and IP auth type
        :param auth_type: (str) VPN authentication type.
        valid options CN, IP, UFQDN,XAUTH
        :param comments: (str) Additional information about this VPN credential.

        :return: (json)
        """
        url = "/vpnCredentials"
        payload = {
            "type": auth_type,
            "fqdn": fqdn,
            "preSharedKey": pre_shared_key,
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

    def delete_vpn_credentials(
        self,
        vpn_id: int,
    ) -> requests.Response:  # TODO: Move to returning json
        """
        Deletes the VPN credentials for the specified ID.

        :param vpn_id: (int) The unique identifier for the VPN credential.

        :return: (requests.Response object)
        """
        url = f"/vpnCredentials/{vpn_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def list_static_ip(
        self,
        ip_id: int = None,
    ) -> json:
        """
        Gets all provisioned static IP addresses.

        :param ip_id: (str) Optional. If specified, get IP address for the specified id

        :return: (json)
        """
        url = "/staticIP"
        if ip_id:
            url = f"/staticIP/{ip_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_static_ip(
        self,
        ip_address: str,
        geo_override: bool = False,
        routable_ip: bool = True,
        latitude: float = 0,
        longitude: float = 0,
        comment: str = "",
    ) -> json:
        """
        Adds a static IP address

        :param ip_address: (str) The static IP address
        :param geo_override: (bool) If not set, geographic coordinates and city are automatically determined from the
        IP address. Otherwise, the latitude and longitude coordinates must be provided.
        :param routable_ip: (bool) Indicates whether a non-RFC 1918 IP address is publicly routable. This attribute is
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
            "ipAddress": ip_address,
            "latitude": latitude,
            "longitude": longitude,
            "routableIP": routable_ip,
            "comment": comment,
        }
        if geo_override:
            payload.update(geoOverrride=geo_override)
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

    def delete_static_ip(
        self,
        ip_address_id: int,
    ) -> requests.Response:
        """
        Deletes the static IP address for the specified ID.

        :param ip_address_id: (int) The unique identifier for the provisioned static IP address.

        :return: (request.Response object))
        """
        url = f"/staticIP/{ip_address_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    # User Authentication Settings
    def list_exempted_urls(self) -> json:
        """
        Gets a list of URLs that were exempted from cookie authentication

        :return: (json)
        """
        url = "/authSettings/exemptedUrls"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_exempted_urls(
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

    def delete_exempted_urls(
        self,
        urls: list,
    ) -> json:
        """
        Removed URLs to the cookie authentication exempt list to the list

        :param urls: (list) List of urls. Example ['url1','url2']

        :return: (json)
        """
        url = "/authSettings/exemptedUrls"
        parameters = {"action": "REMOVE_FROM_LIST"}
        payload = {"urls": urls}
        response = self.hp_http.post_call(
            url,
            params=parameters,
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

    def add_security_blacklist_urls(
        self,
        urls: list,
    ) -> requests.Response:  # TODO: Move to return json
        """
        Adds a URL from the black list. To add a URL to the black list.

        :param urls: (list) List of urls

        :return: (request.Response object)
        """
        url = "/security/advanced/blacklistUrls"
        parameters = {"action": "ADD_TO_LIST"}
        payload = {"blacklistUrls": urls}
        response = self.hp_http.post_call(
            url,
            payload=payload,
            params=parameters,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def remove_security_blacklist_urls(
        self,
        urls: list,
    ) -> json:
        """
        Removes a URL from the black list.

        :param urls: (list) List of urls

        :return: (json)
        """
        url = "/security/advanced/blacklistUrls"
        parameters = {"action": "REMOVE_FROM_LIST"}
        payload = {"blacklistUrls": urls}
        response = self.hp_http.post_call(
            url,
            payload=payload,
            params=parameters,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    # DLP Policies

    def list_dlp_dictionaries(
        self,
        dlp_dic_id: int = None,
    ) -> json:
        """
        Gets a list of all DLP Dictionaries.

        :param dlp_dic_id: (int) dlp dictionary id ( optional parameter)

        :return: (json)
        """
        url = "/dlpDictionaries"
        if dlp_dic_id:
            url = f"/dlpDictionaries/{dlp_dic_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_dlp_dictionaries_lite(self) -> json:
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

    def validate_dlp_pattern(
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
            payload=payload,  # TODO: payload is typically dict but here it is str?
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_dlp_dictionaries(
        self,
        dlp_dic_id: int,
    ) -> requests.Response:
        """
        Deletes the custom DLP category for the specified ID. You cannot delete predefined DLP dictionaries. You
        cannot delete a custom dictionary while it is being used by a DLP Engine or policy. Also, predefined DLP
        dictionaries cannot be deleted.

        :param dlp_dic_id: (int) dlp dictionary ID

        :return: (requests.Response object)
        """
        url = f"/dlpDictionaries/{dlp_dic_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def add_dlp_dictionaries(
        self,
        dlp_dic_name: str,
        custom_phrase_match_type: str = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
        description: str = None,
        phrases: list = None,
        patterns: list = None,
    ) -> json:
        """
        Adds a new custom DLP dictionary that uses either Patterns and/or Phrases.

        :param dlp_dic_name: (str) Name
        :param custom_phrase_match_type: (str) customPhraseMatchType
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

        if custom_phrase_match_type not in [
            "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY",
            "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
        ]:
            raise ValueError("Invalid customPhraseMatchType")

        url = "/dlpDictionaries"
        payload = {
            "name": dlp_dic_name,
            "description": description,
            "confidenceThreshold": None,
            "customPhraseMatchType": custom_phrase_match_type,
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

    def list_dlp_engines(
        self,
        dlp_engine_id: int = None,
    ) -> json:
        """
        Get a list of DLP engines.

        :param dlp_engine_id: (int) Optional value. The unique identifier for the DLP engine

        :return: (json)
        """
        url = "/dlpEngines"
        if dlp_engine_id:
            url = f"/dlpEngines/{dlp_engine_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_dlp_exact_data_match_schemas(self) -> json:
        """
        Exact Data Match (EDM) templates (or EDM schemas) allow the Zscaler service to identify a record from a
        structured data source that matches predefined criteria. Using the Index Tool, you can create an EDM template
        that allows you to define the criteria (i.e., define the tokens) for your data records by importing a CSV
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

    def list_dlp_notification_templates(
        self,
        template_id: int = None,
    ) -> json:
        """
        Gets a list of DLP notification templates

        :param template_id: (int) Optional value. The unique identifier for a DLP notification template

        :return: (json)
        """
        url = "/dlpNotificationTemplates"
        if template_id:
            url = f"/dlpNotificationTemplates/{template_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_dlp_notification_templates(
        self,
        name: str,
        subject: str,
        plain_text_message: str,
        html_message: str,
        attach_content: bool = True,
        tls_enabled: bool = True,
    ) -> json:
        """
        :param name: (str) The DLP notification template name
        :param subject: (str) The Subject line that is displayed within the DLP notification template
        :param plain_text_message: (str) The template for the plain text UTF-8 message body that must be displayed in
        the DLP notification email.
        :param html_message: (str) The template for the HTML message body that myst tbe displayed in the DLP
        notification email
        :param attach_content: (bool) if set to True, the content that is violation is attached to the DLP
        notification email
        :param tls_enabled: (bool) If set to True tls will be used to send email.

        :return: (json)
        """
        url = "/dlpNotificationTemplates"
        payload = {
            "name": name,
            "subject": subject,
            "tlsEnabled": tls_enabled,
            "attachContent": attach_content,
            "plainTextMessage": plain_text_message,
            "htmlMessage": html_message,
        }
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_dlp_notification_templates(
        self,
        template_id: int,
    ) -> requests.Response:  # TODO: return json instead
        """
        Deletes a DLP notification template

        :param template_id: (int) The unique identifies for the DLP notification template
        :return: (requests.Response Object)
        """
        url = f"/dlpNotificationTemplates/{template_id}"
        response = self.hp_http.delete_call(
            url=url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def list_icap_server(
        self,
        icap_server_id: int = None,
    ) -> json:
        """
        Gets a list of DLP notification templates

        :param icap_server_id: (int) Optional value. The unique identifier for the DLP server using ICAP

        :return: (json)
        """
        url = "/icapServers"
        if icap_server_id:
            url = f"/icapServers/{icap_server_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_idm_profile(
        self,
        profile_id: int = None,
    ) -> json:
        """
        List all the IDM templates for all Index Tools used by the organization. If profileId, it lists the IDM
        template information for the specified ID.

        :param profile_id: (int) Optional value. The unique identifier for the IDM template (or profile)

        :return: (json)
        """
        if profile_id:
            url = f"/idmprofile/{profile_id}"
        else:
            url = "/idmprofile"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_web_dlp_rules(
        self,
        rule_id: int = None,
    ) -> json:
        """
        list DLP policy rules, excluding SaaS Security API DLP policy rules. If ruleId, list DLP policy rule
        information for the specified ID

        :param rule_id: (int) Optional value. The unique identifier for theDLP rule

        :return: (json)
        """
        url = "/webDlpRules"
        if rule_id:
            url = f"/webDlpRules/{rule_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def delete_web_dlp_rules(
        self,
        rule_id: int,
    ) -> json:
        """
        Deletes a DLP policy rule. This endpoint is not applicable to SaaS Security API DLP policy rules.

        :param rule_id: (int) The unique identifier for the DLP policy rule.

        :return: (json)
        """
        url = f"/webDlpRules/{rule_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    # Firewall Policies

    def list_network_services_lite(
        self,
    ) -> json:
        """
        Gets a summary list of all network service groups.

        :return: (json)
        """
        response = self.hp_http.get_call(
            "/networkServices/lite",
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_network_services(
        self,
        service_id: int = None,
    ) -> json:
        """
        Gets a list of all network service groups. The search parameters find matching values within the "name" or
        "description" attributes.

        :param service_id: (int)

        :return: (json)
        """
        url = "/networkServices"
        if service_id:
            url = f"/networkServices/{service_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_network_services(
        self,
        name: str,
        tag: str = None,
        src_tcp_ports: list = None,
        dest_tcp_ports: list = None,
        src_udp_ports: list = None,
        dest_udp_ports: list = None,
        service_type: str = "CUSTOM",
        description: str = None,
        is_name_l10n_tag: bool = False,
    ) -> requests.Response:  # TODO: return json
        """
        Adds a new network service.

        :param name: (str) Name
        :param tag: (str)
        :param src_tcp_ports:(list) Each element is [{"start": int, "end": int}]
        :param dest_tcp_ports:(list) Each element is [{"start": int, "end": int}]
        :param src_udp_ports:(list) Each element is [{"start": int, "end": int}]
        :param dest_udp_ports:(list) Each element is [{"start": int, "end": int}]
        :param service_type: (str) STANDARD|PREDEFINE|CUSTOM
        :param description: (str) Description
        :param is_name_l10n_tag: (bool)

        :return: (requests.Response Object)
        """
        url = "/networkServices"
        payload = {
            "id": 0,
            "name": name,
            "tag": tag,
            "srcTcpPorts": src_tcp_ports,
            "destTcpPorts": dest_tcp_ports,
            "srcUdpPorts": src_udp_ports,
            "destUdpPorts": dest_udp_ports,
            "type": service_type,
            "description": description,
            "isNameL10nTag": is_name_l10n_tag,
        }
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def delete_network_services(
        self,
        service_id: int,
    ) -> requests.Response:
        """
        :param service_id: (int) The unique identifier for the network service

        :return: (requests.Response Object)
        """
        url = f"/networkServices/{service_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=False,
            headers=self.headers,
        )

        return response

    def list_firewall_filtering_rules(
        self,
        rule_id: int = None,
    ) -> json:
        """
        Gets all rules in the Firewall Filtering policy.

        :param rule_id: (int)

        :return: (json)
        """
        url = "/firewallFilteringRules"
        if rule_id:
            url = f"/firewallFilteringRules/{rule_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_firewall_filtering_rules(
        self,
        name: str,
        order: int,
        state: str,
        action: str,
        description: str = None,
        default_rule: bool = False,
        predefined: bool = False,
        src_ips: list = None,
        dest_addresses: list = None,
        dest_ip_groups: list = None,
        src_ip_groups: list = None,
        dest_ip_categories: list = None,
        labels=None,
        nw_services: list = None,
        rank: int = 0,
    ) -> requests.Response:
        """
        :param name: (str) Name of the Firewall Filtering policy rule ["String"]
        :param order: (int), Rule order number of the Firewall Filtering policy rule
        :param state: (str) Possible values : DISABLED or  ENABLED
        :param action: (str) Possible values: ALLOW, BLOCK_DROP, BLOCK_RESET, BLOCK_ICMP, EVAL_NWAPP
        :param description: (str) Additional information about the rule
        :param default_rule: (bool) Default is false.If set to true, the default rule is applied
        :param predefined: (bool)
        :param src_ips: (list) List of source IP addresses
        :param dest_addresses: (list) List of destination addresses
        :param dest_ip_groups: (list) List of user-defined destination IP address groups
        :param src_ip_groups: (list) List of user defined source IP address groups
        :param dest_ip_categories:(list) list of destination IP categories
        :param labels: (?)
        :param nw_services: (list) List of user-defined network services on with the rule is applied
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
            "defaultRule": default_rule,
            "description": description,
        }
        if src_ips:
            payload.update(srcIps=src_ips)
        if src_ip_groups:
            payload.update(srcIpGroups=src_ip_groups)
        if dest_addresses:
            payload.update(destAddresses=dest_addresses)
        if dest_ip_groups:
            payload.update(destIpGroups=dest_ip_groups)
        if labels:
            payload.update(labels=labels)
        if dest_ip_categories:
            payload.update(destIpCategories=dest_ip_categories)
        if nw_services:
            payload.update(nwServices=nw_services)
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    def delete_firewall_filtering_rules(
        self,
        rule_id: int,
    ) -> requests.Response:
        """
        Deletes a Firewall Filtering policy rule for the specified ID.

        :param rule_id: (int) The unique identifier for the policy rule

        :return: (requests.Response Object)
        """
        url = f"/firewallFilteringRules/{rule_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=False,
            headers=self.headers,
        )

        return response

    def list_ip_source_groups(
        self,
        ip_group_id: int = None,
    ) -> json:
        """
        Gets a list of all IP source groups. The search parameters find matching values within the "name" or
        "description" attributes.

        :param ip_group_id: (int) Option ip group id

        :return: (json)
        """
        url = "/ipSourceGroups"
        if ip_group_id:
            url = f"/ipSourceGroups/{ip_group_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_ip_source_groups_lite(self) -> json:
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

    def list_ip_destination_groups(
        self,
        ip_group_id: int = None,
    ) -> json:
        """
        Gets a list of all IP source groups. The search parameters find matching values within the "name" or
        "description" attributes.

        :param ip_group_id: (int) Option ip group id

        :return: (json)
        """
        url = "/ipDestinationGroups/"
        if ip_group_id:
            url = f"/ipDestinationGroups/{ip_group_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def list_ip_destination_groups_lite(self) -> json:
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

    def add_ip_source_groups(
        self,
        name: str,
        ip_addresses: list,
        description: str = None,
    ) -> json:
        """
        :param name: (str) Name
        :param ip_addresses: (list) List of IP addresses
        :param description: (str) description

        :return: (json)
        """
        url = "/ipSourceGroups"
        payload = {
            "name": name,
            "ipAddresses": ip_addresses,
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

    def delete_ip_source_groups(
        self,
        ip_group_id: int,
    ) -> requests.Response:
        """
        Deletes the IP source group for the specified ID

        :param ip_group_id: (int) The unique identifies for the IP source group

        :return: (requests.Response Object)
        """
        url = f"/ipSourceGroups/{ip_group_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            payload={},
            headers=self.headers,
        )

        return response

    def delete_ip_destination_groups(
        self,
        ip_group_id: int,
    ) -> requests.Response:
        """
        Deletes the IP destination group for the specified ID

        :param ip_group_id: (int) The unique identifies for the IP source group

        :return: (requests.Response Object)
        """
        url = f"/ipDestinationGroups/{ip_group_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            payload={},
            headers=self.headers,
        )

        return response

    def add_ip_destination_groups(
        self,
        name: str,
        dest_ip_group_type: str,
        addresses: list,
        ip_categories: list = None,
        countries: list = None,
        description: str = None,
    ) -> json:
        """
        :param name: (str) Name
        :param dest_ip_group_type: (str) Destination IP group type. Either DSTN_IP or  DSTN_FQDN or DSTN_DOMAIN
        :param addresses: (list) List of Destination IP addresses within the group.
        :param ip_categories: (list) List of Destination IP address URL categories. You can identify destination based
        on the URL category of the domain. Default value ANY
        :param countries: (list) List of destination IP address countries. You can identify destinations based on
        the location of a server.Default value ANY
        :param description: (str) description
        """
        if dest_ip_group_type not in [
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

        if ip_categories:
            for j in ip_categories:
                if j not in valid_category_ids:
                    raise ValueError("Invalid country ")
        else:
            ip_categories = []

        url = "/ipDestinationGroups"
        payload = {
            "name": name,
            "type": dest_ip_group_type,
            "addresses": addresses,
            "ipCategories": ip_categories,
            "countries": countries,
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
        url = "/deviceGroups"
        if query:
            url = f"/deviceGroups?{query}"

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
        url = "/deviceGroups/devices"
        if query:
            url = f"/deviceGroups/devices?{query}"

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
        rule_label_id: int = None,
    ) -> json:
        """
        Gets rule label information for the specified ID

        :param rule_label_id: (int)

        :return: (json)
        """
        url = "/ruleLabels?pageSize=1000"
        if rule_label_id:
            url = f"/ruleLabels/{rule_label_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_rule_label(
        self,
        name: str,
        description: str = "",
        payload: dict = None,
    ) -> json:
        """
        Adds new rule labels with the given name
        :param name: (str) name  # FIXME: Not in passed attributes.
        :param description: (str) description  # FIXME: Not in passed attributes.
        :param payload: (dict)
        """
        url = "/ruleLabels"
        if not payload:
            payload = {"name": name, "description": description}
        response = self.hp_http.post_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
            payload=payload,
        )

        return response.json()

    def delete_rule_label(self, rule_id: str):
        url = f"/ruleLabels/{rule_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )
        return response

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
