from helpers.http_calls import HttpCalls


class ZpaTalkerPublic(object):
    """
    ZPA API talker
    Documentation: https://help.zscaler.com/zpa/zpa-api/api-developer-reference-guide
    """

    def __init__(self, customerID, cloud='https://config.private.zscaler.com'):
        """
        :param cloud: type string. Example https://config.zpabeta.net
        :param customerID: type int. The unique identifier of the ZPA tenant
        """
        self.base_uri = f'{cloud}'
        # self.base_uri = f'https://config.zpabeta.net'
        self.hp_http = HttpCalls(host=self.base_uri, verify=True)
        self.jsessionid = None
        self.version = '1.3'
        self.header = None
        self.customerId = customerID

    def _obtain_all_results(self, url):
        """
        API response can have multiple pages. This method return the whole response in a list
        :param url: type string. url
        :return: type list
        """
        result = []
        if '?pagesize' not in url:
            url = url + '?pagesize=500'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        if 'list' not in response.json().keys():
            return []
        if int(response.json()['totalPages']) > 1:
            i = 0
            while i <= int(response.json()['totalPages']):
                result = result + \
                         self.hp_http.get_call(f'{url}&page={i}', headers=self.header, error_handling=True).json()[
                             'list']
                i += 1
        else:
            result = response.json()['list']
        return result

    def authenticate(self, client_id, client_secret):
        """
        Method to obtain the Bearer Token
        return token
        """
        url = f'/signin'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        payload = {
            'client_id': client_id,
            'client_secret': client_secret
        }
        response = self.hp_http.post_call(url, headers=headers, error_handling=True, payload=payload, urlencoded=True)
        self.header = {
            'Authorization': f"{response.json()['token_type']} {response.json()['access_token']}"
        }
        return response.json()

    # app-server-controller

    def list_servers(self, query=False, serverId=None):
        """
        Method to obtain all the configured Servers.
        :param serverId: type int. Unique server id number
        :param query: type string. Example ?page=1&pagesize=20&search=consequat
        :return:json
        """
        if serverId:
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/server/{serverId}'
        else:
            if not query:
                query = '?pagesize=500'
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/server{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    # application-controller
    def list_application_segments(self, query=False, applicationId=None):
        """
        Method to obtain application segments
        :param query: url query: Example ?page=1&pagesize=20&search=consequat
        :param applicationId type int. Application unique identified id
        """
        if applicationId:
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/application/{applicationId}'
        else:
            if not query:
                query = '?pagesize=500'
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/application{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    def add_application_segment(self, name, healthReporting, domainNames, segmentGroupId, serverGroups,
                                tcpPortRanges=[], udpPortRanges=[], description='', enabled=True, ipAnchored=False,
                                doubleEncrypt=False, bypassType='NEVER', isCnameEnabled=True, cnameConfig='NOFLATTEN'):
        """
        Adds a new Application Segment for a ZPA tenant.
        :param name: type string. App Name
        :param description: type string. Description
        :param enabled: type boolean (True|False)
        :param healthReporting: type string. possible values: NONE, ON_ACCESS, CONTINUOUS
        :param ipAnchored: type boolean (True|False)
        :param doubleEncrypt: type boolean (True|False)
        :param bypassType: type string. possible values ALWAYS, NEVER, ON_NET
        :param isCnameEnabled: type boolean (True|False)
        :param tcpPortRanges: type list.  ["from", "to"]
        :param udpPortRanges: type list.  ["from", "to"]
        :param domainNames: type list. List of domains or IP addresses
        :param segmentGroupId: type string. Application Segment Group id
        :param serverGroups=type list. list of dictionaries, where key is id and value is serverGroupId [{
                "id": "<serverGroupId>"}]
        :return: type dict. HTTP response
        """

        url = f"/mgmtconfig/v1/admin/customers/{self.customerId}/application"
        payload = {
            "name": name,
            "description": description,
            "enabled": enabled,
            "healthReporting": healthReporting,
            "ipAnchored": ipAnchored,
            "doubleEncrypt": doubleEncrypt,
            "bypassType": bypassType,
            "isCnameEnabled": isCnameEnabled,
            "tcpPortRanges": tcpPortRanges,
            "udpPortRanges": udpPortRanges,
            "domainNames": domainNames,
            "segmentGroupId": segmentGroupId,
            "serverGroups": serverGroups,
            "cnameConfig": cnameConfig
        }
        response = self.hp_http.post_call(url=url, payload=payload, headers=self.header, error_handling=True)
        return response.json()

    # segment-group-controller

    def list_segment_group(self, segmentGroupId=None, query=False):
        """
        Get all the configured Segment Groups. If segmentGroupId obtains the segment sroup details
        :param segmentGroupId: The unique identifier of the Segment Group.
        :param query: url query: Example ?page=1&pagesize=20&search=consequat
        return json
        """
        if segmentGroupId:
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/segmentGroup/{segmentGroupId}'
        else:
            if not query:
                query = '?pagesize=500'
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/segmentGroup/{query}'

        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    def add_segment_group(self, name, description, enabled=True):
        """
        Add a new segment group
        :param name: type string. Name of segment Group
        :param description: type string. Description
        :param enabled: type boolean: True or False
        :return: Json
        """
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/segmentGroup'
        payload = {
            "name": name,
            "description": description,
            "enabled": enabled,
        }
        response = self.hp_http.post_call(url, headers=self.header, error_handling=True, payload=payload)
        return response.json()

    # connector-controller
    def list_connector(self, connectorId=None, ):
        """
        Get all the configured Segment Groups. If segmentGroupId obtains the segment group details
        :param connectorId: The unique identifier of the App Connector.
        return json
        """
        if connectorId:
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/connector/{connectorId}'
            return self.hp_http.get_call(url, headers=self.header, error_handling=True).json()
        else:
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/connector'
        response = self._obtain_all_results(url)
        return response

    def delete_bulk_connector(self, ids):
        """
        Get all the configured Segment Groups. If segmentGroupId obtains the segment sroup details
        :param ids: type list. list of resouces ids for bulk deleting the App Connectors..
        return json
        """
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/connector/bulkDelete'
        payload = {"ids": ids
                   }
        response = self.hp_http.post_call(url=url, headers=self.header, error_handling=True, payload=payload)
        return response.json()

    # Connector-group-controller
    def list_connector_group(self, appConnectorGroupId=None):
        """
        Gets all configured App Connector Groups for a ZPA tenant.
        :param appConnectorGroupId: type int: The unique identifier of the Connector Group.
        return json
        """
        if appConnectorGroupId:
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/appConnectorGroup/{appConnectorGroupId}'
            return self.hp_http.get_call(url, headers=self.header, error_handling=True).json()
        else:
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/appConnectorGroup'
            response = self._obtain_all_results(url)
        return response

    # ba-certificate-controller-v-2

    def list_browser_access_certificates(self):
        """
        Get all Browser issued certificates
        return json
        """
        url = f'/mgmtconfig/v2/admin/customers/{self.customerId}/clientlessCertificate/issued'
        response = self._obtain_all_results(url)
        return response

    # enrollment-cert-controller

    def list_enrollment_certificates(self, ):
        """
        Get all the Enrollment certificates
        return list
        """
        url = f'/mgmtconfig/v2/admin/customers/{self.customerId}/enrollmentCert'
        response = self._obtain_all_results(url)
        return response

    def list_browser_access_certificates(self):
        """
        Get all the issued certificates
        return list
        """
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/visible/versionProfiles'
        response = self._obtain_all_results(url)
        return response

    # customer-version-profile-controller

    def list_customer_version_profile(self, query=False):
        """
        Get Version Profiles visible to a customer
        :param query: url query: Example ?page=1&pagesize=20&search=consequat
        return json
        """
        if not query:
            query = '?pagesize=500'
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/visible/versionProfiles{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    # cloud - connector - group - controller
    def list_cloud_connector_group(self, id=None, query=False):
        """
        Get all configured Cloud Connector Groups. If id, Get the Cloud Connector Group details
        :param query: url query: Example ?page=1&pagesize=20&search=consequat
        return json
        """
        if id:
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/cloudConnectorGroup/{id}'
        else:
            if not query:
                query = '?pagesize=500'
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/cloudConnectorGroup{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    # idp-controller-v-2
    def list_idP(self, query=False):
        """
        Method to Get all the idP details for a ZPA tenant
        :param query: HTTP query
        :return: json
        """
        if not query:
            query = '?pagesize=500'

        url = f'/mgmtconfig/v2/admin/customers/{self.customerId}/idp{query}'
        response = self._obtain_all_results(url)
        return response

    # provisioningKey-controller
    def list_provisioningKey(self, associationType='CONNECTOR_GRP'):
        """
        Gets details of all the configured provisioning keys.
        :param associationType: type string. The supported values are CONNECTOR_GRP and SERVICE_EDGE_GRP.
        :return: list
        """
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/associationType/{associationType}/provisioningKey'
        response = self._obtain_all_results(url)
        return response

    # policy-set-controller

    # scim-attribute-header-controller

    def list_scim_attributes(self, idpId, query=False):
        """

        :param idpId: The unique identifies of the Idp
        :param query: ?page=1&pagesize=20&search=consequat
        """
        if not query:
            query = '?pagesize=500'
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/idp/{idpId}/scimattribute{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    # scim-group-controller
    def list_scim_groups(self, idpId, query=False):
        """
        Method details for all SCIM groups
        :param idpId: The unique identifies of the Idp
        :param query: ?page=1&pagesize=20&search=consequat
        """
        if not query:
            query = '?pagesize=500'
        url = f'/userconfig/v1/customers/{self.customerId}/scimgroup/idpId/{idpId}{query}'
        response = self._obtain_all_results(url)
        return response

    # saml-attr-controller-v-2
    def list_saml_attributes(self):
        """
        Method to get all SAML attributes
        """
        url = f'/mgmtconfig/v2/admin/customers/{self.customerId}/samlAttribute'
        response = self._obtain_all_results(url)
        return response

    # global-policy-controller

    def list_policies(self, policyType='ACCESS_POLICY'):
        """list policie(s)  by policy type,
         :param policyType: Type string. Supportef values Possible values=ACCESS_POLICY,GLOBAL_POLICY, TIMEOUT_POLICY,REAUTH_POLICY,
         SIEM_POLICY, CLIENT_FORWARDING_POLICY,BYPASS_POLICY
         """
        url = f"/mgmtconfig/v1/admin/customers/{self.customerId}/policySet/rules/policyType/{policyType}"
        response = self._obtain_all_results(url)
        return response

    def list_global_policy_id(self, query=False):
        """
        Method to get the global policy
        :param query: ?page=1&pagesize=20&search=consequat
        """
        if not query:
            query = '?pagesize=500'
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/policySet/global{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    def add_policySet(self, app_operands, RuleName, Action, policySetId, operands, operator, MsgString=None):
        """
        Method to create a new access Policy
        :param app_operands: list of app_operands: Examples
        [{
                    "objectType": "APP",
                    "lhs": "id",
                    "rhs": applicationId,
        }]
        :param RuleName: Policy set Rule Name
        :param Action: ALLOW / DENY
        :param policySetId:  Global Policy ID. can be obtained from list_global_policy_id
        :param operands:  List of operands. Example
        [{
            "objectType": "SAML",
            "lhs": "<samlAttrId>",
            "rhs": "<samlAttrValue>",
        },{
            "objectType": "SCIM",
            "lhs": "<scimAttrId>",
            "rhs": "<scimAttrValue>”
        }]


        :return:
        """
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/policySet/{policySetId}/rule'
        payload = {
            "conditions": [{
                "operands": app_operands
            }, {

                "operands": operands,
                "operator": operator,
            }, ],
            # Seems here needs to be AND
            "operator": 'AND',
            "name": RuleName,
            "description": "Description",
            "action": Action,
            "customMsg": MsgString
        }
        print(payload)
        response = self.hp_http.post_call(url=url, headers=self.header, error_handling=True, payload=payload)
        return response.json()

    # Server Group Controller

    def list_server_groups(self, groupId=None):
        """
        Method to get all configured Server Groups. If groupI, get the Server Group details
        :param groupId: type integer. The unique identifier of the Server Group.
        return json
        """
        if groupId:
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/serverGroup/{groupId}'
            response = self.hp_http.get_call(url, headers=self.header, error_handling=True).json()
        else:
            url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/serverGroup'
            response = self._obtain_all_results(url)
        return response

    def add_server_groups(self, name, description, connector_group_id):
        """
        :param name: Server Group Name
        :param description: Description
        :param connector_group_id: list of dictionaries with key as "id" and value connector_group_id.
            [{"id": connector_group_id}]
        """
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/serverGroup'

        payload = {
            "enabled": True,
            "dynamicDiscovery": True,
            "name": name,
            "description": description,
            "servers": [
            ],
            "appConnectorGroups": connector_group_id
        }
        response = self.hp_http.post_call(url=url, headers=self.header, error_handling=True, payload=payload)
        return response.json()

    def list_posture_profiles(self, query=False):
        """
        Method to Get all the idP details for a ZPA tenant
        :param query: HTTP query
        :return: json
        """
        if not query:
            query = '?pagesize=500'

        url = f'/mgmtconfig/v2/admin/customers/{self.customerId}/posture{query}'
        response = self._obtain_all_results(url)
        return response
