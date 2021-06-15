import json
import pdb

from helpers.http_calls import HttpCalls


class ZpaTalkerPublic(object):
    """
    ZIA API talker
    Documentation: https://help.zscaler.com/zia/api
    https://help.zscaler.com/zpa
    """

    def __init__(self, customerID, cloud='https://config.private.zscaler.com'):
        """
        :param cloud: example https://config.zpabeta.net
        :param customerID: The unique identifier of the ZPA tenant
        """
        self.base_uri = f'{cloud}'
        # self.base_uri = f'https://config.zpabeta.net'
        self.hp_http = HttpCalls(host=self.base_uri, verify=True)
        self.jsessionid = None
        self.version = '1.1'
        self.header = None
        self.customerId = customerID

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

    # application-controller
    def list_application_segments(self, query=False):
        """
        Method to obtain application segments
        :param query: url query: Example ?page=1&pagesize=20&search=consequat
        """
        if not query:
            query = '?pagesize=500'
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/application{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    def add_application_segment(self, APPname, healthReporting, domainNames, applicationGroupId, serverGroups,
                                tcpPortRanges, udpPortRanges=[], description='', enabled=True, ipAnchored=False,
                                doubleEncrypt=False, bypassType='NEVER', isCnameEnabled=True, cnameConfig='NOFLATTEN'):
        """
        Adds a new Application Segment for a ZPA tenant.
        :param APPname: string. App Name
        :param description: string. Description
        :param enabled: Boolean (True|False)
        :param healthReporting: string. possible values: NONE, ON_ACCESS, CONTINUOUS
        :param ipAnchored: Boolean (True|False)
        :param doubleEncrypt: Boolean (True|False)
        :param bypassType: string. possible values ALWAYS, NEVER, ON_NET
        :param isCnameEnabled: Boolean (True|False)
        :param tcpPortRanges: list ["from", "to"]
        :param udpPortRanges: list ["from", "to"]
        :param domainNames: list of domains or IP addresses
        :param applicationGroupId: Application Group id
        :param serverGroups=list of dictionaries, where key is id and value is serverGroupId [{
                "id": "<serverGroupId>"}]
        :return:
        """

        url = f"/mgmtconfig/v1/admin/customers/{self.customerId}/application"
        payload = {
            "name": APPname,
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
            "applicationGroupId": applicationGroupId,
            "serverGroups": serverGroups,
            "cnameConfig": cnameConfig
        }
        response = self.hp_http.post_call(url=url, payload=payload, headers=self.header, error_handling=True)
        return response.json()

    def list_scim_group_controller(self, idpId, query=False):
        """
        Method details for all SCIM groups
        :param idpId: The unique identifies of the Idp
        :param query: ?page=1&pagesize=20&search=consequat
        """
        if not query:
            query = '?pagesize=500'
        url = f'/userconfig/v1/customers/{self.customerId}/scimgroup/idpId/{idpId}{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    # Connector-group-controller
    def list_connector_group(self, query=False):
        """
        Gets all configured App Connector Groups for a ZPA tenant.
        :param query: url query: Example ?page=1&pagesize=20&search=consequat
        return json
        """
        if not query:
            query = '?pagesize=500'
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/appConnectorGroup{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    #  Segment Group Controller

    def list_segment_group(self, query=False):
        """
        Method to list all segment group details
        :return: list
        """
        if not query:
            query = '?pagesize=500'

        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/segmentGroup{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    def add_segment_group(self, name, description, enabled=True):
        """
        Add a new segment group
        :param name:
        :param description:
        :param enabled:
        :return:
        """
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/segmentGroup'
        payload = {
            "name": name,
            "description": description,
            "enabled": enabled,
        }
        response = self.hp_http.post_call(url, headers=self.header, error_handling=True, payload=payload)
        return response.json()

    # Server Group Controller

    def list_server_groups(self, query=False):
        """
        Method to get all configured Server Groups
        :param query: url query: Example ?page=1&pagesize=20&search=consequat
        return json
        """
        if not query:
            query = '?pagesize=500'

        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/serverGroup{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

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

    # idP - controller
    def list_idP(self, query=False):
        """
        Method to Get all the idP details for a ZPA tenant
        :param query: HTTP query
        :return: json
        """
        if not query:
            query = '?pagesize=500'

        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/idp{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()
