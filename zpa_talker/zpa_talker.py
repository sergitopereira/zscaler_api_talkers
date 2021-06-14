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
        :param cloud: examplehttps://config.zpabeta.net
        :param customerID: The unique identifier of the ZPA tenant
        """
        self.base_uri = f'{cloud}'
        #self.base_uri = f'https://config.zpabeta.net'
        self.hp_http = HttpCalls(host=self.base_uri, verify=True)
        self.jsessionid = None
        self.version = '1.0'
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

    def get_application_segments(self, query=False):
        """
        Method to obtain application segments
        :param query: url query: Example ?page=1&pagesize=20&search=consequat
        """
        if not query:
            query = '?pagesize=500'
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/application{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    def get_scim_group_controller(self, idpId, query=False):
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

    # Segment Group Controller

    def list_segment_group(self,query=False):
        """
        Method to get all configured Server Groups
        :param query: url query: Example ?page=1&pagesize=20&search=consequat
        return json
        """
        if not query:
            query = '?pagesize=500'
        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/segmentGroup{query}'
        response = self.hp_http.get_call(url, headers=self.header, error_handling=True)
        return response.json()

    # Connector-group-controller
    def list_connector_group(self,query=False):
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


    # Server Group Controller
    def add_segment_group(self, name, description, enabled=True):

        url = f'/mgmtconfig/v1/admin/customers/{self.customerId}/segmentGroup'
        payload = {
            "name": name,
            "description": description,
            "enabled": enabled,
        }
        print(payload)
        response = self.hp_http.post_call(url, headers=self.header, error_handling=True, payload=payload)
        print(response)
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
