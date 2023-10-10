import json

import requests

from zscaler_api_talkers.helpers import HttpCalls, setup_logger
from typing import Any

logger = setup_logger(name=__name__)


class ZpaTalker(object):
    """
    ZPA API talker
    Documentation: https://help.zscaler.com/zpa/zpa-api/api-developer-reference-guide
    """

    def __init__(
        self,
        customer_id: int,
        cloud: str = "https://config.private.zscaler.com",
        client_id: str = None,
        client_secret: str = "",
    ):
        """
        :param cloud: (str) Example https://config.zpabeta.net
        :param customer_id: (int) The unique identifier of the ZPA tenant
        :param client_id: (str)
        :param client_secret: (str)
        """
        self.base_uri = cloud
        self.hp_http = HttpCalls(
            host=self.base_uri,
            verify=True,
        )
        self.jsessionid = None
        self.version = "1.3"
        self.header = None
        self.customer_id = customer_id
        if client_id and client_secret:
            self.authenticate(
                client_id=client_id,
                client_secret=client_secret,
            )

    def _obtain_all_results(
        self,
        url: str,
    ) -> list:
        """
        API response can have multiple pages. This method return the whole response in a list

        :param url: (str) url

        :return: (list)
        """
        result = []
        if "?pagesize" not in url:
            url = f"{url}?pagesize=500"  # TODO: Move to parameters
        response = self.hp_http.get_call(
            url,
            headers=self.header,
            error_handling=True,
        )
        if "list" not in response.json().keys():
            return []
        if int(response.json()["totalPages"]) > 1:
            i = 0
            while i <= int(response.json()["totalPages"]):
                result = (
                    result
                    + self.hp_http.get_call(
                        f"{url}&page={i}",
                        headers=self.header,
                        error_handling=True,
                    ).json()["list"]
                )
                i += 1
        else:
            result = response.json()["list"]

        return result

    def authenticate(
        self,
        client_id: str,
        client_secret: str,
    ) -> None:
        """
        Method to obtain the Bearer Token. Refer to https://help.zscaler.com/zpa/adding-api-keys
        :param client_id: (str) client id
        :param client_secret. (str) client secret

        return (json))
        """
        url = f"/signin"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = {
            "client_id": client_id,
            "client_secret": client_secret,
        }
        response = self.hp_http.post_call(
            url,
            headers=headers,
            error_handling=True,
            payload=payload,
            urlencoded=True,
        )
        self.header = {
            "Authorization": f"{response.json()['token_type']} {response.json()['access_token']}"
        }

        return

    # app-server-controller

    def list_servers(
        self,
        query: str = False,
        server_id: int = None,
    ) -> json:
        """
        Method to obtain all the configured Servers.

        :param query: (str) Example ?page=1&pagesize=20&search=consequat
        :param server_id: (int) Unique server id number

        :return: (json)
        """
        if server_id:
            url = (
                f"/mgmtconfig/v1/admin/customers/{self.customer_id}/server/{server_id}"
            )
        else:
            if not query:
                query = "?pagesize=500"
            url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/server{query}"
        response = self.hp_http.get_call(
            url,
            headers=self.header,
            error_handling=True,
        )

        return response.json()

    # application-controller
    def list_application_segments(
        self,
        application_id: int = None,
    ) -> json or list:
        """
        Method to obtain application segments

        :param application_id: (int) Application unique identified id

        :return: (json|list)
        """
        if application_id:
            url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/application/{application_id}"
            response = self.hp_http.get_call(
                url,
                headers=self.header,
                error_handling=True,
            )
            return response.json()

        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/application"
        response = self._obtain_all_results(url)

        return response

    def add_application_segment(
        self,
        name: str,
        health_reporting: str,
        domain_names: list,
        segment_group_id: str,
        server_groups: list,
        common_apps_dto: list = None,
        segment_group_name: str = "",
        health_check_type: str = "DEFAULT",
        clientless_apps: list = None,
        inspection_apps: list = None,
        sra_apps: list = None,
        tcp_port_range: dict = None,
        tcp_port_ranges: list = None,
        udp_port_ranges: list = None,
        udp_port_range: dict = None,
        description: str = "",
        enabled: bool = True,
        icmp_access_type: str = "NONE",
        ip_anchored: bool = False,
        double_encrypt: bool = False,
        bypass_type: str = "NEVER",
        is_cname_enabled: bool = True,
        select_connector_close_to_app: bool = False,
        passive_health_enabled: bool = True,
    ) -> json:
        """
        Adds a new Application Segment for a ZPA tenant.
        :param name: (str) App Name
        :param health_reporting: (str) possible values: NONE, ON_ACCESS, CONTINUOUS
        :param domain_names: (list) List of domains or IP addresses
        :param segment_group_id: (str) Application Segment Group id
        :param server_groups=(list) List of dictionaries, where key is id and value is serverGroupId [
        {"id": "<serverGroupId>"}
        ]
        :param common_apps_dto: (list) List of dictionaries, where appsConfig will list the apps with Browser Access
        or Inspection
        :param segment_group_name: (str) Application Segment Group Name
        :param health_check_type: (str)
        :param clientless_apps: (list) List of application domains in Application Segment with Browser access enabled
        :param inspection_apps: (list) List of application domains in Application Segment with Inspection enabled
        :param sra_apps: (list) List of application domains in Application Segment with Privileged Remote Access enabled
        :param tcp_port_range: type dict.  [{"from":int, "to":int}]
        :param tcp_port_ranges: (list)  ["from", "to"]. This will be deprecated in the future.
        :param udp_port_range: type dict.  [{"from":int, "to":int}]
        :param udp_port_ranges: (list)  ["from", "to"]. This will be deprecated in the future.
        :param description: (str) Description
        :param enabled: (bool) (True|False)
        :param icmp_access_type: (str) possible values: PING_TRACEROUTING, PING, NONE
        :param ip_anchored: (bool) (True|False)
        :param double_encrypt: (bool) (True|False)
        :param bypass_type: (str) possible values ALWAYS, NEVER, ON_NET
        :param is_cname_enabled: (bool) (True|False)
        :param select_connector_close_to_app: (bool) (True|False)
        :param passive_health_enabled: (bool) (True|False)

        :return: (json)
        """

        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/application"
        payload = {
            "name": name,
            "description": description,
            "enabled": enabled,
            "healthCheckType": health_check_type,
            "healthReporting": health_reporting,
            "icmpAccessType": icmp_access_type,
            "ipAnchored": ip_anchored,
            "doubleEncrypt": double_encrypt,
            "bypassType": bypass_type,
            "isCnameEnabled": is_cname_enabled,
            "clientlessApps": clientless_apps,
            "inspectionApps": inspection_apps,
            "sraApps": sra_apps,
            "commonAppsDto": common_apps_dto,
            "selectConnectorCloseToApp": select_connector_close_to_app,
            "passiveHealthEnabled": passive_health_enabled,
            "tcpPortRanges": tcp_port_ranges,
            "tcpPortRange": tcp_port_range,
            "udpPortRange": udp_port_range,
            "udpPortRanges": udp_port_ranges,
            "domainNames": domain_names,
            "segmentGroupId": segment_group_id,
            "segmentGroupName": segment_group_name,
            "serverGroups": server_groups,
        }
        response = self.hp_http.post_call(
            url=url,
            payload=payload,
            headers=self.header,
            error_handling=True,
        )

        return response.json()

    def update_application_segment(
        self,
        application_id: int,
        payload: dict,
    ) -> requests.Response:
        """
        Updates the Application Segment details for the specified ID

        :param application_id: (int) Application ID
        :param payload: (dict)

        :return: (requests.Response Object)
        """
        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/application/{application_id}"
        response = self.hp_http.put_call(
            url=url,
            payload=payload,
            headers=self.header,
            error_handling=True,
        )

        return response

    def delete_application_segment(
        self,
        application_id: int,
    ) -> requests.Response:
        """
        Updates the Application Segment details for the specified ID

        :param application_id: (int) Application ID

        :return: (requests.Response Object)
        """
        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/application/{application_id}"
        response = self.hp_http.delete_call(
            url=url,
            error_handling=True,
        )

        return response

    # segment-group-controller

    def list_segment_group(
        self,
        segment_group_id: int = None,
        query: str = False,
    ) -> json or list:
        """
        Get all the configured Segment Groups. If segmentGroupId obtains the segment sroup details

        :param segment_group_id: (int) The unique identifier of the Segment Group.
        :param query: (str) Example ?page=1&pagesize=20&search=consequat

        return (json|list)
        """
        if segment_group_id:
            url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/segmentGroup/{segment_group_id}"
            response = self.hp_http.get_call(
                url, headers=self.header, error_handling=True
            ).json()
        else:
            if not query:
                query = "?pagesize=500"
            url = (
                f"/mgmtconfig/v1/admin/customers/{self.customer_id}/segmentGroup{query}"
            )
            response = self._obtain_all_results(url)

        return response

    def add_segment_group(
        self,
        name: str,
        description: str,
        enabled: bool = True,
    ) -> json:
        """
        Add a new segment group

        :param name: (str) Name of segment Group
        :param description: (str) Description
        :param enabled: (bool): True or False
        :return: (json)
        """
        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/segmentGroup"
        payload = {
            "name": name,
            "description": description,
            "enabled": enabled,
        }
        response = self.hp_http.post_call(
            url,
            headers=self.header,
            error_handling=True,
            payload=payload,
        )

        return response.json()

    def delete_segment_group(self, segmentGroupId: int) -> json:
        """
        Deletes specified Segment Group.
        :param segmentGroupId: The unique identifier of the Segment Group.
        return: response
        """
        url: str = f'/mgmtconfig/v1/admin/customers/{self.customer_id}/segmentGroup/{segmentGroupId}'
        response = self.hp_http.delete_call(url=url, error_handling=True)
        return response

    def update_segment_group(self, segment_group_id: int, payload: dict) -> json:
        """
        Update Segment Group
        :param segment_group_id: type int. The unique identifier of the Segment Group.
        :param payload: type dict. Segment Group details to be updated.
        :return: Json
        """
        url: str = f'/mgmtconfig/v1/admin/customers/{self.customer_id}/segmentGroup/{segment_group_id}'
        response = self.hp_http.put_call(url, headers=self.header, error_handling=True, payload=payload)
        return response

    # connector-controller
    def list_connector(
        self,
        connector_id: int = None,
    ) -> json or list:
        """
        Get all the configured Segment Groups. If segmentGroupId obtains the segment group details

        :param connector_id: The unique identifier of the App Connector.

        return (json|list)
        """
        if connector_id:
            url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/connector/{connector_id}"
            return self.hp_http.get_call(
                url,
                headers=self.header,
                error_handling=True,
            ).json()
        else:
            url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/connector"
            response = self._obtain_all_results(url)

        return response

    def update_connector(self, connector_id: int, payload: dict) -> requests.Response:
        """
        Update Connector =
        :param connector_id: type int. The unique identifier of the App Connector.
        :param payload: type dict.
        :return: Json
        """
        url  = f'/mgmtconfig/v1/admin/customers/{self.customer_id}/connector/{connector_id}'
        response = self.hp_http.put_call(url, headers=self.header, error_handling=True, payload=payload)
        return response

    def delete_bulk_connector(
        self,
        ids: list,
    ) -> json:
        """
        Get all the configured Segment Groups. If segmentGroupId obtains the segment sroup details

        :param ids: (list) list of resources ids for bulk deleting the App Connectors.

        return (json)
        """
        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/connector/bulkDelete"
        payload = {"ids": ids}
        response = self.hp_http.post_call(
            url=url,
            headers=self.header,
            error_handling=True,
            payload=payload,
        )

        return response.json()

    # Connector-group-controller
    def list_connector_group(
        self,
        app_connector_group_id: int = None,
    ) -> json or list:
        """
        Gets all configured App Connector Groups for a ZPA tenant.

        :param app_connector_group_id: (int) The unique identifier of the Connector Group.

        return (json|list)
        """
        if app_connector_group_id:
            url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/appConnectorGroup/{app_connector_group_id}"
            return self.hp_http.get_call(
                url,
                headers=self.header,
                error_handling=True,
            ).json()
        else:
            url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/appConnectorGroup"
            response = self._obtain_all_results(url)

        return response

    def add_connector_group(self, name: str, description: str, latitude: str, longitude: str, location: str, upgradeDay: str = 'SUNDAY',
                            enabled: bool = True,
                            dnsQueryType: str = 'IPV4_IPV6', upgradeTimeInSecs: int = 66600,
                            overrideVersionProfile: bool = False, versionProfileId: int = None, tcpQuickAckApp: bool = False,
                            tcpQuickAckAssistant: bool = False, tcpQuickAckReadAssistant: bool = False, cityCountry: str = "",
                            countryCode: str = "", connectors: list = [], serverGroups: list = [], lssAppConnectorGroup: bool = False) -> json:
        """
        :param name: type string. Name of App Connector Group
        :param description: type string. Description
        :param latitude: type string. Latitude of App Connector Group
        :param longitude: type string. Longitude of App Connector Group
        :param location: type string. Location of the App Connector Group
        :param upgradeDay: type string. App Connectors in this group attempt to update to a newer version of the software during this specified day
        :param upgradeTimeInSecs: type int. App Connectors in this group attempt to update to a newer version of the software during this specified time
        :param overrideVersionProfile: type boolean. Whether the default version profile of the App Connector Group is applied or overridden
        :param versionProfileId: type int. ID of the version profile
        :param tcpQuickAckApp: type boolean. Whether TCP Quick Acknowledgement is enabled or disabled for the application. The tcpQuickAckApp, tcpQuickAckAssistant, and tcpQuickAckReadAssistant fields must all share the same value.
        :param tcpQuickAckAssistant: type boolean. Whether TCP Quick Acknowledgement is enabled or disabled for the application
        :param tcpQuickAckReadAssistant: type boolean. Whether TCP Quick Acknowledgement is enabled or disabled for the application
        :param connectors: type dict. App Connector Id's part of the App Connector Group.
        :param serverGroups: type dict. Server Groups part of App Connector Group
        :param lssAppConnectorGroup: type boolean. Is App Connector Group reserved for LSS
        """
        url: str = f'/mgmtconfig/v1/admin/customers/{self.customer_id}/appConnectorGroup'
        payload: dict[str | Any, object | Any] = {
            "name": name,
            "description": description,
            "latitude": latitude,
            "longitude": longitude,
            "location": location,
            "upgradeDay": upgradeDay,
            "enabled": enabled,
            "dnsQueryType": dnsQueryType,
            "upgradeTimeInSecs": upgradeTimeInSecs,
            "overrideVersionProfile": overrideVersionProfile,
            "versionProfileId": versionProfileId,
            "tcpQuickAckApp": tcpQuickAckApp,
            "tcpQuickAckAssistant": tcpQuickAckAssistant,
            "tcpQuickAckReadAssistant": tcpQuickAckReadAssistant,
            "cityCountry": cityCountry,
            "countryCode": countryCode,
            "connectors": connectors,
            "serverGroups": serverGroups,
            "lssAppConnectorGroup": lssAppConnectorGroup
        }
        response = self.hp_http.post_call(url, headers=self.header, error_handling=True, payload=payload)
        return response.json()

    def update_connector_group(self, appConnectorGroupId: int, payload: dict) -> json:
        """
        Update configured App Connector Groups for a ZPA tenant.
        :param appConnectorGroupId: type int. The unique identifier of the Connector Group
        :param payload: type dict. Details of App Connector group to be updated
        return response
        """
        url: str = f'/mgmtconfig/v1/admin/customers/{self.customer_id}/appConnectorGroup/{appConnectorGroupId}'
        response = self.hp_http.put_call(url, headers=self.header, error_handling=True, payload=payload)
        return response

    def delete_connector_group(self, appConnectorGroupId: int) -> json:
        """
            Delete specified App Connector Group
            :param appConnectorGroupId: type int. The unique identifier of the Connector Group
            return response
        """
        url: str = f'/mgmtconfig/v1/admin/customers/{self.customer_id}/appConnectorGroup/{appConnectorGroupId}'
        response = self.hp_http.delete_call(url, error_handling=True)
        return response
    # ba-certificate-controller-v-2

    def list_browser_access_certificates(
        self,
    ) -> list:  # FIXME: duplicate but URL is slightly different.
        """
        Get all Browser issued certificates

        :return: (list)
        """
        url = f"/mgmtconfig/v2/admin/customers/{self.customer_id}/clientlessCertificate/issued"
        response = self._obtain_all_results(url)

        return response

    # enrollment-cert-controller

    def list_enrollment_certificates(self) -> list:
        """
        Get all the Enrollment certificates

        :return: (list)
        """
        url = f"/mgmtconfig/v2/admin/customers/{self.customer_id}/enrollmentCert"
        response = self._obtain_all_results(url)

        return response

    def list_v1_browser_access_certificates(
        self,
    ) -> list:
        """
        Get all the issued certificates

        :return: (list)
        """
        url = (
            f"/mgmtconfig/v1/admin/customers/{self.customer_id}/visible/versionProfiles"
        )
        response = self._obtain_all_results(url)

        return response

    # customer-version-profile-controller

    def list_customer_version_profile(
        self,
        query: str = False,
    ) -> json:
        """
        Get Version Profiles visible to a customer

        :param query: (str) Example ?page=1&pagesize=20&search=consequat

        :return: (json)
        """
        if not query:
            query = "?pagesize=500"
        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/visible/versionProfiles{query}"
        response = self.hp_http.get_call(
            url,
            headers=self.header,
            error_handling=True,
        )

        return response.json()

    # cloud - connector - group - controller
    def list_cloud_connector_group(
        self,
        group_id: int = None,
        query: str = False,
    ) -> json:
        """
        Get all configured Cloud Connector Groups. If id, Get the Cloud Connector Group details

        :param group_id: (int)
        :param query: (str) Example ?page=1&pagesize=20&search=consequat

        :return: (json)
        """
        if group_id:
            url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/cloudConnectorGroup/{group_id}"
        else:
            if not query:
                query = "?pagesize=500"
            url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/cloudConnectorGroup{query}"

        response = self.hp_http.get_call(
            url,
            headers=self.header,
            error_handling=True,
        )

        return response.json()

    # idp-controller-v-2
    def list_idp(
        self,
        query: str = False,
    ) -> list:
        """
        Method to Get all the idP details for a ZPA tenant

        :param query: (str) HTTP query

        :return: (list)
        """
        if not query:
            query = "?pagesize=500"
        url = f"/mgmtconfig/v2/admin/customers/{self.customer_id}/idp{query}"
        response = self._obtain_all_results(url)

        return response

    # provisioningKey-controller
    def list_provisioning_key(
        self,
        association_type: str = "CONNECTOR_GRP",
    ) -> list:
        """
        Gets details of all the configured provisioning keys.

        :param association_type: (str) The supported values are CONNECTOR_GRP and SERVICE_EDGE_GRP.

        :return: (list)
        """
        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/associationType/{association_type}/provisioningKey"
        response = self._obtain_all_results(url)

        return response

    # policy-set-controller

    # scim-attribute-header-controller

    def list_scim_attributes(
        self,
        idp_id: int,
        query: str = False,
    ) -> json:
        """
        :param idp_id: (int) The unique identifies of the Idp
        :param query: (str) ?page=1&pagesize=20&search=consequat

        :return: (json)
        """
        if not query:
            query = "?pagesize=500"
        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/idp/{idp_id}/scimattribute{query}"
        response = self.hp_http.get_call(
            url,
            headers=self.header,
            error_handling=True,
        )

        return response.json()

    # scim-group-controller
    def list_scim_groups(
        self,
        idp_id: int,
        query: str = False,
    ) -> list:
        """
        Method to list all SCIM groups

        :param idp_id: (int) The unique identifies of the Idp
        :param query: (str) ?page=1&pagesize=20&search=consequat

        :return: (list)
        """
        if not query:
            query = "?pagesize=500"
        url = f"/userconfig/v1/customers/{self.customer_id}/scimgroup/idpId/{idp_id}{query}"
        response = self._obtain_all_results(url)

        return response

    # saml-attr-controller-v-2
    def list_saml_attributes(self) -> list:
        """
        Method to get all SAML attributes

        :return: (list)
        """
        url = f"/mgmtconfig/v2/admin/customers/{self.customer_id}/samlAttribute"
        response = self._obtain_all_results(url)

        return response

    # global-policy-controller

    def list_policies(
        self,
        policy_type: str = "ACCESS_POLICY",
    ) -> list:
        """list policie(s)  by policy type,

        :param policy_type: (str) Supported values Possible values = ACCESS_POLICY,GLOBAL_POLICY, TIMEOUT_POLICY,
        REAUTH_POLICY, SIEM_POLICY, CLIENT_FORWARDING_POLICY,BYPASS_POLICY

        :return: (list)
        """
        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/policySet/rules/policyType/{policy_type}"
        response = self._obtain_all_results(url)

        return response

    def list_policy_set(
        self,
        policy_type: str = "ACCESS_POLICY",
    ) -> json:
        """Gets the policy set for the specified policy type

        :param policy_type: (str) Supported values are ACCESS_POLICY,GLOBAL_POLICY, TIMEOUT_POLICY,REAUTH_POLICY,
        SIEM_POLICY, CLIENT_FORWARDING_POLICY,BYPASS_POLICY

        :return: (json)
        """
        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/policySet/policyType/{policy_type}"
        response = self.hp_http.get_call(
            url,
            headers=self.header,
            error_handling=True,
        )

        return response.json()

    def add_policy_set(
        self,
        app_operands: list,
        rule_name: str,
        action: str,
        policy_set_id: int,
        operands: list,
        operator: str,
        msg_string: str = None,
    ) -> json:
        """
        Method to create a new access Policy

        :param app_operands: (list) List of app_operands: Examples = [{
        "objectType": "APP",
        "lhs": "id",
        "rhs": applicationId,
        }]
        :param rule_name: (str) Policy set Rule Name
        :param action: (str) ALLOW / DENY
        :param policy_set_id: (int) Global Policy ID. can be obtained from list_global_policy_id
        :param operands: (list) List of operands. Example = [{
        "objectType": "SAML",
        "lhs": "<samlAttrId>",
        "rhs": "<samlAttrValue>",
        },{
        "objectType": "SCIM",
        "lhs": "<scimAttrId>",
        "rhs": "<scimAttrValue>”
        }]
        :param operator: (str)
        :param msg_string: (str)

        :return: (json)
        """
        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/policySet/{policy_set_id}/rule"
        payload = {
            "conditions": [
                {"operands": app_operands},
                {
                    "operands": operands,
                    "operator": operator,
                },
            ],
            # Seems here needs to be AND
            "operator": "AND",
            "name": rule_name,
            "description": "Description",
            "action": action,
            "customMsg": msg_string,
        }
        logger.info(payload)
        response = self.hp_http.post_call(
            url=url,
            headers=self.header,
            error_handling=True,
            payload=payload,
        )

        return response.json()

    # Server Group Controller

    def list_server_groups(
        self,
        group_id: int = None,
    ) -> json or list:
        """
        Method to get all configured Server Groups. If groupI, get the Server Group details

        :param group_id: (int) The unique identifier of the Server Group.

        :return: (json|list)
        """
        if group_id:
            url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/serverGroup/{group_id}"
            response = self.hp_http.get_call(
                url,
                headers=self.header,
                error_handling=True,
            ).json()
        else:
            url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/serverGroup"
            response = self._obtain_all_results(url)

        return response

    def add_server_groups(
        self,
        name: str,
        description: str,
        connector_group_id: list,
    ) -> json:
        """
        :param name: (str) Server Group Name
        :param description: (str) Description
        :param connector_group_id: (list) List of dictionaries with key as "id" and value connector_group_id.
        [{"id": connector_group_id}]

        :return: (json)
        """
        url = f"/mgmtconfig/v1/admin/customers/{self.customer_id}/serverGroup"
        payload = {
            "enabled": True,
            "dynamicDiscovery": True,
            "name": name,
            "description": description,
            "servers": [],
            "appConnectorGroups": connector_group_id,
        }
        response = self.hp_http.post_call(
            url=url,
            headers=self.header,
            error_handling=True,
            payload=payload,
        )

        return response.json()

    def list_posture_profiles(
        self,
        query: str = False,
    ) -> list:
        """
        Method to Get all the idP details for a ZPA tenant

        :param query: (str) HTTP query

        :return: (list)
        """
        if not query:
            query = "?pagesize=500"
        url = f"/mgmtconfig/v2/admin/customers/{self.customer_id}/posture{query}"
        response = self._obtain_all_results(url)

        return response

    def list_privileged_consoles(
        self,
        query: str = False,
    ) -> list:
        """
        Method to Get all the privileged_remote_consoles for a ZPA tenant

        :param query: (str) HTTP query

        :return: (list)
        """
        if not query:
            query = "?pagesize=500"
        url = f"/mgmtconfig/v2/admin/customers/{self.customer_id}/privilegedConsoles{query}"
        response = self._obtain_all_results(url)

        return response

    def list_sra_consoles(self) -> list:
        """
        Method to obtain list of sra consoles from all application segments

        :return: (list)
        """
        sra_list = []
        app_segments = self.list_application_segments()
        for apps in app_segments:
            srap = apps.get("sraApps")
            if srap is not None:
                sra_list.extend(srap)

        return sra_list

    # Certificate Controller v2
    def list_issued_certificates(
        self,
        query: str = None,
    ) -> list:
        """
        Method to get all issued certificates

        :return: (list)
        """
        if not query:
            query = "?pagesize=500"  # TODO: Query never put into url.

        url = f"/mgmtconfig/v2/admin/customers/{self.customer_id}/certificate/issued"
        response = self._obtain_all_results(url)

        return response
