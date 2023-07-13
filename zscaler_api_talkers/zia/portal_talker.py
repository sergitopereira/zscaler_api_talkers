import json

import requests
from zscaler_api_talkers.helpers import HttpCalls, setup_logger, request_

from .helpers import _get_seed, _obfuscate_api_key
from http.cookies import SimpleCookie

logger = setup_logger(name=__name__)


class ZiaPortalTalker(object):
    """
    ZIA Portal API talker
    Documentation: https://help.zscaler.com/zia/zia-api/api-developer-reference-guide
    """

    def __init__(
        self,
        cloud_name: str,
        username: str = "",
        password: str = "",
    ):
        """
        Method to start the class

        :param cloud_name: (str) Example: zscalerbeta.net, zscalerone.net, zscalertwo.net, zscalerthree.net,
        zscaler.net, zscloud.net
        :param username: (str) Client ID
        :param password: (str) Secret Key
        """
        logger.warning("These API endpoints are unsupported and Zscaler can change at will and without notice.")
        self.cloud_name = cloud_name
        self.base_uri = f"https://admin.{cloud_name}/zsapi/v1"
        self.hp_http = HttpCalls(
            host=self.base_uri,
            verify=True,
        )
        self.j_session_id = None
        self.zs_session_code = None
        self.headers = None
        self.version = "0.1"
        if username and password:
            self.authenticate(
                username=username,
                password=password,
            )

    def authenticate(
            self,
            username: str = "",
            password: str = "",
            zsui_cookie: str = "",
            zsui_customcode: str = ""
    ):
        """
        Method to authenticate.

        :param username: (str) A string that contains the email ID of the API admin
        :param password: (str) A string that contains the password for the API admin
        :param zsui_cookie: (str) A string that contains the JSESSIONID cookie (optional)
        :param zsui_customcode: (str) A string that contains the ZS_CUSTOM_CODE value (optional)
        """
        if zsui_cookie and zsui_customcode:
            cookie = SimpleCookie()
            cookie.load(zsui_cookie)
            self.headers = {
                "Content-Type": "application/json",
                "Zs_custom_code": zsui_customcode,
            }
            self.j_session_id = cookie['JSESSIONID'].value
            self.zs_session_code = cookie['ZS_SESSION_CODE'].value
        else:
            timestamp, key = _obfuscate_api_key(
                _get_seed(url=f"https://admin.{self.cloud_name}")
            )
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
                headers={
                    "Accept": "application/json",
                },
            )
            if response.cookies.get("JSESSIONID"):
                self.j_session_id = response.cookies["JSESSIONID"]
            else:
                raise ValueError("Invalid Credentials")
            if response.cookies.get("ZS_SESSION_CODE"):
                self.zs_session_code = response.cookies["ZS_SESSION_CODE"]
                self.headers = {
                    "Content-Type": "application/json",
                    "ZS_CUSTOM_CODE": self.zs_session_code,
                }
            else:
                raise ValueError("Invalid API key")


    def add_dlp_engine(
        self,
        payload: dict = None,
        engine_expression: str = None,
        name: str = None,
        custom_dlp_engine: bool = True,
        predefined_engine_name: bool = None,
        description: str = None,
    ) -> requests.Response:
        """
        Method to create a DLP engine

        :param payload: (dict?)
        :param name: (str) Name of the DLP ENGINE
        :param engine_expression: (str) Engine Expression
        :param custom_dlp_engine: : (bool) True if custom DLP engine
        :param predefined_engine_name: (bool)
        :param description: (str) Description

        :return: requests.Response object
        """
        url = "/dlpEngines"
        if payload:
            payload = payload
        else:
            payload = {
                "EngineExpression": engine_expression,
                "CustomDlpEngine": custom_dlp_engine,
            }
            if predefined_engine_name:
                payload.update(PredefinedEngineName=predefined_engine_name)
            else:
                payload.update(Name=name)
            if description:
                payload.update(Description=description)
        response = self.hp_http.post_call(
            url=url,
            payload=payload,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response

    def update_dlp_engine(
        self,
        payload: json,
        dlp_id: int,
    ) -> requests.Response:
        """
        Method to update a DLP engine

        :param payload: (json) payload
        :param dlp_id: (int) ID

        :return: requests.Response object
        """
        url = f"/dlpEngines/{dlp_id}"
        response = self.hp_http.put_call(
            url=url,
            payload=payload,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response

    def list_pac_files(self) -> json:
        """
        Method to list PAC files

        :return: (json)
        """
        url = f"/pacFiles"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def add_pac_file(
        self,
        name: str,
        description: str,
        domain: str,
        pac_content: str,
        editable: bool = True,
        pac_url_obfuscated: bool = True,
    ) -> json:
        """
        Method to Add a PAC file

        :param name: (str) Name of the PAC
        :param description: (str) Description
        :param domain: (str) Domain
        :param pac_content: (str) PAC content
        :param editable: (bool) Default True
        :param pac_url_obfuscated: (bool) Default True

        :return: (json)
        """
        payload = {
            "name": name,
            "editable": editable,
            "pacContent": pac_content,
            "pacUrlObfuscated": pac_url_obfuscated,
            "domain": domain,
            "description": description,
            "pacVerificationStatus": "VERIFY_NOERR",
        }
        url = f"/pacFiles"
        response = self.hp_http.post_call(
            url=url,
            headers=self.headers,
            payload=payload,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_malware_policy(self) -> json:
        """
        Method to list Malware Policy.  Policy > Malware Protection > Malware Policy

        :return: (json)
        """
        url = f"/malwarePolicy"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_virus_spyware_settings(self) -> json:
        """
        Method to list virus, malware, adware and spyware settings.  Policy > Malware Protection > Malware Policy

        :return: (json)
        """
        url = f"/virusSpywareSettings"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_advanced_url_filtering_settings(self) -> json:
        """
        Method to list Advanced Policy settings.  Policy > URL & Cloud App Control > Advanced  Policy Settings

        :return: (json)
        """
        url = f"/advancedUrlFilterAndCloudAppSettings"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_subscriptions(self) -> json:
        """
        Method to list tenant subscriptions.  Administration > Company Profile > Subscriptions

        :return: (json)
        """
        url = f"/subscriptions"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_cyber_risk_score(self) -> json:
        """
        Method to list tenant subscriptions.  Administration > Company Profile > Subscriptions

        :return: (json)
        """
        url = f"/cyberRiskScore"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def add_user_groups(
        self,
        group_name,
    ) -> json:
        """
        Creates user groups

        :return: (json)
        """
        url = "/groups"
        payload = {"name": group_name}
        response = self.hp_http.post_call(
            url=url,
            headers=self.headers,
            payload=payload,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_saml_settings(self) -> json:
        """
        Method to list SAML settings.  Administration > Authentication Settings

        :return: (json)
        """
        url = f"/samlSettings"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_advanced_settings(self) -> json:
        """
        Method to list ZIA advanced settings.  Administration > Advanced Settings

        :return: (json)
        """
        url = f"/advancedSettings"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_idp_config(self) -> json:
        """
        Method to list ZIA idp configuration.  Administration > Authentication Settings > identity Providers

        :return: (json)
        """
        url = f"/idpConfig"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_icap_servers(self) -> json:
        """
        Method to list ZIA icap servers.  Administration > DLP incident Receiver > ICAP Settings

        :return: (json)
        """
        url = f"/icapServers"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_auth_settings(self) -> json:
        """
        Method to list ZIA auth settings.  Administration > Authentication Settings

        :return: (json)
        """
        url = f"/authSettings"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_saml_admin_settings(self) -> json:
        """
        Method to list ZIA auth settings.  Administration > Authentication Settings

        :return: (json)
        """
        url = f"/samlAdminSettings"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_eun(self) -> json:
        """
        Method to list ZIA End User Notification settings.  Administration > End User Notifications

        :return: (json)
        """
        url = f"/eun"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_admin_password_mgt(self) -> json:
        """
        Method to list ZIA Administrator Management password.  Administration > Administration Management

        :return: (json)
        """
        url = f"/passwordExpiry/settings"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_api_keys(self) -> json:
        """
        Method to list ZIA Administrator Management password.  Administration > Administration Management

        :return: (json)
        """
        url = f"/apiKeys"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def delete_group(
        self,
        group_id: int,
    ) -> requests.Response:
        """
        Method to delete a group given group id

        :param group_id: (int) Group id

        :return: requests.Response object
        """
        url = f"/groups/{group_id}"
        response = self.hp_http.delete_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response

    def delete_department(
        self,
        department_id: int,
    ) -> json:
        """
        Method to delete a group given department

        :param department_id: (int) Department id

        :return: requests.Response object
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/departments/{department_id}",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return result.json()

    def list_web_application_rules(self) -> json:
        """
        Method to list Cloud APP policies

        :return: (json)
        """
        url = "/webApplicationRules"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()
    def list_org_information(self) -> json:
        """
        Method to list org information
        :return: (json)
        """
        url="/orgInformation"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()
    def list_subscriptions(self) -> json:
        """
        Method to list org subscriptions
        :return: (json)
        """
        url="/subscriptions"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_advanced_threat_settings(self) -> json:
        """
        Method to list Advanced Threat Protection settings.  Policy > Advanced Threat Protection > Advanced Threats Policy

        :return: (json)
        """
        url = f"/advancedThreatSettings"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_ftp_settings(self) -> json:
        """
        Method to list FTP settings.  Policy > FTP Control

        :return: (json)
        """
        url = f"/ftpSettings"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_mobile_advance_threat_settings(self) -> json:
        """
        Method to list Mobile Advance Threat settings.  Policy > Mobile Malware Protection

        :return: (json)
        """
        url = f"/mobileAdvanceThreatSettings"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_nss_servers(self) -> json:
        """
        Method to list NSS Servers.  Administration > Nanolog Streaming Service

        :return: (json)
        """
        url = f"/nssServers"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_orginformation(self) -> json:
        """
        Method to list tenant Org Information.  Administration > Company Profile

        :return: (json)
        """
        url = f"/orgInformation"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_ssl_inspection_rules(self) -> json:
        """
        Method to list SSL Inspection rules.  Policy > SSL Inspection > SSL Inspection Policy

        :return: (json)
        """
        url = f"/sslInspectionRules"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_intermediate_ca_certificate(self) -> json:
        """
        Method to list SSL Inspection Intermediate CA Certificates.  Policy > SSL Inspection > Intermediate CA Certificates

        :return: (json)
        """
        url = f"/intermediateCaCertificate/lite"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_security_policy_audit_traffic_inspection(self) -> json:
        """
        Method to list the Traffic Inspection section within the Security Policy Audit Report. Analytics > Security Policy Audit Report

        :return: (json)
        """
        url = f"/securityPolicyAudit/trafficInspection"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_system_audit_report_gre_tunnel(self) -> json:
        """
        Method to list the GRE Tunnel recommendation within the System Audit Report. Analytics > System Audit Report

        :return: (json)
        """
        url = f"/configAudit/greTunnel"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_system_audit_report_pac_file(self) -> json:
        """
        Method to list the PAC File recommendation within the System Audit Report. Analytics > System Audit Report

        :return: (json)
        """
        url = f"/configAudit/pacFile"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def list_system_audit_report_ip_visibility(self) -> json:
        """
        Method to list the IP Visability recommendation within the System Audit Report. Analytics > System Audit Report

        :return: (json)
        """
        url = f"/configAudit/ipVisibility"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()

    def update_eun(self, **kwargs) -> json:
        """
        Method to update the EUN settings for a ZIA Tenant

        :return: (json)
        """
        url = "/eun"
        payload = kwargs
        response = self.hp_http.put_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            payload=payload
        )

        return response.json()

    def generic_post(self, url, **kwargs) -> json:
        """
        Generic POST method

        :return: (json)
        """
        url = url
        payload = kwargs
        response = self.hp_http.post_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            payload=payload
        )

        return response.json()

    def generic_put(self, url, **kwargs) -> json:
        """
        Generic PUT method

        :return: (json)
        """
        url = url
        payload = kwargs
        response = self.hp_http.put_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            payload=payload
        )

        return response.json()

    def generic_get(self, url) -> json:
        """
        Generic GET method

        :return: (json)
        """
        url = url
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            }
        )

        return response.json()

    def generic_delete(self, url) -> json:
        """
        Generic DELETE method

        :return: (json)
        """
        url = url
        response = self.hp_http.delete_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            }
        )

        return response.json()
