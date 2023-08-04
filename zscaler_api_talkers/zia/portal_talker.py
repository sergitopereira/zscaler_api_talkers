import json
from http.cookies import SimpleCookie

import requests

from zscaler_api_talkers.helpers import HttpCalls, request_, setup_logger

from .helpers import _get_seed, _obfuscate_api_key

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
        logger.warning(
            "These API endpoints are unsupported and Zscaler can change at will and without notice."
        )
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
        zsui_custom_code: str = "",
    ):
        """
        Method to authenticate.

        :param username: (str) A string that contains the email ID of the API admin
        :param password: (str) A string that contains the password for the API admin
        :param zsui_cookie: (str) A string that contains the JSESSIONID cookie (optional)
        :param zsui_custom_code: (str) A string that contains the ZS_CUSTOM_CODE value (optional)
        """
        if zsui_cookie and zsui_custom_code:
            cookie = SimpleCookie()
            cookie.load(zsui_cookie)
            self.headers = {
                "Content-Type": "application/json",
                "Zs_custom_code": zsui_custom_code,
            }
            self.j_session_id = cookie["JSESSIONID"].value
            self.zs_session_code = cookie["ZS_SESSION_CODE"].value
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
        pac_commit_message: str,
        editable: bool = True,
        pac_url_obfuscated: bool = True,
        pac_version_status: str = "STAGE",
        pac_verification_status: str = "VERIFY_NOERR"
    ) -> json:
        """
        Method to Add a PAC file
        :param name: (str) Name of the PAC
        :param description: (str) Description
        :param domain: (str) Domain
        :param pac_content: (str) PAC content
        :param pac_commit_message: (str) PAC commit message
        :param editable: (bool) Default True
        :param pac_url_obfuscated: (bool) Default True
        :param pac_version_status: (str) Default VERIFY_NOERR
        :return: (json)
        """
        payload = {
            "name": name,
            "editable": editable,
            "pacContent": pac_content,
            "pacUrlObfuscated": pac_url_obfuscated,
            "domain": domain,
            "description": description,
            "pacCommitMessage": pac_commit_message,
            "pacVerificationStatus": pac_verification_status,
            "pacVersionStatus":pac_version_status,

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

    def update_virus_spyware_settings(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Update Virus Spyware Settings

        :param data: (dict) Dict of Virus Spyware Settings configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="put",
            url=f"{self.base_uri}/virusSpywareSettings",
            json=data,
            **kwargs,
        )

        return result

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

    def update_saml_admin_settings(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Update SAML Admin Settings

        :param data: (dict) Dict of SAML Admin Settings configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="put",
            url=f"{self.base_uri}/samlAdminSettings",
            json=data,
            **kwargs,
        )

        return result

    def upload_saml_admin_settings_certificate(
        self,
        filename: str,
        certificate: str,
        **kwargs,
    ) -> requests.Response:
        """
        Upload Certificate for SAML Admin

        :param filename: (str) Name of certificate
        :param certificate: (str) X509 encoded certificate

        :return: (requests.Response Object)
        """
        file = [
            (
                "fileUpload",
                (
                    filename,
                    certificate,
                    "application/x-x509-ca-cert",
                ),
            )
        ]
        headers = self.headers
        headers.pop("Content-Type")
        result = request_(
            method="post",
            url=f"{self.base_uri}/samlAdminSettings/uploadCert/text",
            files=file,
            headers=headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

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
    ) -> requests.Response:
        """
        Method to delete a group given department

        :param department_id: (int) Department id

        :return: (requests.Response object)
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

        return result

    def delete_admin_role(
        self,
        role_id,
        **kwargs,
    ) -> requests.Response:
        """
        Delete an Admin Role.
        Note: Deletion will fail if there are still users assigned to this role.

        :param role_id: (int) ID of the role

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/adminRoles/{role_id}",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def add_admin_role(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Create an Admin Role

        :param data: (dict) Dict of Admin Role configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="post",
            url=f"{self.base_uri}/adminRoles",
            json=data,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

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
        url = "/orgInformation"
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
        Method to list the IP Visibility recommendation within the System Audit Report. Analytics > System Audit Report

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

    def update_eun(
        self,
        **kwargs,
    ) -> json:
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
            payload=payload,
        )

        return response.json()

    def generic_post(
        self,
        url,
        **kwargs,
    ) -> json:
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
            payload=payload,
        )

        return response.json()

    def generic_put(
        self,
        url,
        **kwargs,
    ) -> json:
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
            payload=payload,
        )

        return response.json()

    def generic_get(
        self,
        url,
    ) -> json:
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
            },
        )

        return response.json()

    def generic_delete(
        self,
        url,
    ) -> json:
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
            },
        )

        return response

    def delete_web_application_rule(
        self,
        rule_id: int,
        rule_type: str,
        **kwargs,
    ) -> requests.Response:
        """
        Delete Web Application Rule

        :param rule_id: (int) ID of Web Application Rule.
        :param rule_type: (str) Type of rule.

        :return: (requests.Response object)
        """
        parameters = {"type": rule_type}
        result = request_(
            method="delete",
            url=f"{self.base_uri}/webApplicationRules/{rule_id}",
            params=parameters,
            **kwargs,
        )

        return result

    def delete_admin_user(
        self,
        user_id: int,
        **kwargs,
    ) -> requests.Response:
        """
        Delete Admin User

        :param user_id: (int) ID of user.

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/adminUsers/{user_id}",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def add_admin_user(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Create an Admin User

        :param data: (dict) Dict of Admin User configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="post",
            url=f"{self.base_uri}/adminUsers",
            json=data,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def update_admin_user(
        self,
        data: dict,
        user_id: int,
        **kwargs,
    ) -> requests.Response:
        """
        Update an Admin User

        :param data: (dict) Dict of Admin Role configuration.
        :param user_id: (int)  ID of user.

        :return: (requests.Response object)
        """
        result = request_(
            method="put",
            url=f"{self.base_uri}/AdminUsers/{user_id}",
            json=data,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def update_advanced_threat_settings(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Update an Advanced Threat Settings

        :param data: (dict) Dict of Advanced Threat Settings configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="put",
            url=f"{self.base_uri}/advancedThreatSettings",
            json=data,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def add_api_key(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        Generate an API Key

        :return: (requests.Response object)
        """
        result = request_(
            method="post",
            url=f"{self.base_uri}/apiKeys/generate",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def update_api_key(
        self,
        data: dict,
        api_key_id: int,
        **kwargs,
    ) -> requests.Response:
        """
        Update an API Key

        :param data: (dict) Dict of API Key configuration.
        :param api_key_id: (int) ID of API Key

        :return: (requests.Response object)
        """
        result = request_(
            method="put",
            url=f"{self.base_uri}/apiKeys/{api_key_id}",
            json=data,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def delete_api_key(
        self,
        api_key_id: int,
        **kwargs,
    ) -> requests.Response:
        """
        Delete API Key

        :param api_key_id: (int) ID of API Key.

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/apiKeys/{api_key_id}",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def update_auth_settings(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Update an Auth Setting

        :param data: (dict) Dict of Auth Settings configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="put",
            url=f"{self.base_uri}/authSettings",
            json=data,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def list_eusa_status(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        List the configured EUSA Status

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/eusaStatus/latest",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def add_eusa_status(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Create an EUSA Status

        :param data: (dict) Dict of EUSA Status configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/eusaStatus",
            json=data,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def list_file_type_rule(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        List the configured File Type Rules

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/fileTypeRules",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def delete_file_type_rule(
        self,
        rule_id: int,
        **kwargs,
    ) -> requests.Response:
        """
        Delete File Type Rule

        :param rule_id: (int) ID of File Type Rule.

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/fileTypeRules/{rule_id}",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def list_firewall_dns_rule(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        List the configured Firewall DNS Rules

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/firewallDnsRules",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def delete_firewall_dns_rule(
        self,
        rule_id: int,
        **kwargs,
    ) -> requests.Response:
        """
        Delete Firewall DNS Rule

        :param rule_id: (int) ID of Firewall DNS Rule.

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/firewallDnsRules/{rule_id}",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def list_firewall_ips_rule(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        List the configured Firewall IPS Rules

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/firewallIpsRules",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def list_firewall_network_settings(
        self,
        **kwargs,
    ) -> json:
        """
        List the configured Firewall IPS Rules

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/firewallNetworkSettings",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result.json()
    def delete_firewall_ips_rule(
        self,
        rule_id: int,
        **kwargs,
    ) -> requests.Response:
        """
        Delete Firewall IPS Rule

        :param rule_id: (int) ID of Firewall IPS Rule.

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/firewallIpsRules/{rule_id}",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def upload_idp_config_certificate(
        self,
        file: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Upload Certificate file for IDP Config

        :param file: (dict) Formatted dict for file upload.

        :return: (requests.Response Object)
        """
        headers = self.headers
        headers.pop("Content-Type")
        result = request_(
            method="post",
            url=f"{self.base_uri}/idpConfig/uploadCert",
            files=file,
            headers=headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def add_idp_config_bearer_token(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        Create Bearer Token

        :return: (requests.Response Object)
        """
        result = request_(
            method="post",
            url=f"{self.base_uri}/ipdConfig/generateBearerToken",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def update_idp_config(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Update an IDP Config

        :param data: (dict) Dict of IDP Config configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="put",
            url=f"{self.base_uri}/idpConfig/{data['id']}",
            json=data,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )
        return result

    def add_idp_config(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        result = request_(
            method="post",
            url=f"{self.base_uri}/idpConfig",
            json=data,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )
        return result

    def update_malware_policy(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Update Malware Policy

        :param data: (dict) Dict of Malware Policy configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="put",
            url=f"{self.base_uri}/malwarePolicy",
            json=data,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def update_remote_assistance(
        self,
        data: dict,
        **kwargs,
    ) -> requests.Response:
        """
        Update Remote Assistance

        :param data: (dict) Dict of Remote Assistance configuration.

        :return: (requests.Response object)
        """
        result = request_(
            method="put",
            url=f"{self.base_uri}/remoteAssistance",
            json=data,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def list_ssl_inspection_rule(
        self,
        **kwargs,
    ) -> requests.Response:
        """
        List the configured SSL Inspection Rules

        :return: (requests.Response object)
        """
        result = request_(
            method="get",
            url=f"{self.base_uri}/sslInspectionRules",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result

    def delete_ssl_inspection_rule(
        self,
        rule_id: int,
        **kwargs,
    ) -> requests.Response:
        """
        Delete SSL Inspection Rule

        :param rule_id: (int) ID of SSL Inspection Rule.

        :return: (requests.Response object)
        """
        result = request_(
            method="delete",
            url=f"{self.base_uri}/sslInspectionRules/{rule_id}",
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
            **kwargs,
        )

        return result
    def list_casb_tenat(self) -> json:
        """
        Method to SaaS Application Tenants

        :return: (json)
        """
        url = f"/casbTenant?page1&pagesize=100"
        response = self.hp_http.get_call(
            url=url,
            headers=self.headers,
            cookies={
                "JSESSIONID": self.j_session_id,
                "ZS_SESSION_CODE": self.zs_session_code,
            },
        )

        return response.json()