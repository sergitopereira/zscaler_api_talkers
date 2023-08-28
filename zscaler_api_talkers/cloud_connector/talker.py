import json
import pdb
import time
import requests
from zscaler_api_talkers.helpers.http_calls import HttpCalls
from zscaler_api_talkers.helpers.logger import setup_logger

from zscaler_api_talkers.zia.helpers import _obfuscate_api_key

logger = setup_logger(name=__name__)

class CloudConnectorTalker(object):
    """
    Cloud and Branch Connector Talker
    Documentation:
    https://help.zscaler.com/cloud-branch-connector/about-zscaler-cloud-branch-connector-api
    """

    def __init__(
        self,
        cloud_name: str,
        api_key: str = "",
        username: str = "",
        password: str = "",
    ):
        """
        Method to start the class

        :param cloud_name: (str) Example: zscalerbeta.net, zscalerone.net, zscalertwo.net, zscalerthree.net,
            zscaler.net, zscloud.net
        """
        self.base_uri = f"https://connector.{cloud_name}/api/v1"
        self.hp_http = HttpCalls(
            host=self.base_uri,
            verify=True,
        )
        self.cookies = None
        self.headers = None
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
        url = "/auth"
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
        url = "/auth"
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
        url = "/auth"
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
        url = "/ecAdminActivateStatus"
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
        url = "/ecAdminActivateStatus/activate"
        response = self.hp_http.put_call(
            url,
            payload={},
            cookies=self.cookies,
            error_handling=True,
        )

        return response.json()
    
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
        isDefaultAdmin: bool = False,
        disabled: bool = False,
        isDeprecatedDefaultAdmin: bool = False,
        isAuditor: bool = False,
        isPasswordLoginAllowed: bool = False,
        isSecurityReportCommEnabled: bool = False,
        isServiceUpdateCommEnabled: bool = False,
        isProductUpdateCommEnabled: bool = False,
        isPasswordExpired: bool = False,
        isExecMobileAppEnabled: bool = False,
        newLocationCreateAllowed: bool = False,) -> json:
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
               :param isDefaultAdmin: boolean. Indicates whether this is a default admin. default: False.
               :param disabled: boolean. If admin accounts is disabled. default: False.
               :param isDeprecatedDefaultAdmin: boolean. Indicates whether this admin is deletable. If true, this admin is read-only and not deletable. default: False.
               :param isAuditor:boolean. Indicates if user is auditor. default: False.
               :param isPasswordLoginAllowed: boolean. If password login is allowed. default: False.
               :param isSecurityReportCommEnabled: boolean. Communication for Security Report is enabled. default: False.
               :param isServiceUpdateCommEnabled: boolean. Communication setting for Service Update. default: False.
               :param isProductUpdateCommEnabled: boolean. Communication setting for Product Update. default: False.
               :param isPasswordExpired: boolean. Expire password to force user to change password on logon. default: False.
               :param isExecMobileAppEnabled: boolean. Indicates whether or not Executive Insights App access is enabled for the admin. default: False.
               :param newLocationCreateAllowed: boolean. Indicates whether user is allowed to create a new location. default: False.
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
            "isDefaultAdmin": isDefaultAdmin,
            "disabled": disabled,
            "isDeprecatedDefaultAdmin": isDeprecatedDefaultAdmin,
            "isAuditor": isAuditor,
            "isPasswordLoginAllowed": isPasswordLoginAllowed,
            "isSecurityReportCommEnabled": isSecurityReportCommEnabled,
            "isServiceUpdateCommEnabled": isServiceUpdateCommEnabled,
            "isProductUpdateCommEnabled": isProductUpdateCommEnabled,
            "isPasswordExpired": isPasswordExpired,
            "isExecMobileAppEnabled": isExecMobileAppEnabled,
            "newLocationCreateAllowed": newLocationCreateAllowed
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
        role_id: int = None,
    ) -> json:
        """
        Gets a name and ID dictionary of al admin roles

        :param role_id: (int) 

        :return: (json)
        """
        if role_id:
            url = f"/adminRoles/{role_id}"
        else:
            url = "/adminRoles"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()
    
    # Cloud & Branch Connector Groups
    def list_cloud_branch_connector_groups(self,
                                           group_id: int = None,
                                           vm_id: int = None,
                                           ) -> json:
        """
        Gets a name and ID dictionary of all Connector Groups and VMs

        :param group_id: Integer. Cloud or Branch Connector Group ID
        :param vm_id: Integer. VM ID
        :return: (json)
        """
        if group_id and vm_id:
            url = f"/ecgroup/{group_id}/vm/{vm_id}"
        elif group_id:
            url = f"/ecgroup/{group_id}"
        else:
            url = "/ecgroup"
        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,           
        )

        return response.json()
    
    def delete_cloud_branch_connector_vm(
            self,
            group_id: int = None,
            vm_id: int = None,
    ) -> requests.Response:
        """
        Deletes a VM specified by Cloud or Branch Connector group ID and VM ID.

        :param group_id: Integer. Cloud or Branch Connector Group ID
        :param vm_id: Integer. VM ID
        :return: (requests.Response)
        """
        url = f"/ecgroup/{group_id}/vm/{vm_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response

    # Location Management
    def list_locations(
        self,
        location_id: int = None,
    ) -> json:
        """
        Gets locations only, not sub-locations. When a location matches the given search parameter criteria Sub-Locations are 
        included.

        :param location_id: (int) Location id

        :return: (json)
        """
        url = "/location"
        if location_id:
            url = f"/location/{location_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()
    
    def list_location_templates(
            self,
            template_id: int = None,
    ) -> json:
        """
        Gets location template. When a temaplte matches the given search parameter only a specific temaplte is returned
        
        :param template_id: int. Location templateID.
        
        :return: JSON
        """
        url = "/locationTemplate"
        if template_id:
            url = f"/locationTemplate/{template_id}"

        response = self.hp_http.get_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,
        )

        return response.json()

    def add_location_template(
            self,
            name: str,
            desc: str = None,
            template: list = None,
            editable: bool = True,
        ) -> json:
        """
        Creates a location template
        
        :param    name: str, Name of Cloud & Branch Connector location template.
        :param    desc: str, Description of Cloud & Branch Connector location template.
        :param    template: list, List of Template Details.
        :param    editable: bool = True, Whether Cloud & Branch Connector location template is editable.

        :return:       
        """
        url="/locationTemplate"
        payload = {
            "name": name,
            "desc": desc,
            "template": template,
            "editable": editable,            
        }
        response = self.hp_http.post_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,            
        )

        return response.json()
    
    def update_location_template(
            self,
            template_id: int,
            name: str = None,
            desc: str = None,
            template: list = None,
            editable: bool = True,
    ) -> json:
        """
        Updates the location template specified by the location template ID.

        :param templateid: int, ID of the location template.
        :param name: str, Name of Cloud & Branch Connector location template.
        :param desc: str, Description of Cloud & Branch Connector location template.
        :param template: list, List of Template Details to be updated. Unlisted Parameters will be reset to default values.
        :param editable: bool, Whether Cloud & Branch Connector location template is editable.

        :return: (json)
        """
        url = f"/locationTemplate/{template_id}"
        payload = {
            "name": name,
            "desc": desc,
            "template": template,
            "editable": editable,            
        }
        response = self.hp_http.put_call(
            url,
            payload=payload,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,            
        )

        return response.json()
    
    def delete_location_template(
            self,
            template_id: int,
    ) ->json:
        """
        Deletes the location template specified by the location template ID.
        
        :param template_id: int, ID of the location template

        :return: json
        """
        url = f"/locationTemplate/{template_id}"
        response = self.hp_http.delete_call(
            url,
            cookies=self.cookies,
            error_handling=True,
            headers=self.headers,               
        )

        return response