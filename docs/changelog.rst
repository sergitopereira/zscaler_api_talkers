v6.2.0 (January 2024)
=========================
Fix: Bug Fix with response of ZiaTalker.delete_web_dlp_rules method  (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Fix: Bug Fix with response of ZiaTalker.list_static_ip method  (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v6.1.2 (December 2023)
=========================
Feat: Updated add_firewall_filtering_rules to support network service groups to ZiaTalker (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v6.1.1 (December 2023)
=========================
Feat: Added method to list_network_service_groups()  and list_network_service_groups_lite() to ZiaTalker (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v6.1.0 (October 2023)
=========================
Feat: Added cloud_connector API Talker for Cloud and Branch Connector (by `Dominic Schimanski <mailto:dschimanski@zscaler.com>)
Feat: Added Method to update APP connectors (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Fix: Proper defaults for ZIA __init__() attributes.  (by `Dax Mickelson <mailto:dmickelson@zscaler.com>`_)
Fix: All instead of Any for ZIA username/password/api_key auth method.  (by `Dax Mickelson <mailto:dmickelson@zscaler
.com>`_)
Feat: Add warning message about needing to auth if not done during ZIA __init__().  (by `Dax Mickelson
<mailto:dmickelson@zscaler.com>`_)
Feat: Add warning message about needing to auth if not done during ZIA __init__().  (by `Dax Mickelson
<mailto:dmickelson@zscaler.com>`_)
Feat: Updated main http_call helper to perform exponential backoff retries (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v6.0.0 (August 2023)
=========================
Fix: Removed unsupported ZIA, ZPA and ZDX Portal Talkers from this SDX (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v5.0.1 (August 2023)
=========================
Fet: Added method to list CASB tenants Portal Talker (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Fix: Migrate Portal Talker generic_delete to return bare response (by `Ryan Ulrick <mailto: rulrick@zscaler.com>`_)

v5.0.0 (July 2023)
=========================
Feat: Add list_api_key() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add add_api_key() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add update_api_key() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_api_key() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add list_application() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_application() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add list_application_group() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_application_group() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add list_assistant_group() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_assistant_group() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add list_clientless_certificate() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_clientless_certificate() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add list_role() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_role() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add add_role() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add add_search_suffix() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_server() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_server_group() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add add_support_access() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add add_admin_user() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_admin_user() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add update_admin_user() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add list_user_portal() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_user_portal() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_web_application_rule() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add update_virus_spyware_settings() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add list_ssl_inspection_rule() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_ssl_inspection_rule() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add update_saml_admin_settings() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add upload_saml_admin_settings_certificate() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add update_remote_assistance() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add list_network_services_lite() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add update_malware_policy() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add add_idp_config_bearer_token() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add upload_idp_config_certificate() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add update_idp_config() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add add_idp_config() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add list_firewall_ips_rule() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_firewall_ips_rule() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add list_firewall_dns_rule() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_firewall_dns_rule() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add list_file_type_rule() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_file_type_rule() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Docs: Update/Add docstrings (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add list_eusa_status() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add add_eusa_status() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add update_auth_settings() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add add_api_key() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add update_api_key() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_api_key() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add update_advanced_threat_settings() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add add_admin_user() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add delete_admin_user() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Feat: Add update_admin_user() (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Fix: Resolved issue with ZiaPortal Talker Cookie parsing (by `Patrick de Niet`)
Feat: Added additional methods to ZiaPortal Talker (by `Patrick de Niet`)
Feat: Added several methods to ZiaPortal Talker (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Feat: ZiaPortal Talker now accepts cookies as authentication  (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Fix: Renamed ZccTalker to ClientConnectorTalker. (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Style: Rename files and folders to reduce redundancies. (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Fix: Add list object for adding url categories in ZiaTalker (by `Ryan Ulrick <mailto: rulrick@zscaler.com>`_)
Fix: Add kwargs for url filtering rule to allow for dictionary pass in (by `Ryan Ulrick <mailto: rulrick@zscaler.com>`_)
Feat: Added method to update pre-exisiting url filtering rule (by `Ryan Ulrick <mailto: rulrick@zscaler.com>`_)
Fix: Fixed add_rule_label method in ZiaTalker (by `Ryan Ulrick <mailto: rulrick@zscaler.com>`_)
Feat: Add delete_rule_label method for ZiaTalker (by `Ryan Ulrick <mailto: rulrick@zscaler.com>`_)
Feat: Add generic PUT, POST, GET, DELETE calls for ZiaPortalTalker (by `Ryan Ulrick <mailto: rulrick@zscaler.com>`_)
Fix: Remove json method from Generic DELETE call in ZiaPortalTalker (by `Ryan Ulrick <mailto: rulrick@zscaler.com>`_)
Fix: Correct typehinting for delete_url_category method arguments (by `Ryan Ulrick <mailto: rulrick@zscaler.com>`_)
Feat: ZIATalker method add_adminUsers to add Administrator.(by`BrijeshShingadia<mailto:bshingadia@zscaler.com>`_)
Feat: update_segment_group,update_connector_group,delete_connector_group,add_connector_group methods to ZPATalker.(by`BrijeshShingadia<mailto:bshingadia@zscaler.com>`_)
Fix: ZpaTalker authenticate method prints the auth-token in the terminal which is a security concern (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Fix: ClientConnectorTalker download_service_status method renamed to list_download_service_status  and fixed response type return by api (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Fix: ClientConnectorTalker force_remove_devices and remove_devices method to remove company_id parameter and add userName and clientConnectorVersion parameters. (by`BrijeshShingadia<mailto:bshingadia@zscaler.com>`_)
Fix: Removed company id requirement from zscaler client connector methods (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v4.1.1 ( July 2023 )
=========================
Fix: init_py updated to include missing zscaler_api_talker from the import statements (by 'Gurnaib Brar <mailto: gbrar@zscaler.com>'_)
Fix: ZiaTalker list_department method now returns all departments  (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Fix: Updated contribution guidelines (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
PEP8, docstrings, typehints, misc restructuring code (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Added the ability to "authenticate" during object instantiation (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)


v4.1.0 ( June 2023 )
=========================
Added ZDX Portal Talker (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Added my logger and helper methods (goes along with ZDX Portal Talker) (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Worked on init to advertise methods/classes that should be publicly accessible. (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Created pip_version.Dockerfile to provide method to use pip version in Docker. (by `Dax Mickelson <mailto:
dmickelson@zscaler.com>`_)
Moved working python code into sub-dir to isolate from other repo uses. (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)
Built working Poetry build structure (renamed previous files to *.old). (by `Dax Mickelson <mailto: dmickelson@zscaler.com>`_)

Updated readme.md for consistency in examples (by `Ryan Ulrick <mailto:rulrick@zscaler.com>`_)
Began adding type hinting to ZIA Talker methods (by `Ryan Ulrick <mailto:rulrick@zscaler.com>`_)
PEP8 Linting for zia_talker.py (by `Ryan Ulrick <mailto:rulrick@zscaler.com>`_)
Refactored API Key Obfuscation for increased performance on repeated runs (by `Ryan Ulrick <mailto:rulrick@zscaler.com>`_)
Added add_rule_label method to zia_talker (by `Ryan Ulrick <mailto:rulrick@zscaler.com>`_)
Fix: ZPA list_segment_group paging  (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Fix: Added **kwargs to ziatalker add_FirewallFilteringRules method to prevent erroring when replicating configuration. (by `Ryan Ulrick <mailto:rulrick@zscaler.com>`_)
Added Method to zcc_talker to download downloadServiceStatus (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Added Method to zia_portaltalker to list Cloud App policies (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v4.0.2 ( APRIL 2023 )
=========================
Replaced deprecated ZPA method list_global_policy_id method with list_policySet (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Added new parameters to add_application_segment method (by `Brijesh Shingadia <mailto:bshingadia@zscaler.com>`_)

v4.0.1 ( APRIL 2023 )
=========================
Added method to ZiaPortalTalker to delete user groups (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Added method to ZiaPortalTalker to delete deparments (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Updated readme.doc

v4.0 ( APRIL 2023 )
=========================
Zia_talker updated to support OAuth 2.0 Authentication (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
ZCC talker method remove devices added osType attribute (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Added the following methods to ZIA Portal Talker:
  list_malwarePolicy, list_virusSpywareSettings, list_advancedUrlFilteringSettings, list_subscriptions, list_cyberRiskScore
zpa_portaltalker moved under zpa_talker
ZpaTalkerPublic library renamed to ZpaTalker
Updated  README.md

v3.10 ( February 2023)
=========================
Added zpa_portaltalker library:(by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Added zpa methods update_application_segment, delete_application_segment and list_issued_certificates

v3.9 ( December 2022)
=========================
Fixed bug for ZPA list segment_group method.

v3.8 ( November 2022)
=========================
Fixed bug for return response of ZIA method add_security_blacklistUrls (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v3.7 ( October 2022)
=========================
Updated add_url_categories method to support Custom IP Ranges  and IP Ranges Retaining Parent Category (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Updated method add_ipDestinationGroups to support domain option due to 6.2 release
Added method to add PAC files

v3.6 ( August 2022)
=========================
Added zia_portaltalker library:(by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

Updated ZPA talker. The following methods were added: (by `Kevin Gilmor <mailto:kgilmor@zscaler.com>`_)
list_privileged_consoles
list_sra_consoles

v3.5 ( August 2022)
=========================
Added  list_policies to zpa_talker (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Updated doc strings with new zia and zpa API Developer & Reference guide
Updated zpa methods to iterate through all pages in order to return all objects and not only objects from page 1
Added to zia_talker
validateDlpPattern
add|delete dlpNotificationTemplates


v3.4 ( July 2022)
=========================
Fixed API rate limit for ZIA (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v3.3 ( July 2022)
=========================
Updated ZIA talker. The following methods were added:(by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
 list_dlpEngines
 list_dlpExactDataMatchSchemas
 list_dlpNotificationTemplates
 list_icapServer
 list_idmprofile
 list_webDlpRules
 delete_webDlpRules

v3.2 ( July 2022)
=========================
Updated ZCC talker. The following methods were added:(by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
remove_devices: Marks the device for removal ( Device removal pending)
force_remove_devices" Marks the device for removal  and also signals the cloud to invalidate the user's session

v3.1 ( July 2022)
=========================
Updated setup.conf for pypi installation using pip install zscaler-api-talkers

v3 ( July 2022)
=========================
1. Updated zia_talker url_lookup method (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
2. Updated zpa_talker method add_application_segment string docs (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v2.2 ( April 2022)
=========================
1. Updated zzc_talker README instructions and doc string (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v2.0 ( April 2022)
=========================
1. Added Zscaler Client Connector API talker (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v1.5 ( March 2022)
=========================
1. Fixed typos in doc strings (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
2. Added Several zia_methods  (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
    list devices
    list device groups
    Generic update and add calls
3. Added method to iterate all pages of ZPA responses (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v1.4 ( December 2021)
=========================
1. Added the following ZIA methods (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
  - List admin users and roles
2. Updated readme file with docker instructions (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v1.3 ( November 2021)
=========================
1. Added the following ZIA methods (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
  - List, add, delete network services
  - List, add, delete admin audit logs
  - Added delete ipSourceGroups and ipDestinationGroups
  - Added delete static IP Method
  - list  ipSourceGroups lite method
  - added a generic update call
2. Updated install instructions
3. Added the following ZPA methods (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
  - list configured servers
  - list_segment_group
  - list_connector
  - delete_bulk_connector
  - list_connector_group
  - list_browser_access_cert
  - list_customer_version_profile
  - list_cloud_connector_group
4. Updated list_idP method url to v2. (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
5. Updated list_saml_attributes method url to v2 (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v1.2 ( September 2021)
=========================
1. Added the following ZIA methods (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
  - List, add, delete Cloud Firewall Policies
2. Updated instructions of zpa usage(by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
3. Added the following ZIA methods (by `Hasan Faraz <mailto:hfaraz@zscaler.com>`_)
  - DLP Dictionaries
  - List, add, delete DLP Dictionaries
4. Fixed bug for ZIA list sub locations (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v1.1 ( July 2021)
=========================
1. Updated README file (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
   - Updated instructions of zpa usage
   - Added method to create access policy
   - Added method to obtain VPN credentials in zia_talker
   - Added method to add static IP address in zia_talker

2. Updated zpa_talker for SAML method (by `Rohit Luthra <mailto:rluthra@zscaler.com>`_)
    - Added method for SAML Attribute pull from the customer portal
    - Added method for fetching the global policy Global policy ID

v1.0 ( June 2021)
=========================
1. Released Version 1.0 (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
   - zia_talker: Class to consume ZIA public API
   - zpa_talker: Class to consume ZPA public API
   - helpers
        -http_calls: Class to perform HTTP calls
   - Docs
         -Changelog.rst: Tracks changes made
         -Contributing.rst: Contribution guidelines
   - requirements.txt: Repository packages dependency
