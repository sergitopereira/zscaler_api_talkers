v3.10 (February)
=========================
Added zpa_portaltalker library:(by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Added zpa methods update_application_segment, delete_application_segment and list_issued_certificates

v3.9 (December)
=========================
Fixed bug for ZPA list segment_group method.

v3.8 ( NOVEMBER)
=========================
Fixed bug for return response of ZIA method add_security_blacklistUrls (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

v3.7 ( OCTOBER)
=========================
Updated add_url_categories method to support Custom IP Ranges  and IP Ranges Retaining Parent Category (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
Updated method add_ipDestinationGroups to support domain option due to 6.2 release
Added method to add PAC files

v3.6 ( AUGUST 2022)
=========================
Added zia_portaltalker library:(by `Sergio Pereira <mailto:spereira@zscaler.com>`_)

Updated ZPA talker. The following methods were added: (by `Kevin Gilmor <mailto:kgilmor@zscaler.com>`_)
list_privileged_consoles
list_sra_consoles

v3.5 ( AUGUST 2022)
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
