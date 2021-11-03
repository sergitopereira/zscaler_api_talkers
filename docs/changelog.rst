v1.3 ( To be released 2021)
=========================
1. Added the following ZIA methods (by `Sergio Pereira <mailto:spereira@zscaler.com>`_)
  - List, add, delete network services
  - List, add, delete admin audit logs
  - Added delete ipSourceGroups and ipDestinationGroups
  - list  ipSourceGroups lite method
2. Updated install instructions

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