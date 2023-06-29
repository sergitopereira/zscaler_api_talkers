# Unofficial Zscaler API talkers

## API Talkers

### ZIA API Talker
A Python client to leverage [Zscaler Internet Access API](https://help.zscaler.com/zia/api)

The ZIA API talker is divided into two Class objects: ZiaTalker and ZiaPortalTalker.  ZiaTalker interacts 
with ZIA via the published APIs; whereas ZiaPortalTalker interacts with ZIA via the URLs presented in the Portal 
(aka, the ZIA configuration website).

### ZPA API Talker
Python client to leverage [Zscaler Private Access API](https://help.zscaler.com/zpa/api-reference)

The ZPA API talker is divided into two Class objects: ZpaTalker and ZpaPortalTalker.  ZpaTalker interacts 
with ZPA via the published APIs; whereas ZpaPortalTalker interacts with ZPA via the URLs presented in the Portal 
(aka, the ZPA configuration website).

### ZCC API Talker
Python client to leverage Zscaler Client Connector API. ( Currently in Beta status)

The ZCC API talker is accessed via the Class object named: ZccTalker.

## Installation

### Option 1: Run within a Docker Container
We provide two methods to build a Docker container.  Either using the code hosted on GitHub or the code published to PyPi.

#### GitHub Method
1. Download Dockerfile
   - Linux: `curl -O https://raw.githubusercontent.com/sergitopereira/zscaler_api_talkers/sergiodevelop/git_version.Dockerfile`
   - Windows: `wget -O Dockerfile https://raw.githubusercontent.com/sergitopereira/zscaler_api_talkers/sergiodevelop/git_version.Dockerfile` 
1. Build Image and Run Container
   1. `docker build -f git_version.Dockerfile -t zscaler_api_talkers .`
   1. `docker run -it zscaler_api_talkers bash`
1. Usage (program is in /zscaler_api_talkers/)
   - `cd zscaler_api_talkers`

#### PyPi Method
1. Download Dockerfile
   - Linux: `curl -O https://raw.githubusercontent.com/sergitopereira/zscaler_api_talkers/sergiodevelop/Dockerfile`
   - Windows: `wget -O Dockerfile https://raw.githubusercontent.com/sergitopereira/zscaler_api_talkers/sergiodevelop/Dockerfile` 
1. Build Image and Run Container
   1. `docker build -t zscaler_api_talkers .`
   1. `docker run -it zscaler_api_talkers bash`
1. Usage (program is in /zscaler_api_talkers/)
   - `cd zscaler_api_talkers`

### Option2: Run in a Python Virtual Environment
1. Create a virtual Environment: `python3 -m venv .zs_api_talkers`
1. Activate virtual environment: 
  - Linux: `source .zs_api_talkers/bin/activate`
  - Windows: `.\.zs_api_talkers\Scripts\activate`
1. Install Zscales API talkers: `pip install zscaler-api-talkers`


## Zscaler Secure Internet and SaaS Access SDK (zia_talker)

### Usage zia_talker
``` python
from zia_talker.zia_talker import ZiaTalker
zia=ZiaTalker('<Zscaler Cloud Name>')
zia.authenticate(apikey='API_KEY', username='USERNAME', password='PASSWORD')
zia.list_urlcategories()
zia.list_users()
# To view all methods available
print(dir(zia))
```

### Usage zia_talker with OAUTH2.0
``` python
from zia_talker.zia_talker import ZiaTalker
a=ZiaTalker('<Zscaler Cloud Name>', <Bear oauth2.0 token))
a.list_url_categorie.url_categories()
a.list_users()
# To view all methods available
print(dir(a))
```


## Zscaler Secure Private Access SDK (zpa_talker)

### Usage zpa_talker
``` python
from zpa_talker.zpa_talker import ZpaTalker
a=ZpaTalker('customerID')
a.authenticate(client_id='clientID',client_secret='clientSecret')
# To view all methods available
print(dir(a))
```

## Zscaler Client Connector SDK  (zcc_talker)

### Usage zcc_talker
``` python
from zcc_talker.zcc_talker import ZccTalker
a=ZccTalker('<Zscaler Cloud Name>')    
a.authenticate(clientid='clientID',secretkey='clientSecret')
a.list_devices('companyID')
a.list_OTP('companyID','user device id')
# To view all methods available
print(dir(a))
```

## Usage examples
  - https://github.com/sergitopereira/zscaler_api_talkers#usage-example
  - https://github.com/sergitopereira/zscaler_api_talkers/blob/main/example.py

## Bugs and enhancements
Feel free to open an issues using [Gihub Issues](https://github.com/sergitopereira/zscaler_api_talkers)

## Author
Sergio Pereira: Zscaler Professional Services 
