# Unofficial Zscaler API talkers

### ZIA API Talker
Python client to leverage  [Zscaler Internet Access API](https://help.zscaler.com/zia/api)

### ZPA API Talker
Python client to leverage [Zscaler Private Access API](https://help.zscaler.com/zpa/api-reference)

### ZCC API Talker

Python client to leverage Zscaler Client Connector API. ( Currently in Beta status)

# Installation

## Option1: Run within a Docker Container
``` bash
# Download Dockerfile
Linux:
curl -O https://raw.githubusercontent.com/sergitopereira/zscaler_api_talkers/sergiodevelop/Dockerfile
Windows:
wget -O Dockerfile https://raw.githubusercontent.com/sergitopereira/zscaler_api_talkers/sergiodevelop/Dockerfile 

# Build Image and Run Container
docker build -t zscaler_api_talkers .  
docker run -it zscaler_api_talkers bash

# Usage (program is in /zscaler_api_talkers/)
cd zscaler_api_talkers
```

## Option2: Run in a Python Virtual Environment

``` bash
* Create a virtual Environment:
  python3 -m venv .zs_api_talkers
* Activate virtual environment
  # Linux
  source .zs_api_talkers/bin/activate
  # Windows
  .\.zs_api_talkers\Scripts\activate
* Install Zscales API talkers
   pip install zscaler-api-talkers  
```

# Zscaler Secure Internet and SaaS Access SDK (zia_talker)

## Usage zia_talker
``` python
from zia_talker.zia_talker import ZiaTalker
zia=ZiaTalker('<Zscaler Cloud Name>')
zia.authenticate(apikey='API_KEY', username='USERNAME', password='PASSWORD')
zia.list_urlcategories()
a.list_users()
# To view all methods available
print(dir(a))
```

## Usage zia_talker with OAUTH2.0
``` python
from zia_talker.zia_talker import ZiaTalker
a=ZiaTalker('<Zscaler Cloud Name>', <Bear oauth2.0 token))
a.list_url_categorie.url_categories()
a.list_users()
# To view all methods available
print(dir(a))
```


# Zscaler Secure Private Access SDK (zpa_talker)

## Usage zpa_talker
``` python
from zpa_talker.zpa_talker import ZpaTalker
a=ZpaTalker('customerID')
a.authenticate(client_id='clientID',client_secret='clientSecret')
# To view all methods available
print(dir(a))
```
# Zscaler Client Connector SDK  (zcc_talker)

## Usage zcc_talker
``` python
from zcc_talker.zcc_talker import ZccTalker
a=ZccTalker('<Zscaler Cloud Name>')    
a.authenticate(clientid='clientID',secretkey='clientSecret')
a.list_devices('companyID')
a.list_OTP('companyID','user device id')
# To view all methods available
print(dir(a))
```

# Usage example

https://github.com/sergitopereira/zscaler_api_talkers#usage-example

# Bugs and enhancements

Feel free to open an issues using [Gihub Issues](https://github.com/sergitopereira/zscaler_api_talkers)


# Author

Sergio Pereira 

Zscaler Professional Services 



