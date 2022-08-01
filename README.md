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

# ZIA Talker

## Usage zia_talker
``` python
from zia_talker.zia_talker import ZiaTalker
a=ZiaTalker('zsapi.<Zscaler Cloud Name>')
a.authenticate('APIKEY,'admin@<Zscaler Cloud Name>', 'password')
a.url_categories()
a.list_users()
# To view all methods available
print(dir(a))
```

# ZPA Talker

## Usage zpa_talker
``` python
from zpa_talker.zpa_talker import ZpaTalkerPublic as ZpaTalker
a=ZpaTalker('customerID')
a.authenticate('clientID','clientSecret')
# To view all methods available
print(dir(a))
```
# ZCC talker

## Usage zcc_talker
``` python
from zcc_talker.zcc_talker import ZccTalker
a=ZccTalker('cloud')    
a.authenticate('clientID','clientSecret')
a.list_devices('companyID')
a.list_OTP('companyID','user device id')
# To view all methods available
print(dir(a))
```

# Usage example

https://github.com/sergitopereira/zscaler_api_talkers#usage-example

# Bugs and enhancements

Feel free to open an issues using [Gihub Issues](https://github.com/sergitopereira/zscaler_api_talkers/issues)


# Author

Sergio Augusto Pereira Alarcon

Zscaler Professional Services 



