# Zscaler API talkers

ZIA API Talker

ZPA API Talker

Zscaler Client Connector Portal Talker

## Option1: Run within a Docker Container
```bash
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

# Run iPython to start using the modules
ipython

```

## Option2: Run in a Python Virtual Environment

```bash
* Git clone repository from BitBucket
  git clone https://github.com/sergitopereira/zscaler_api_talkers.git
* Create a virtual Environment:
  python3 -m venv .zs_api_talkers
* Activate virtual environment
  # Linux
  source .zs_api_talkers/bin/activate
  # Wiindows
  .\.zs_api_talkers\Scripts\activate
  
* Install requirements
  # Linux
  pip install -r requirements.txt --trusted-host pypi.org --trusted-host files.pythonhosted.org
  # Windows
  pip install -r .\zscaler_api_talkers\requirements.txt --trusted-host pypi.org --trusted-host files.pythonhosted.org
* Create a bash alias and review PYTHONPATH
```


#ZIA Talker
ZIA API talker is a python library to leverage ZIA public API Documentation: https://help.zscaler.com/zia/6.1/api

##Usage zia_talker
```python
from zia_talker.zia_talker import ZiaTalker
a=ZiaTalker('zsapi.<Zscaler Cloud Name>')
a.authenticate('APIKEY,'admin@<Zscaler Cloud Name>', 'password')
a.url_categories()
a.list_users()
# To view all methods available
print(dir(a))
```

#ZPA Talker
ZPA API talker is a python library to leverage ZPA public API Documentation: https://help.zscaler.com/zpa/api-reference

##Usage zpa_talker
``` python
from zpa_talker.zpa_talker import ZpaTalkerPublic as ZpaTalker
a=ZpaTalker('customerID')
a.authenticate('clientID','clientSecret')
# To view all methods available
print(dir(a))
```
# ZCCP talker
Zscaler Client Connector Portal API talker
``` python
from zccp_talker.zccp_talker import ZccpTalker
a.authenticate('clientID','clientSecret')
a.list_devices('companyID')
a.list_OTP('companyID','device id')
# To view all methods available
print(dir(a))
```






https://user-images.githubusercontent.com/43428944/164544149-4431fcbe-100e-4ab8-8c33-a96e72bc7383.mov

