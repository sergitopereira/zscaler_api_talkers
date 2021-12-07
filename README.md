# Zscaler API talkers

## Option1: Run within a Docker Container
```bash
# Download Dockerfile
curl -O https://bitbucket.corp.zscaler.com/scm/zat/zscaler_api_talkers.git/master/Dockerfile

# Build Image and Run Container
docker build -t zscaler_api_talkers .  
docker run -it zscaler_api_talkers bash

# Usage (program is in /app/)
python zscaler_api_talkers -h
```

## Option2: Run in a Python Virtual Environment

* Git clone repository from BitBucket
* Create a virtual Environment:
  python3 -m venv .zs_api_talkers
* Activate virtual environment
  source .zs_api_talkers/bin/activate
* Install requirements
  pip install -r requirements.txt
* Create a bash alias and review PYTHONPATH



#ZIA Talker
ZIA API talker is a python library to leverage ZIA public API Documentation: https://help.zscaler.com/zia/6.1/api

##Usage zia_talker
```
from zscaler_api_talkers.zia_talker import ZiaTalker
a=ZiaTalker('admin.<Zscaler Cloud Name>')
a.authenticate('APIKEY,'admin@<Zscaler Cloud Name>')
a.url_categories()
a.list_users()
# To view all methods available
print(dir(a))
```

#ZPA Talker
ZPA API talker is a python library to leverage ZPA public API Documentation: https://help.zscaler.com/zpa/api-reference

##Usage zpa_talker
```
from zpa_talker.zpa_talker import ZpaTalkerPublic as ZpaTalker
a=ZpaTalker('customerID')
a.authenticate('clientID','clientSecret')
# To view all methods available
print(dir(a))
```

