# Zscaler API talkers

##Installation

* Git clone repository from BitBucket
* Create a virtual Environment:
  python3 -m venv .zs_api_talkers
* Activate virtual environment
  source .zs_api_talkers/bin/activate
* Install requirements
  pip install requirements.txt
* Create a bash alias

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

