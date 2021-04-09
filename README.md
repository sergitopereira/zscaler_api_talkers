# zstools

##Installation

* Git clone repository from BitBucket
* Create a virtual Environment:
  python3 -m venv .zia_talker
* Activate virtual environment
  source .zia_talker/bin/activate
* Install requirements
  pip install requirements.txt
* Create a bash alias

##Usage
```
from zia_talker.zia_talker import ZiaTalker
a=ZiaTalker('admin.zscalerthree.net')
a.authenticate('APIKEY,'admin@/*****zscalerthree.net')
a.url_categories()
a.list_users()
# To view all methods available
print(dir(a))
```
