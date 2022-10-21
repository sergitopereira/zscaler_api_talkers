from helpers.http_calls import HttpCalls
import time
from getpass import getpass


class ZiaPortalTalker(object):
    """
    ZIA Portal API talker
    Documentation: https://help.zscaler.com/zia/zia-api/api-developer-reference-guide
    """

    def __init__(self, cloud_name):
        """
        Method to start the class
        :param cloud_name: type string. Example: zscalerbeta.net, zscalerone.net, zscalertwo.net
        zscalerthree.net, zscaler.net, zscloud.net
        """
        self.base_uri = f'https://admin.{cloud_name}/zsapi/v1'
        self.hp_http = HttpCalls(host=self.base_uri, verify=True)
        self.jsessionid = None
        self.zs_session_code = None
        self.headers = None
        self.version = '0.1'

    def _obfuscateApiKey(self, seed):
        """
        Internal method to Obfuscate the API key
        :param seed: API key
        :return: timestamp,obfuscated key
        """
        now = int(time.time() * 1000)
        n = str(now)[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ""
        for i in range(0, len(str(n)), 1):
            key += seed[int(str(n)[i])]
        for j in range(0, len(str(r)), 1):
            key += seed[int(str(r)[j]) + 2]
        return now, key

    def authenticate(self, apikey, username, password=None, ):
        """
        Method to authenticate.
        :param apikey: API key
        :param username: A string that contains the email ID of the API admin
        :param password: A string that contains the password for the API admin
        :return:  JSESSIONID. This cookie expires by default 30 minutes from last request
        """
        if not password:
            password = getpass(" Introduce password: ")
        timestamp, key = self._obfuscateApiKey('jj7tg80fEGao')

        payload = {
            "apiKey": key,
            "username": username,
            "password": password,
            "timestamp": timestamp
        }
        url = '/authenticatedSession'
        response = self.hp_http.post_call(url=url, payload=payload, headers={"Accept": "application/json"})
        if response.cookies.get('JSESSIONID'):
            self.jsessionid = response.cookies['JSESSIONID']
        else:
            raise ValueError("Invalid Credentials")
        if response.cookies.get('ZS_SESSION_CODE'):
            self.zs_session_code = response.cookies['ZS_SESSION_CODE']
            self.headers = {'Content-Type': 'application/json', 'ZS_CUSTOM_CODE': self.zs_session_code}
        else:
            raise ValueError("Invalid API key")

    def create_dlpEngine(self, payload=None, EngineExpression=None, Name=None, CustomDlpEngine=True,
                         PredefinedEngineName=None, Description=None):
        """
        Method to create a DLP engine
        :param Name: type string. Name of the DLP ENGINE
        :param EngineExpression: type string. Engine Expression
        :param CustomDlpEngine: : type boolean. True if custom DLP engine
        :param PredefinedEngineName: type boolean.
        :param Description: type string. Description
        :return: 
        """
        url = '/dlpEngines'
        if payload:
            payload = payload
        else:
            payload = {
                "EngineExpression": EngineExpression,
                "CustomDlpEngine": CustomDlpEngine
            }
            if PredefinedEngineName:
                payload.update(PredefinedEngineName=PredefinedEngineName)
            else:
                payload.update(Name=Name)

            if Description:
                payload.update(Description=Description)
        response = self.hp_http.post_call(url=url, payload=payload, headers=self.headers,
                                          cookies={'JSESSIONID': self.jsessionid,
                                                   'ZS_SESSION_CODE': self.zs_session_code,
                                                   })
        return response

    def update_dlpEngine(self, payload, id):
        """
        Method to update a DLP engine
        :param payload: type json. payload
        :return: 
        """
        url = f'/dlpEngines/{id}'
        response = self.hp_http.put_call(url=url, payload=payload, headers=self.headers,
                                         cookies={'JSESSIONID': self.jsessionid,
                                                  'ZS_SESSION_CODE': self.zs_session_code,
                                                  })
        return response

    def list_PacFiles(self):
        """
        Method to list PAC files
        :return: json
        """
        url = f'/pacFiles'
        response = self.hp_http.get_call(url=url, headers=self.headers,
                                         cookies={'JSESSIONID': self.jsessionid,
                                                  'ZS_SESSION_CODE': self.zs_session_code,
                                                  })
        return response.json()

    def add_PacFile(self, name, description, domain, PacContent, editable=True, pacUrlObfuscated=True):
        """
        Method to Add a PAC file
        :param name: type string. Name of the PAC
        :param description: type string. Description
        :param domain: type string. Domain
        :param PacContent: Type string: PAC content
        :param editable: Type boolean. Default True
        :param pacUrlObfuscated: Type boolean. Default True
        :return:
        """
        payload = {
            'name': name,
            'editable': editable,
            'pacContent': PacContent,
            'pacUrlObfuscated': pacUrlObfuscated,
            'domain': domain,
            'description': description,
            'pacVerificationStatus': 'VERIFY_NOERR'
        }
        url = f'/pacFiles'
        response = self.hp_http.post_call(url=url, headers=self.headers, payload=payload,
                                          cookies={'JSESSIONID': self.jsessionid,
                                                   'ZS_SESSION_CODE': self.zs_session_code,
                                                   })
        return response.json()
