import time

from zscaler_api_talkers.helpers import request_


def _obfuscate_api_key(
    seed: str,
) -> (time, str):
    """
    Internal method to Obfuscate the API key

    :param seed: (str) API key

    :return: (str, str) timestamp,obfuscated key
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


def _get_seed(
    url: str,
) -> str:
    result = request_(
        method="get",
        url=url,
    )
    api = result.text.split('"')
    js = None
    for each in api:
        if each.startswith("js"):
            if each.find("lean") > 0:
                js = each
                break

    result = request_(
        method="get",
        url=f"{url}/{js}",
    )
    key = result.text.split(".")
    seed = None
    for each in key:
        if each.startswith("obfuscateApiKey"):
            getkey = each.split('"')
            seed = getkey[1]
            break

    return seed
