import time

import requests
import requests.packages.urllib3.exceptions

from .logger import setup_logger

# Disable the InsecureRequestWarning
requests.packages.urllib3.disable_warnings(
    category=requests.packages.urllib3.exceptions.InsecureRequestWarning
)

logger = setup_logger(name=__name__)


def get_user_agent() -> str:
    return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36"


def request_(
    method: str,
    url: str,
    retries: int = 10,
    wait_time: float = 5,
    silence_logs: bool = False,
    **kwargs,
) -> requests.Response:
    """
    Submit to requests module with retry and error logic.

    :param method: (str) ['get', 'put', 'post', 'delete', 'patch', 'head', 'options']
    :param url: (str) URL to call.
    :param retries: (int) If an error is reached how many times to re-attempt request.
    :param wait_time: (float) Time to wait between re-attempts, when necessary.
    :param silence_logs: (bool) Suppress error messages in logs.  (Default: False)
    :param kwargs: Options:
        params: (optional) Dictionary, list of tuples or bytes to send in the query string for the :class:`Request`.
        data: (optional) Dictionary, list of tuples, bytes, or file-like object to send in the body of the
            :class:`Request`.
        json: (optional) A JSON serializable Python object to send in the body of the :class:`Request`.
        headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
        cookies: (optional) Dict or CookieJar object to send with the :class:`Request`.
        files: (optional) Dictionary of ``'name': file-like-objects`` (or ``{'name': file-tuple}``) for multipart
            encoding upload. ``file-tuple`` can be a 2-tuple ``('filename', fileobj)``, 3-tuple ``('filename',
            fileobj, 'content_type')`` or a 4-tuple ``('filename', fileobj, 'content_type', custom_headers)``,
            where ``'content-type'`` is a string defining the content type of the given file and ``custom_headers``
            a dict-like object containing additional headers to add for the file.
        auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
        timeout: (optional) How many seconds to wait for the server to send data before giving up, as a float,
            or a :ref:`(connect timeout, read timeout) <timeouts>` tuple. :type timeout: float or tuple
        allow_redirects: (optional) Boolean. Enable/disable GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD redirection.
            Defaults to ``True`` :type allow_redirects: bool
        proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
        verify: (optional) Either a boolean, in which case it controls whether we verify the server's TLS
            certificate, or a string, in which case it must be a path to a CA bundle to use. Defaults to ``True``.
        stream: (optional) if ``False``, the response content will be immediately downloaded.
        cert: (optional) if String, path to ssl client cert file (.pem). If Tuple, ('cert', 'key') pair.

    :return: :class:`Response <Response>` object :rtype: requests.Response
    """
    retry_attempts = 0
    result = None
    while retry_attempts <= retries:
        try:
            passable_options = [
                "params",
                "data",
                "json",
                "headers",
                "cookies",
                "files",
                "auth",
                "allow_redirects",
                "proxies",
                "verify",
                "stream",
                "cert",
                "timeout",
            ]
            result = requests.request(
                method=method.upper(),
                url=url,
                **{k: v for k, v in kwargs.items() if k in passable_options},
            )
            if result.status_code < 400:
                break  # Only stop looping if the status_code is reported as not an error.
        except requests.exceptions.SSLError:
            if not silence_logs:
                logger.debug("Disabling SSL verification for the next request attempt.")
            kwargs.update(
                {
                    "verify": False,
                }
            )
            continue  # Skip the wait and try again but with SSL verification off.
        except requests.exceptions.RequestException as e:
            if not silence_logs:
                logger.error(f"Encountered error: {e}")
        except requests.packages.urllib3.exceptions as e:
            if not silence_logs:
                logger.error(f"Encountered error: {e}")
        if not silence_logs:
            logger.info(
                f"Retrying request in {wait_time}s.  Retries remaining: {retries - retry_attempts}"
            )
        retry_attempts += 1
        time.sleep(wait_time)

    if result.status_code == 400:
        if not silence_logs:
            logger.info(
                f"Status code 400 indicates that the server cannot or will not process "
                f"the request due to something that is perceived to be a client error."
            )
    elif result.status_code == 401:
        if not silence_logs:
            logger.info(
                f"Status code 401 indicates the client request has not been completed "
                f"because it lacks valid authentication credentials for the requested resource."
            )
    elif result.status_code == 404:
        if not silence_logs:
            logger.info(
                f"Status code 404 indicates that the server cannot find the requested resource."
            )
    elif result.status_code == 405:
        if not silence_logs:
            logger.info(
                f"Status code 405 indicates that the server knows the request method, "
                f"but the target resource doesn't support this method."
            )
    elif result.status_code == 415:
        if not silence_logs:
            logger.info(
                f"Status code 415 indicates that the server refuses to accept the request "
                f"because the payload format is in an unsupported format; so stop trying!"
            )
    elif result.status_code == 429:
        if not silence_logs:
            logger.info(
                f"Status code 429 indicates the user has sent too many requests in a "
                f"given amount of time."
            )

    return result
