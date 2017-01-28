#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

import copy
import datetime as dt
import json
import logging
import os
import time
from functools import partial
# from pprintpp import pprint

import requests
from logging_mv_integrations import (
    TuneLoggingFormat,
    TuneLoggingHandler,
    get_logger,
)
from pyhttpstatus_utils import (
    HttpStatusCode,
    HttpStatusType,
    http_status_code_to_desc,
    http_status_code_to_type,
    is_http_status_type,
)
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from requests_mv_integrations import (
    __python_required_version__,
    __version__,
)
from requests_mv_integrations.errors import (
    get_exception_message,
    print_traceback,
    TuneRequestErrorCodes,
)
from requests_mv_integrations.exceptions import (
    TuneRequestBaseError,
    TuneRequestClientError,
    TuneRequestServiceError,
    TuneRequestModuleError,
    TuneRequestValueError,
)
from requests_mv_integrations.support import (
    build_response_error_details,
    command_line_request_curl,
    base_class_name,
    python_check_version,
    safe_dict,
    safe_str,
    env_usage,
    REQUEST_RETRY_EXCPS,
    REQUEST_RETRY_HTTP_STATUS_CODES,
    __USER_AGENT__,
)
from requests_mv_integrations.support.tune_request import (TuneRequest)

python_check_version(__python_required_version__)


# @brief Request with retry class for TUNE Multiverse classes
#
# @namespace requests_mv_integrations.RequestMvIntegration
class RequestMvIntegration(object):
    """Request with retry class for TUNE Multiverse classes
    """

    _REQUEST_CONFIG = {
        "timeout": 60,  # timeout: the number of seconds to connect to
        # and then read from a remote machine.
        "tries": 3,  # tries: the maximum number of attempts.
        # (-1 is infinite). default: 10 tries.
        "delay": 10  # delay: initial delay between attempts.
        # default: 10 seconds.
    }

    # Current directory
    # @var string
    CURRENT_DIR = \
        os.path.dirname(os.path.realpath(__file__))

    __tune_request = None
    __request_retry_http_status_codes = REQUEST_RETRY_HTTP_STATUS_CODES
    __request_retry_func = None
    __request_retry_excps = REQUEST_RETRY_EXCPS
    __request_retry_excps_func = None

    __built_request_curl = None
    __logger = None

    @property
    def built_request_curl(self):
        return self.__built_request_curl

    @built_request_curl.setter
    def built_request_curl(self, value):
        self.__built_request_curl = value

    @property
    def logger(self):
        """Get Property: Logger
        """
        if self.__logger is None:
            self.__logger = get_logger(
                logger_name=__name__.split('.')[0],
                logger_version=__version__,
                logger_format=self.logger_format,
                logger_level=self.logger_level
            )

        return self.__logger

    @property
    def session(self):
        if self.tune_request:
            return self.tune_request.session

    @property
    def tune_request(self):
        return self.__tune_request

    @tune_request.setter
    def tune_request(self, value):
        self.__tune_request = value

    @property
    def request_retry_http_status_codes(self):
        return self.__request_retry_http_status_codes

    @request_retry_http_status_codes.setter
    def request_retry_http_status_codes(self, value):
        self.__request_retry_http_status_codes = value

    @property
    def request_retry_func(self):
        return self.__request_retry_func

    @request_retry_func.setter
    def request_retry_func(self, value):
        self.__request_retry_func = value

    @property
    def request_retry_excps(self):
        return self.__request_retry_excps

    @request_retry_excps.setter
    def request_retry_excps(self, value):
        self.__request_retry_excps = value

    @property
    def request_retry_excps_func(self):
        return self.__request_retry_excps_func

    @request_retry_excps_func.setter
    def request_retry_excps_func(self, value):
        self.__request_retry_excps_func = value

    def __init__(
        self,
        logger_level=logging.INFO,
        logger_format=TuneLoggingFormat.JSON,
        tune_request=None,
    ):
        self.logger_level = logger_level
        self.logger_format = logger_format

        self.tune_request = tune_request
        self._requests_logger()

        self.timeout = self._REQUEST_CONFIG['timeout']
        self.retry_delay = self._REQUEST_CONFIG['delay']
        self.retry_tries = self._REQUEST_CONFIG['tries']

        self.retry_max_delay = None
        self.retry_backoff = 0
        self.retry_jitter = 0

    def _requests_logger(self):
        """Set logging format to package 'requests'"""
        if self.logger:
            request_logger_level = self.logger_level

            if request_logger_level == logging.INFO:
                request_logger_level = logging.WARNING

            tune_loggin_handler = TuneLoggingHandler(logger_format=self.logger_format)

            tune_loggin_handler.add_logger_version('requests', requests.__version__)

            requests_logger = logging.getLogger('requests')
            requests_logger.addHandler(tune_loggin_handler.log_handler)
            requests_logger.propagate = True
            requests_logger.setLevel(level=request_logger_level)

    def _prep_request_retry(self, request_retry=None, request_retry_http_status_codes=None):
        self.timeout = self._REQUEST_CONFIG['timeout']
        self.retry_tries = self._REQUEST_CONFIG['tries']
        self.retry_delay = self._REQUEST_CONFIG['delay']

        if request_retry:
            self.timeout = request_retry.get('timeout', self._REQUEST_CONFIG['timeout'])
            self.retry_tries = request_retry.get('tries', self._REQUEST_CONFIG['tries'])
            self.retry_delay = request_retry.get('delay', self._REQUEST_CONFIG['delay'])
            self.retry_max_delay = request_retry.get('max_delay', None)
            self.retry_backoff = request_retry.get('backoff', 0)
            self.retry_jitter = request_retry.get('jitter', 0)

        self.request_retry_http_status_codes = \
            request_retry_http_status_codes or REQUEST_RETRY_HTTP_STATUS_CODES

    def request(
        self,
        request_method,
        request_url,
        request_params=None,
        request_data=None,
        request_json=None,
        request_retry=None,
        request_retry_excps=None,
        request_retry_http_status_codes=None,
        request_retry_func=None,
        request_retry_excps_func=None,
        request_headers=None,
        request_auth=None,
        cookie_payload=None,
        build_request_curl=True,
        allow_redirects=True,
        verify=True,
        stream=False,
        request_label=None
    ):
        """Request data from remote source with retries.

        Args:
            request_method: request_method for the new :class:`Request` object.
            request_url: URL for the new :class:`Request` object.
            request_params: (optional) Dictionary or bytes to be sent in the
                query string for the :class:`Request`.
            request_data: (optional) Dictionary, bytes, or file-like object to
                send in the body of the :class:`Request`.
            request_json: (optional) json data to send in the body of
                the :class:`Request`.
            request_retry: (optional) Retry configuration.
            request_retry_func: (optional) Retry function, alternative
                to request_retry_excps.
            request_retry_excps: An exception or a tuple of exceptions
                to catch.
            request_headers: (optional) Dictionary of HTTP Headers to
                send with the :class:`Request`.
            request_auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
            allow_redirects: (optional) Boolean. Set to True if POST/PUT/DELETE
                redirect following is allowed.
            verify: (optional) whether the SSL cert will be verified. A
                CA_BUNDLE path can also be provided. Defaults to ``True``.
            stream: (optional) if ``False``, the response content will be
                immediately downloaded.
            request_label:

        Returns:
            requests.Response: Data result if success or None if error.

        Raises:
            ServiceGatewayTimeoutError: Upon any timeout condition.
            Exception: Upon error within this request_method.

        Notes:
            * tries: the maximum number of attempts. default: 1.
            * delay: initial delay between attempts. default: 1.
            * max_delay: the maximum value of delay. default: None (no limit).
            * backoff: multiplier applied to delay between attempts.
                default: 1 (no backoff).
            * jitter: extra seconds added to delay between attempts.
                default: 0.
        """
        self.logger.debug("Request: Start: {}".format(request_label if request_label else ""))

        timeout = None

        if not verify:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        if request_method:
            request_method = request_method.upper()

        if not request_retry:
            request_retry = {}

        if 'timeout' not in request_retry:
            request_retry['timeout'] = self._REQUEST_CONFIG['timeout']
        if 'tries' not in request_retry:
            request_retry['tries'] = self._REQUEST_CONFIG['tries']
        if 'delay' not in request_retry:
            request_retry['delay'] = self._REQUEST_CONFIG['delay']

        self._prep_request_retry(request_retry, request_retry_http_status_codes)

        if not self.tune_request:
            self.tune_request = TuneRequest(
                retry_tries=self.retry_tries,
                retry_backoff=self.retry_backoff,
                retry_codes=self.request_retry_http_status_codes
            )

        key_user_agent = 'User-Agent'
        header_user_agent = {key_user_agent: __USER_AGENT__}

        if request_headers:
            if key_user_agent not in request_headers:
                request_headers.update(header_user_agent)
        else:
            request_headers = header_user_agent

        kwargs = {
            'request_method': request_method,
            'request_url': request_url,
            'request_params': request_params,
            'request_data': request_data,
            'request_json': request_json,
            'request_headers': request_headers,
            'request_auth': request_auth,
            'cookie_payload': cookie_payload,
            'request_label': request_label,
            'timeout': timeout,
            'build_request_curl': build_request_curl,
            'allow_redirects': allow_redirects,
            'verify': verify,
            'stream': stream
        }

        time_start_req = dt.datetime.now()

        if request_retry_func is None:
            request_retry_func = self.request_retry_func

        if request_retry_excps_func is None:
            request_retry_excps_func = self.request_retry_excps_func

        if request_retry_http_status_codes is not None:
            self.request_retry_http_status_codes = request_retry_http_status_codes

        if request_retry_excps is not None:
            self.request_retry_excps = request_retry_excps

        extra_request = copy.copy(kwargs)

        if request_retry:
            extra_request.update({'request_retry': request_retry})

        if request_label:
            extra_request.update({'request_label': request_label})

        if request_retry:
            extra_request.update({'request_retry': request_retry})

        if request_retry_func:
            extra_request.update({'request_retry_func': request_retry_func})
        if request_retry_http_status_codes:
            extra_request.update({'request_retry_http_status_codes': request_retry_http_status_codes})
        if request_retry_excps:
            extra_request.update({'request_retry_excps': request_retry_excps})
        if request_retry_excps:
            extra_request.update({'request_retry_excps_func': request_retry_excps_func})

        extra_request.update(
            env_usage()
        )
        self.logger.debug("Request: Start: Details", extra=extra_request)

        try:
            self._prep_request_retry(request_retry, request_retry_http_status_codes)
            response = self._request_retry(
                call_func=self._request,
                fargs=None,
                fkwargs=kwargs,
                timeout=timeout,
                request_label=request_label,
                request_retry_func=request_retry_func,
                request_retry_excps_func=request_retry_excps_func
            )

        except (
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.Timeout,
        ) as ex_req_timeout:
            raise TuneRequestServiceError(
                error_message="Request: Exception: Timeout",
                errors=ex_req_timeout,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.GATEWAY_TIMEOUT
            )

        except requests.exceptions.HTTPError as ex_req_http:
            raise TuneRequestModuleError(
                error_message="Request: Exception: HTTP Error",
                errors=ex_req_http,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST_HTTP
            )

        except requests.exceptions.ConnectionError as ex_req_connect:
            raise TuneRequestModuleError(
                error_message="Request: Exception: Connection Error",
                errors=ex_req_connect,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT
            )

        except BrokenPipeError as ex_broken_pipe:
            raise TuneRequestModuleError(
                error_message="Request: Exception: Broken Pipe Error",
                errors=ex_broken_pipe,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT
            )

        except ConnectionError as ex_connect:
            raise TuneRequestModuleError(
                error_message="Request: Exception: Connection Error",
                errors=ex_connect,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT
            )

        except requests.packages.urllib3.exceptions.ProtocolError as ex_req_urllib3_protocol:
            raise TuneRequestModuleError(
                error_message="Request: Exception: Protocol Error",
                errors=ex_req_urllib3_protocol,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT
            )

        except requests.packages.urllib3.exceptions.ReadTimeoutError as ex_req_urllib3_read_timeout:
            raise TuneRequestServiceError(
                error_message="Request: Exception: Urllib3: Read Timeout Error",
                errors=ex_req_urllib3_read_timeout,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.GATEWAY_TIMEOUT
            )

        except requests.exceptions.TooManyRedirects as ex_req_redirects:
            raise TuneRequestModuleError(
                error_message="Request: Exception: Too Many Redirects",
                errors=ex_req_redirects,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST_REDIRECTS
            )

        except requests.exceptions.RequestException as ex_req_request:
            raise TuneRequestModuleError(
                error_message="Request: Exception: Request Error",
                errors=ex_req_request,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST
            )

        except TuneRequestBaseError:
            raise

        except Exception as ex:
            print_traceback(ex)

            raise TuneRequestModuleError(
                error_message="Request: Exception: Unexpected",
                errors=ex,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_SOFTWARE
            )

        time_end_req = dt.datetime.now()
        diff_req = time_end_req - time_start_req

        request_time_msecs = int(diff_req.total_seconds() * 1000)

        self.logger.info("Request: Finished", extra={
            'request_label': request_label,
            'request_time_msecs': request_time_msecs,
        })
        self.logger.debug("Request: Usage", extra=env_usage())

        return response

    def _request_retry(
        self,
        call_func,
        fargs=None,
        fkwargs=None,
        timeout=60,
        request_retry_func=None,
        request_retry_excps_func=None,
        request_label=None,
    ):
        """Request Retry

        Args:
            call_func: the function to execute.
            request_retry_excps: A tuple of exceptions to catch.
            fargs: the positional arguments of the function to execute.
            fkwargs: the named arguments of the function to execute.
            timeout: (optional) How long to wait for the server to send
                data before giving up.
            request_retry_func: (optional) Retry alternative to request_retry_excps.

            retry_tries: the maximum number of attempts.
                default: -1 (infinite).
            retry_delay: initial delay between attempts.
                default: 0.
            retry_max_delay:the maximum value of delay.
                default: None (no limit).
            retry_backoff: multiplier applied to delay between attempts.
                default: 1 (no backoff).
            retry_jitter: extra seconds added to delay between attempts.
                default: 0.
            request_label: Label

        Returns:

        """
        request_retry_extra = {
            'request_label': request_label,
            'timeout': timeout,
            'request_retry_http_status_codes': self.request_retry_http_status_codes,
        }

        if self.request_retry_excps is not None:
            request_retry_excp_names = [excp.__name__ for excp in list(self.request_retry_excps)]
            request_retry_extra.update({'request_retry_excps': request_retry_excp_names})

        if request_retry_func is not None:
            request_retry_func_name = request_retry_func.__name__
            request_retry_extra.update({'request_retry_func': request_retry_func_name})

        if request_retry_excps_func is not None:
            request_retry_excps_func_name = request_retry_excps_func.__name__
            request_retry_extra.update({'request_retry_excps_func': request_retry_excps_func_name})

        self.logger.debug("Request Retry: Start", extra=request_retry_extra)

        args = fargs if fargs else list()
        kwargs = fkwargs if fkwargs else dict()

        request_url = kwargs['request_url'] if kwargs and 'request_url' in kwargs else ""

        _attempts = 0

        _tries, _delay, _timeout = self.retry_tries, self.retry_delay, self.timeout
        while _tries:
            _attempts += 1

            kwargs['timeout'] = _timeout
            request_func = partial(call_func, *args, **kwargs)

            self.logger.debug(
                "Request Retry: Attempt",
                extra={
                    'request_label': request_label,
                    'attempts': _attempts,
                    'timeout': _timeout,
                    'tries': _tries,
                    'delay': _delay,
                    'request_url': request_url
                }
            )

            _tries -= 1

            to_raise_exception, to_return_response = self.try_send_request(
                _attempts, _tries, request_func, request_label, request_retry_func, request_url
            )

            if to_raise_exception:
                raise to_raise_exception

            if to_return_response:
                return to_return_response

            self.logger.info(
                "Request Retry: Performing Retry",
                extra={
                    'tries': _tries,
                    'delay': _delay,
                    'timeout': _timeout,
                    'request_url': request_url,
                    'request_label': request_label
                }
            )

            time.sleep(_delay)

            if self.retry_backoff and self.retry_backoff > 0:
                _delay *= self.retry_backoff

            if self.retry_jitter and self.retry_jitter > 0:
                _delay += self.retry_jitter

            if self.retry_max_delay is not None:
                _delay = min(_delay, self.retry_max_delay)

    def try_send_request(self, _attempts, _tries, request_func, request_label, request_retry_func, request_url):
        to_raise_exception = None
        to_return_response = None
        try:
            response = request_func()

            if response is None:
                raise TuneRequestModuleError(
                    error_message="Request Retry: No response",
                    error_code=TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_VALUE
                )

            if self.is_return_response(request_label, request_retry_func, request_url, response):
                to_return_response = response
            else:
                self.logger.debug(
                    "Request Retry: Response: Valid: Retry Candidate",
                    extra={'request_url': request_url,
                           'request_label': request_label}
                )

        except tuple(self.request_retry_excps) as retry_ex:
            if not self.is_retry_retry_ex(_tries, request_label, request_url, retry_ex):
                to_raise_exception = retry_ex

        except TuneRequestBaseError as tmv_ex:
            if not self.is_retry_non_retry_ex(_tries, request_label, tmv_ex):
                to_raise_exception = tmv_ex

        except Exception as ex:
            is_retry, raised_exception = self.is_retry_non_tune_ex(_tries, ex, request_label, request_url)
            if not is_retry:
                to_raise_exception = raised_exception

        # A final check, whether we need to raise an exception, is in case the number of retries has exhausted.
        if not to_raise_exception and self.is_exhausted_retries(
            _tries,
            partial(
                self.logger.error,
                "Request Retry: Exhausted Retries",
                extra={
                    'attempts': _attempts,
                    'tries': _tries,
                    'request_url': request_url,
                    'request_label': request_label
                }
            )
        ):
            to_raise_exception = TuneRequestModuleError(
                error_message=("Request Retry: Exhausted Retries: {}: {}").format(request_label, request_url),
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED
            )

        return to_raise_exception, to_return_response

    def is_retry_non_tune_ex(self, _tries, ex, request_label, request_url):
        is_retry = True
        raised_exception = None
        error_exception = ex
        ex_extra = {
            'error_exception': base_class_name(error_exception),
            'error_details': get_exception_message(error_exception),
            'request_url': request_url,
            'request_label': request_label
        }
        if not self.request_retry_excps_func or \
                not self.request_retry_excps_func(error_exception, request_label):
            self.logger.error(
                "Request Retry: Unexpected: {}: Not Retry Candidate".format(base_class_name(error_exception)),
                extra=ex_extra
            )
            is_retry = False
            raised_exception = error_exception
        if is_retry:
            self.logger.warning(
                "Request Retry: Unexpected: {}: Retry Candidate".format(base_class_name(error_exception)),
                extra=ex_extra
            )

            if self.is_exhausted_retries(_tries, lambda: None):
                is_retry = False
                raised_exception = TuneRequestModuleError(
                    error_message="Unexpected: {}".format(base_class_name(error_exception)),
                    errors=error_exception,
                    error_request_curl=self.built_request_curl,
                    error_code=TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED
                )
        return is_retry, raised_exception

    def is_retry_non_retry_ex(self, _tries, request_label, tmv_ex):
        is_retry = True
        error_exception = tmv_ex
        tmv_ex_extra = tmv_ex.to_dict()
        tmv_ex_extra.update({
            'error_exception': base_class_name(error_exception),
            'error_details': get_exception_message(error_exception),
            'request_label': request_label
        })
        self.logger.warning(
            "Request Retry: Failed: {}".format(get_exception_message(error_exception)), extra=tmv_ex.to_dict()
        )
        if not self.request_retry_excps_func or \
                not self.request_retry_excps_func(tmv_ex, request_label):
            tmv_ex_extra.update({'request_retry_excps_func': self.request_retry_excps_func})
            self.logger.error(
                "Request Retry: Integration: {}: Not Retry Candidate".format(base_class_name(error_exception)),
                extra=tmv_ex_extra
            )
            is_retry = False
        if is_retry:
            self.logger.warning(
                "Request Retry: Integration: {}: Retry Candidate".format(base_class_name(error_exception)),
                extra=tmv_ex_extra
            )
            is_retry = not self.is_exhausted_retries(
                _tries,
                partial(
                    self.logger.error,
                    "Request Retry: Expected: {}: Exhausted Retries".format(base_class_name(error_exception))
                )
            )
        return is_retry

    def is_exhausted_retries(self, tries, logger_func_call):
        if not tries:
            logger_func_call()
            return True
        return False

    def is_retry_retry_ex(self, tries, request_label, request_url, retry_ex):
        self.logger.warning(
            "Request Retry: Expected: {}: Retry Candidate".format(base_class_name(retry_ex)),
            extra={
                'error_details': get_exception_message(retry_ex),
                'request_url': request_url,
                'request_label': request_label
            }
        )
        return not self.is_exhausted_retries(
            tries,
            partial(
                self.logger.error, "Request Retry: Expected: {}: Exhausted Retries".format(base_class_name(retry_ex))
            )
        )

    def is_return_response(self, request_label, request_retry_func, request_url, response):
        is_return_response = False
        self.logger.debug(
            "Request Retry: Checking Response", extra={'request_url': request_url,
                                                       'request_label': request_label}
        )
        if request_retry_func is not None:
            if not request_retry_func(response):
                self.logger.debug(
                    "Request Retry: Response: Valid: Not Retry Candidate",
                    extra={'request_url': request_url,
                           'request_label': request_label}
                )
                is_return_response = True
        else:
            self.logger.debug(
                "Request Retry: Response: Valid", extra={'request_url': request_url,
                                                         'request_label': request_label}
            )
            is_return_response = True
        return is_return_response

    # Request Data
    #
    def _request(
        self,
        request_method,
        request_url,
        request_params=None,
        request_data=None,
        request_json=None,
        request_headers=None,
        request_auth=None,
        cookie_payload=None,
        request_label=None,
        timeout=60,
        build_request_curl=True,
        allow_redirects=True,
        verify=True,
        stream=False
    ):
        """Constructs and sends a :class:`Request <Request>`.

        Args:
            request_method: request_method for the new :class:`Request` object.
            logger: logging instance
            request_url: URL for the new :class:`Request` object.
            request_params: (optional) Dictionary or bytes to be sent in the
                query string for the :class:`Request`.
            request_data: (optional) Dictionary, bytes, or file-like object to
                send in the body of the :class:`Request`.
            request_json: (optional) json data to send in the body of
                the :class:`Request`.
            request_headers: (optional) Dictionary of HTTP Headers to send
                with the :class:`Request`.
            request_auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
            timeout: (optional) How long to wait for the server to send data
                before giving up.
            allow_redirects: (optional) Boolean. Set to True if POST/PUT/DELETE
                redirect following is allowed.
            verify: (optional) whether the SSL cert will be verified. A
                CA_BUNDLE path can also be provided. Defaults to ``True``.
            stream: (optional) if ``False``, the response content will be
                immediately downloaded.

        Returns:
            requests.Response

        """

        if not request_method:
            raise TuneRequestValueError(error_message="Parameter 'request_method' not defined")
        if not request_url:
            raise TuneRequestValueError(error_message="Parameter 'request_url' not defined")

        self.built_request_curl = None

        self.logger.debug(
            "Session: Details",
            extra={'cookie_payload': self.tune_request.session.cookies.get_dict(),
                   'request_label': request_label}
        )

        response = None
        headers = None

        if request_headers:
            headers = request_headers

        request_method = request_method.upper()

        if request_data and isinstance(request_data, str):
            if len(request_data) <= 20:
                request_data_extra = request_data
            else:
                request_data_extra = request_data[:20] + ' ...'
        else:
            request_data_extra = safe_str(request_data)

        request_extra = {
            'request_method': request_method,
            'request_url': request_url,
            'timeout': timeout,
            'request_params': safe_dict(request_params),
            'request_data': request_data_extra,
            'request_headers': safe_dict(headers),
            'request_label': request_label
        }

        self.logger.debug("Send Request: Details", extra=request_extra)

        self.built_request_curl = None

        kwargs = {}
        if headers:
            kwargs.update({'headers': headers})

        if request_auth:
            kwargs.update({'auth': request_auth})

        if timeout and isinstance(timeout, int):
            kwargs.update({'timeout': timeout})

        if allow_redirects:
            kwargs.update({'allow_redirects': allow_redirects})

        if stream:
            kwargs.update({'stream': stream})

        if cookie_payload:
            kwargs.update({'cookies': cookie_payload})

        kwargs.update({'verify': verify})

        try:
            if build_request_curl:
                self.built_request_curl = command_line_request_curl(
                    request_method=request_method,
                    request_url=request_url,
                    request_headers=headers,
                    request_data=request_data,
                    request_json=request_json,
                    request_auth=request_auth,
                    request_timeout=timeout,
                    request_allow_redirects=allow_redirects
                )

                self.logger.debug(
                    "Send Request: Request: Curl",
                    extra={
                        'request_method': request_method,
                        'request_label': request_label,
                        'request_curl': self.built_request_curl
                    }
                )

            if hasattr(response, 'url'):
                self.logger.debug(
                    msg=(request_label if request_label is not None else "request: {0}".format(request_method)),
                    extra={'response_url': response.url}
                )

            if request_params:
                kwargs.update({'params': request_params})

            if request_data:
                kwargs.update({'data': request_data})

            if request_json:
                kwargs.update({'json': request_json})

            if headers:
                kwargs.update({'headers': headers})

            kwargs.update({'request_method': request_method, 'request_url': request_url})

            response = self.tune_request.request(**kwargs)

        except Exception as ex:
            self.logger.error(
                "Send Request: Request Base: Error",
                extra={
                    'request_label': request_label,
                    'error_exception': base_class_name(ex),
                    'error_details': get_exception_message(ex)
                }
            )
            raise

        if response is None:
            self.logger.error("Failed to get response", extra={'request_curl': self.built_request_curl})
            raise TuneRequestModuleError(
                error_message="Failed to get response",
                error_code=TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_VALUE,
                error_request_curl=self.built_request_curl
            )

        http_status_code = response.status_code
        response_headers = json.loads(json.dumps(dict(response.headers)))

        http_status_type = \
            http_status_code_to_type(http_status_code)
        http_status_desc = \
            http_status_code_to_desc(http_status_code)

        response_extra = {
            'http_status_code': http_status_code,
            'http_status_type': http_status_type,
            'http_status_desc': http_status_desc,
            'response_headers': safe_dict(response_headers),
            'request_label': request_label
        }

        self.logger.debug("Send Request: Response: Details", extra=response_extra)

        http_status_successful = is_http_status_type(
            http_status_code=http_status_code, http_status_type=HttpStatusType.SUCCESSFUL
        )

        http_status_redirection = is_http_status_type(
            http_status_code=http_status_code, http_status_type=HttpStatusType.REDIRECTION
        )

        if http_status_successful or http_status_redirection:
            if hasattr(response, 'url') and \
                    response.url and \
                    len(response.url) > 0:
                response_extra.update({'response_url': response.url})

            self.logger.debug(
                "Send Request: Cookie Payload",
                extra={'cookie_payload': self.tune_request.session.cookies.get_dict(),
                       'request_label': request_label}
            )

            assert response
            return response
        else:
            response_extra.update({'error_request_curl': self.built_request_curl})

            self.logger.error("Send Request: Response: Failed", extra=response_extra)

            json_response_error = \
                build_response_error_details(
                    response=response,
                    request_label=request_label,
                    request_url=request_url
                )

            extra_error = copy.deepcopy(json_response_error)

            if self.logger_level == logging.INFO:
                error_response_details = \
                    extra_error.get('response_details', None)

                if error_response_details and \
                        isinstance(error_response_details, str) and \
                        len(error_response_details) > 100:
                    extra_error['response_details'] = \
                        error_response_details[:100] + ' ...'

            if self.built_request_curl and \
                    'error_request_curl' not in extra_error:
                extra_error.update({'error_request_curl': self.built_request_curl})

            self.logger.error("Send Request: Error: Response: Details", extra=extra_error)

            kwargs = {
                'error_status': json_response_error.get("response_status", None),
                'error_reason': json_response_error.get("response_reason", None),
                'error_details': json_response_error.get("response_details", None),
                'error_request_curl': self.built_request_curl
            }

            if http_status_code in [
                HttpStatusCode.BAD_REQUEST,
                HttpStatusCode.UNAUTHORIZED,
                HttpStatusCode.FORBIDDEN,
                HttpStatusCode.NOT_FOUND,
                HttpStatusCode.METHOD_NOT_ALLOWED,
                HttpStatusCode.NOT_ACCEPTABLE,
                HttpStatusCode.REQUEST_TIMEOUT,
                HttpStatusCode.CONFLICT,
                HttpStatusCode.GONE,
                HttpStatusCode.UNPROCESSABLE_ENTITY,
                HttpStatusCode.TOO_MANY_REQUESTS,
            ]:
                kwargs.update({'error_code': http_status_code})
                raise TuneRequestClientError(**kwargs)

            if http_status_code in [
                HttpStatusCode.INTERNAL_SERVER_ERROR,
                HttpStatusCode.NOT_IMPLEMENTED,
                HttpStatusCode.BAD_GATEWAY,
                HttpStatusCode.SERVICE_UNAVAILABLE,
                HttpStatusCode.NETWORK_AUTHENTICATION_REQUIRED,
            ]:
                kwargs.update({'error_code': http_status_code})
                raise TuneRequestServiceError(**kwargs)

            kwargs.update({'error_code': json_response_error["response_status_code"]})

            extra_unhandled = copy.deepcopy(kwargs)
            extra_unhandled.update({'http_status_code': http_status_code})
            self.logger.error("Send Request: Error: Unhandled", extra=extra_unhandled)

            raise TuneRequestModuleError(**kwargs)
