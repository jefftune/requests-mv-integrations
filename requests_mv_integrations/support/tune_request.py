#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

import logging
import requests
from requests.adapters import (HTTPAdapter, DEFAULT_POOLSIZE)
from requests.packages.urllib3.util.retry import Retry
from requests_mv_integrations.support import (REQUEST_RETRY_HTTP_STATUS_CODES)
from requests_mv_integrations.errors import (get_exception_message)
from .singleton import (Singleton)

log = logging.getLogger(__name__)


class TuneRequest(metaclass=Singleton):
    POOL_SIZE = DEFAULT_POOLSIZE
    request_buffer = []

    __session = None

    def __init__(self, retry_tries=3, retry_backoff=0.1, retry_codes=None):
        self.session = requests.session()

        if retry_codes is None:
            retry_codes = set(REQUEST_RETRY_HTTP_STATUS_CODES)

        adapter = HTTPAdapter(
            max_retries=Retry(
                total=retry_tries,
                backoff_factor=retry_backoff,
                status_forcelist=retry_codes,
            )
        )

        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    @property
    def session(self):
        return self.__session

    @session.setter
    def session(self, value):
        self.__session = value

    def request(self, request_method, request_url, **kwargs):
        extra_session_request = {'method': request_method, 'url': request_url}
        extra_session_request.update(kwargs)
        log.debug("Session Request: Details", extra=extra_session_request)
        try:
            return self.session.request(method=request_method, url=request_url, **kwargs)
        except Exception as ex:
            log.warning(
                "Session Request: Failed: {}".format(get_exception_message(ex)),
                extra=extra_session_request,
            )
            raise

    # def request_safe(self, request_method, request_url, response_hook=None, exception_handler=None, **kwargs):
    #     response_hook, exception_handler = self.create_hooks(response_hook, exception_handler)
    #
    #     try:
    #         return self.session.request(
    #             method=request_method, url=request_url, hooks={'response': response_hook}, **kwargs
    #         )
    #     except Exception as ex:
    #         log.warning(
    #             "Session Request: Failed: {}".format(get_exception_message(ex)),
    #             extra={'request_method': request_method,
    #                    'request_url': request_url}
    #         )
    #         exception_handler(ex)
    #         return None
    #
    # def response_hook(self, r, *args, **kwargs):
    #     log.debug("{0} {1} {2}".format(r.request.method, r.url, str(r.status_code)))
    #
    # def exception_handler(self, r, e):
    #     log.error("url: {0}".format(r.url))
    #     raise e
    #
    # def create_hooks(self, response_hook=None, exception_handler=None):
    #     if response_hook is not None:
    #
    #         def rhook(r, *args, **kwargs):
    #             response_hook(r, *args, **kwargs)
    #             self.response_hook(r, *args, **kwargs)
    #
    #         response_hook = rhook
    #     else:
    #         response_hook = self.response_hook
    #
    #     if exception_handler is not None:
    #
    #         def ehook(r, e):
    #             exception_handler(r, e)
    #             self.exception_handler(r, e)
    #
    #         exception_handler = ehook
    #     else:
    #         exception_handler = self.exception_handler
    #
    #     return response_hook, exception_handler

    # def backoff(factor, max_delay):
    #     sleep_time = 1
    #
    #     def inner():
    #         asleep_time = sleep_time * factor
    #         asleep_time = asleep_time if asleep_time < max_delay else max_delay
    #         return asleep_time
    #
    #     return inner
