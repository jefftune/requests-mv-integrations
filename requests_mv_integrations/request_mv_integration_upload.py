#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

import os
import logging
import urllib

import requests
from logging_mv_integrations import (TuneLoggingFormat)

from requests_mv_integrations import (__python_required_version__)
from requests_mv_integrations.errors import (
    get_exception_message,
    print_traceback,
    TuneRequestErrorCodes,
)
from requests_mv_integrations.exceptions.custom import (
    TuneRequestBaseError,
    TuneRequestModuleError,
    TuneRequestValueError,
)
from requests_mv_integrations.support import (
    base_class_name,
    python_check_version,
    REQUEST_RETRY_EXCPS,
    REQUEST_RETRY_HTTP_STATUS_CODES,
)
from .request_mv_integration import (RequestMvIntegration)

log = logging.getLogger(__name__)

python_check_version(__python_required_version__)


class RequestMvIntegrationUpload(object):

    __mv_request = None

    def __init__(
        self,
        logger_level=logging.INFO,
        logger_format=TuneLoggingFormat.JSON,
    ):
        self.mv_request = RequestMvIntegration(
            logger_format=logger_format,
            logger_level=logger_level,
        )

    @property
    def mv_request(self):
        return self.__mv_request

    @mv_request.setter
    def mv_request(self, value):
        self.__mv_request = value

    def request(self, **kwargs):
        return self.mv_request.request(**kwargs)

    @property
    def built_request_curl(self):
        return self.mv_request.built_request_curl

    def request_upload_json_file(
        self,
        upload_request_url,
        upload_data_file_path,
        upload_data_file_size,
        is_upload_gzip=False,
        request_label=None,
        upload_timeout=None
    ):
        """
        Upload File to requested URL.

        :param upload_request_url:
        :param upload_data_file_path:
        :param upload_data_file_size:
        :param is_upload_gzip:
        :param request_label:
        :param upload_timeout:
        :return:
        """
        if not upload_request_url or not isinstance(upload_request_url, str):
            raise TuneRequestValueError(error_message="Missing 'upload_request_url'")

        parsed = urllib.parse.urlparse(upload_request_url)
        if not parsed:
            raise TuneRequestValueError(
                error_message="Unable to parse 'upload_request_url': '{upload_request_url}'".format(
                    upload_request_url=upload_request_url
                )
            )

        if not parsed.scheme:
            raise TuneRequestValueError(
                error_message="'{upload_request_url}': scheme '{parsed_scheme}'".format(
                    upload_request_url=upload_request_url, parsed_scheme=parsed.scheme
                )
            )

        if not parsed.netloc:
            raise TuneRequestValueError(
                error_message="'{upload_request_url}': scheme '{parsed_netloc}'".format(
                    upload_request_url=upload_request_url, parsed_netloc=parsed.netloc
                )
            )

        if not upload_data_file_path or not isinstance(upload_data_file_path, str):
            raise TuneRequestValueError(error_message="Missing 'upload_data_file_path'")

        if not os.path.exists(upload_data_file_path):
            raise TuneRequestValueError(
                error_message="Invalid 'upload_data_file_path': '{upload_data_file_path'}".format(
                    upload_data_file_path=upload_data_file_path
                )
            )

        if not upload_data_file_size or not isinstance(upload_data_file_size, int):
            raise TuneRequestValueError(error_message="Missing 'upload_data_file_size'")

        request_retry_excps = REQUEST_RETRY_EXCPS
        request_retry_http_status_codes = REQUEST_RETRY_HTTP_STATUS_CODES

        upload_request_retry = {"timeout": 60, "tries": -1, "delay": 60}

        upload_request_headers = {'Content-Length': '{}'.format(upload_data_file_size)}

        if is_upload_gzip is None:
            is_upload_gzip = False

        if is_upload_gzip:
            upload_request_headers.update({'Content-Type': 'application/gzip'})
        else:
            upload_request_headers.update({'Content-Type': 'application/json; charset=utf8'})

        if upload_timeout:
            upload_request_retry["timeout"] = int(upload_timeout)

        upload_extra = {
            'upload_request_url': upload_request_url,
            'upload_data_file_path': upload_data_file_path,
            'upload_data_file_size': upload_data_file_size,
            'upload_request_retry': upload_request_retry,
            'upload_request_headers': upload_request_headers
        }

        log.info("Request Upload JSON File: Start", extra=upload_extra)

        try:
            with open(upload_data_file_path, 'rb') as upload_fp:
                response = self.mv_request.request(
                    request_method='PUT',
                    request_url=upload_request_url,
                    request_params=None,
                    request_data=upload_fp,
                    request_retry=upload_request_retry,
                    request_headers=upload_request_headers,
                    request_retry_excps=request_retry_excps,
                    request_retry_http_status_codes=request_retry_http_status_codes,
                    request_retry_excps_func=self._upload_request_retry_excps_func,
                    allow_redirects=False,
                    build_request_curl=False,
                    request_label=request_label
                )
        except TuneRequestBaseError as tmv_ex:

            tmv_ex_extra = tmv_ex.to_dict()
            tmv_ex_extra.update({'error_exception': base_class_name(tmv_ex)})

            log.error("Request Upload JSON File: Failed", extra=tmv_ex_extra)

            raise

        except Exception as ex:
            log.error(
                "Request Upload JSON File: Failed: Unexpected",
                extra={'error_exception': base_class_name(ex),
                       'error_details': get_exception_message(ex)}
            )

            print_traceback(ex)

            raise TuneRequestModuleError(
                error_message=("Request Upload JSON File: Failed: Unexpected: {}: {}").format(
                    base_class_name(ex), get_exception_message(ex)
                ),
                errors=ex,
                error_code=TuneRequestErrorCodes.REQ_ERR_UPLOAD_DATA
            )

        log.info("Request Upload JSON File: Finished")

        return response

    def request_upload_data(
        self,
        upload_request_url,
        upload_data,
        upload_data_size,
        upload_timeout=None,
        request_label=None,
    ):
        """
        Upload Data to requested URL.

        :param upload_request_url:
        :param upload_data:
        :param upload_data_size:
        :param upload_timeout:
        :return:
        """
        if not upload_request_url or not isinstance(upload_request_url, str):
            raise TuneRequestValueError(error_message="Missing 'upload_request_url'")

        parsed = urllib.parse.urlparse(upload_request_url)
        if not parsed:
            raise TuneRequestValueError(
                error_message="Unable to parse 'upload_request_url': '{upload_request_url}'".format(
                    upload_request_url=upload_request_url
                )
            )

        if not parsed.scheme:
            raise TuneRequestValueError(
                error_message="'{upload_request_url}': scheme '{parsed_scheme}'".format(
                    upload_request_url=upload_request_url, parsed_scheme=parsed.scheme
                )
            )

        if not parsed.netloc:
            raise TuneRequestValueError(
                error_message="'{upload_request_url}': scheme '{parsed_netloc}'".format(
                    upload_request_url=upload_request_url, parsed_netloc=parsed.netloc
                )
            )

        request_label = "Upload Data to URL" if request_label is None or not isinstance(
            request_label, str
        ) else request_label

        log.info(
            "Request Upload JSON Data: Start",
            extra={'upload_data_size': upload_data_size,
                   'upload_request_url': upload_request_url}
        )

        request_retry_excps = REQUEST_RETRY_EXCPS
        request_retry_http_status_codes = REQUEST_RETRY_HTTP_STATUS_CODES

        upload_request_retry = {"timeout": 60, "tries": -1, "delay": 60}

        request_headers = {
            'Content-type': 'application/json; charset=utf8',
            'Accept': 'text/plain',
            'Content-Length': "{}".format(upload_data_size)
        }

        if upload_timeout:
            upload_request_retry["timeout"] = int(upload_timeout)

        try:
            response = self.mv_request.request(
                request_method='PUT',
                request_url=upload_request_url,
                request_params=None,
                request_data=upload_data,
                request_retry=upload_request_retry,
                request_retry_excps=request_retry_excps,
                request_retry_http_status_codes=request_retry_http_status_codes,
                request_retry_excps_func=self._upload_request_retry_excps_func,
                request_headers=request_headers,
                allow_redirects=False,
                build_request_curl=False,
                request_label=request_label
            )
        except TuneRequestBaseError as tmv_ex:
            tmv_ex_extra = tmv_ex.to_dict()
            tmv_ex_extra.update({'error_exception': base_class_name(tmv_ex)})

            log.error("Upload: Failed", extra=tmv_ex_extra)
            raise

        except Exception as ex:
            print_traceback(ex)

            log.error(
                "Upload: Failed: Unexpected",
                extra={'error_exception': base_class_name(ex),
                       'error_details': get_exception_message(ex)}
            )
            raise TuneRequestModuleError(
                error_message=("RequestMvIntegration: Failed: {}").format(get_exception_message(ex)),
                errors=ex,
                error_code=TuneRequestErrorCodes.REQ_ERR_UPLOAD_DATA
            )

        log.info("Request Upload JSON Data: Finished")

        return response

    def _upload_request_retry_excps_func(self, excp, request_label):
        """Upload Request Retry Exception Function

        Args:
            excp:

        Returns:

        """
        error_exception = base_class_name(excp)
        error_details = get_exception_message(excp)

        if isinstance(excp, TuneRequestBaseError):
            log.debug(
                "Request Retry: Upload Exception Func",
                extra={
                    'request_label': request_label,
                    'error_exception': error_exception,
                    'error_details': error_details
                }
            )
        else:
            log.debug(
                "Request Retry: Upload Exception Func: Unexpected",
                extra={
                    'request_label': request_label,
                    'error_exception': error_exception,
                    'error_details': error_details
                }
            )

        if isinstance(excp, TuneRequestBaseError) and \
                excp.error_code == TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT:
            if error_details.find('RemoteDisconnected') >= 0 or \
                    error_details.find('ConnectionResetError') >= 0:
                log.debug(
                    "Request Retry: Upload Exception Func: Retry",
                    extra={
                        'request_label': request_label,
                        'error_exception': error_exception,
                        'error_details': error_details
                    }
                )
                return True

        if isinstance(excp, requests.exceptions.ConnectionError):
            if error_details.find('RemoteDisconnected') >= 0 or \
                    error_details.find('ConnectionResetError') >= 0:
                log.debug(
                    "Request Retry: Upload Exception Func: Retry",
                    extra={
                        'request_label': request_label,
                        'error_exception': error_exception,
                        'error_details': error_details
                    }
                )
                return True

        log.debug(
            "Request Retry: Upload Exception Func: Not Retry",
            extra={'request_label': request_label,
                   'error_exception': error_exception,
                   'error_details': error_details}
        )

        return False
