#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

import logging
from logging_mv_integrations import (LoggingFormat, LoggingOutput)

from requests_mv_integrations import (
    __python_required_version__,
    RequestMvIntegration,
)
from requests_mv_integrations.errors import (
    get_exception_message,
    print_traceback,
    TuneRequestErrorCodes,
)
from requests_mv_integrations.exceptions.custom import (
    TuneRequestBaseError,
    TuneRequestModuleError,
)
from requests_mv_integrations.support import (
    base_class_name,
    mv_request_retry_excps_func,
    python_check_version,
    REQUEST_RETRY_EXCPS,
    REQUEST_RETRY_HTTP_STATUS_CODES,
)

log = logging.getLogger(__name__)
python_check_version(__python_required_version__)


class RequestMvIntegrationUpload(object):
    __mv_request = None

    def __init__(
        self,
        logger_level=logging.INFO,
        logger_format=LoggingFormat.JSON,
        logger_output=LoggingOutput.STDOUT_COLOR
    ):
        self.mv_request = RequestMvIntegration(
            logger_format=logger_format,
            logger_level=logger_level,
            logger_output=logger_output
        )

    @property
    def logger(self):
        return self.mv_request.logger

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
        is_upload_gzip,
        request_label=None,
        upload_timeout=None
    ):
        """Upload File to requested URL.

        :param upload_request_url:
        :param upload_data_file_path:
        :param upload_data_file_size:
        :param is_upload_gzip:
        :param request_label:
        :param upload_timeout:
        :return:
        """
        _request_label = 'Request Upload JSON File'
        request_label = f'{request_label}: {request_label}' if request_label is not None else _request_label

        request_retry_excps = REQUEST_RETRY_EXCPS
        request_retry_http_status_codes = REQUEST_RETRY_HTTP_STATUS_CODES

        upload_request_retry = {"timeout": 60, "tries": -1, "delay": 60}
        upload_request_headers = {'Content-Length': f'{upload_data_file_size}'}

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

        log.info(f'{request_label}: Start', extra=upload_extra)

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
                    request_retry_excps_func=mv_request_retry_excps_func,
                    allow_redirects=False,
                    build_request_curl=False,
                    request_label=request_label
                )

        except TuneRequestBaseError as tmv_ex:
            tmv_ex_extra = tmv_ex.to_dict()
            tmv_ex_extra.update({'error_exception': base_class_name(tmv_ex)})
            log.error(f'{request_label}: Failed', extra=tmv_ex_extra)
            raise

        except Exception as ex:
            print_traceback(ex)

            log.error(
                f'{request_label}: Failed: Unexpected',
                extra={
                    'error_exception': base_class_name(ex),
                    'error_details': get_exception_message(ex)
                }
            )

            raise TuneRequestModuleError(
                error_message=f'{request_label}: Failed: Unexpected: {base_class_name(ex)}: {get_exception_message(ex)}',
                errors=ex,
                error_code=TuneRequestErrorCodes.REQ_ERR_UPLOAD_DATA
            )

        log.info(f'{request_label}: Finished')
        return response

    def request_upload_data(
        self,
        upload_request_url,
        upload_data,
        upload_data_size,
        request_label=None,
        upload_timeout=None,
    ):
        """Upload Data to requested URL.

        :param upload_request_url:
        :param upload_data:
        :param upload_data_size:
        :param upload_timeout:
        :return:
        """
        _request_label = 'Request Upload Data'
        request_label = f'{request_label}: {request_label}' if request_label is not None else _request_label

        log.info(
            f'{request_label}: Start',
            extra={
                'upload_data_size': upload_data_size,
                'upload_request_url': upload_request_url,
            }
        )

        request_retry_excps = REQUEST_RETRY_EXCPS
        request_retry_http_status_codes = REQUEST_RETRY_HTTP_STATUS_CODES

        upload_request_retry = {"timeout": 60, "tries": -1, "delay": 60}

        request_headers = {
            'Content-type': 'application/json; charset=utf8',
            'Accept': 'text/plain',
            'Content-Length': str(upload_data_size)
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
                request_retry_excps_func=mv_request_retry_excps_func,
                request_headers=request_headers,
                allow_redirects=False,
                build_request_curl=False,
                request_label=request_label
            )
        except TuneRequestBaseError as tmv_ex:
            tmv_ex_extra = tmv_ex.to_dict()
            tmv_ex_extra.update({'error_exception': base_class_name(tmv_ex)})

            log.error(f'{request_label}: Failed', extra=tmv_ex_extra)
            raise

        except Exception as ex:
            print_traceback(ex)

            log.error(
                f'{request_label}: Failed: Unexpected',
                extra={'error_exception': base_class_name(ex),
                       'error_details': get_exception_message(ex)}
            )
            raise TuneRequestModuleError(
                error_message=f'{request_label}: Failed: {get_exception_message(ex)}',
                errors=ex,
                error_code=TuneRequestErrorCodes.REQ_ERR_UPLOAD_DATA
            )

        log.info(f'{request_label}: Finished')
        return response
