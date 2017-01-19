#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

import logging
import csv
import datetime as dt
import gzip
import http.client as http_client
import io
import json
import os
import re
import time

import requests
from logging_mv_integrations import (TuneLoggingFormat)
from pprintpp import pprint

from requests_mv_integrations import (__python_required_version__)
from requests_mv_integrations.errors import (get_exception_message, TuneRequestErrorCodes)
from requests_mv_integrations.exceptions.custom import (TuneRequestModuleError,)
from requests_mv_integrations.support import (
    base_class_name,
    bytes_to_human,
    csv_skip_last_row,
    detect_bom,
    handle_json_decode_error,
    python_check_version,
    remove_bom,
    safe_dict,
    validate_response,
    disk_usage,
    mem_usage,
)
from requests_mv_integrations.support.curl import command_line_request_curl
from .request_mv_integration import (RequestMvIntegration)

log = logging.getLogger(__name__)

python_check_version(__python_required_version__)


class RequestMvIntegrationDownload(object):

    __mv_request = None

    def __init__(
        self,
        logger_level=logging.INFO,
        logger_format=TuneLoggingFormat.JSON,
        tune_request=None,
    ):
        self.mv_request = RequestMvIntegration(
            logger_format=logger_format,
            logger_level=logger_level,
            tune_request=tune_request,
        )

    @property
    def session(self):
        return self.mv_request.session

    @property
    def tune_request(self):
        return self.mv_request.tune_request

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

    def request_csv_download(
        self,
        request_method,
        request_url,
        tmp_csv_file_name,
        tmp_directory='./tmp',
        request_params=None,
        request_data=None,
        request_retry=None,
        request_retry_func=None,
        request_retry_excps=None,
        request_retry_http_status_codes=None,
        request_retry_excps_func=None,
        request_headers=None,
        request_auth=None,
        request_label=None,
        build_request_curl=True,
        allow_redirects=True,
        verify=True,
        skip_first_row=False,
        skip_last_row=False,
        read_first_row=False,
        csv_delimiter=',',
        csv_header=None,
        encoding_write=None,
        encoding_read=None,
        decode_unicode=False,
    ):
        """Download and Read CSV file.

        Args:
            request_method: request_method for the new :class:`Request` object.
            request_url: URL for the new :class:`Request` object.
            tmp_csv_file_name: Provide temporary name for downloaded CSV
            tmp_directory: Provide temporary directory to hold downloaded CSV
            request_params: (optional) Dictionary or bytes to be sent in the query
                string for the :class:`Request`.
            request_data: (optional) Dictionary, bytes, or file-like object to
                send in the body of the :class:`Request`.
            request_retry: (optional) Retry configuration.
            request_headers: (optional) Dictionary of HTTP Headers to
                send with the :class:`Request`.
            request_auth: (optional) Auth tuple to enable
                Basic/Digest/Custom HTTP Auth.
            allow_redirects: (optional) Boolean. Set to True if
                POST/PUT/DELETE redirect following is allowed.
            verify: (optional) whether the SSL cert will be verified. A
                CA_BUNDLE path can also be provided. Defaults to ``True``.
            skip_first_row: (optional) Skip first row if it does not contain
                column headers.
            skip_last_row: (optional) Skip first row if it does not contain
                column values.
            read_first_row: (optional) Read first row separate from data returned.
            csv_delimiter: (optional) Delimiter character, default comma ','.
            csv_header:
            encoding_write:
            encoding_read:
            decode_unicode:

        Returns:
            Generator containing CSV data by rows in JSON dictionary format.

        """
        log.info(
            "Request CSV Download: Start",
            extra={
                'request_url': request_url,
                'encoding_write': encoding_write,
                'encoding_read': encoding_read,
                'request_label': request_label
            }
        )

        timer_start = dt.datetime.now()

        _attempts = 0
        _tries = 60
        _delay = 10

        log.info("Request CSV Download: Disk Usage: Start", extra=disk_usage(tmp_directory))
        log.info("Request CSV Download: Memory Usage: Start", extra=mem_usage())

        while _tries:
            _attempts += 1

            log.info(
                "Request CSV Download: Attempt: {}".format(_attempts),
                extra={'request_url': request_url,
                       'request_label': request_label}
            )

            response = self.mv_request.request(
                request_method=request_method,
                request_url=request_url,
                request_params=request_params,
                request_data=request_data,
                request_retry=request_retry,
                request_retry_func=request_retry_func,
                request_retry_excps=request_retry_excps,
                request_retry_http_status_codes=request_retry_http_status_codes,
                request_retry_excps_func=request_retry_excps_func,
                request_headers=request_headers,
                request_auth=request_auth,
                build_request_curl=build_request_curl,
                allow_redirects=allow_redirects,
                verify=verify,
                stream=True,
                request_label=request_label
            )

            if response is None:
                log.error(
                    "Request CSV Download: No response",
                    extra={'request_url': request_url,
                           'request_label': request_label}
                )

                raise TuneRequestModuleError(
                    error_message="Request CSV Download: No response", error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST
                )

            http_status_code = response.status_code

            timer_end = dt.datetime.now()
            timer_delta = timer_end - timer_start
            response_time_secs = timer_delta.seconds
            response_headers = None

            if hasattr(response, 'headers'):
                response_headers = \
                    json.loads(
                        json.dumps(
                            dict(response.headers)
                        )
                    )

            log.debug(
                "Request CSV Download: Response Status",
                extra={
                    'http_status_code': http_status_code,
                    'response_time_secs': response_time_secs,
                    'response_url': response.url,
                    'response_headers': safe_dict(response_headers),
                    'request_label': request_label
                }
            )

            (tmp_csv_file_path, tmp_csv_file_size) = self.download_csv(
                response,
                tmp_directory,
                tmp_csv_file_name,
                request_label=request_label,
                encoding_write=encoding_write,
                decode_unicode=decode_unicode
            )

            if tmp_csv_file_path is not None:
                break

            _tries -= 1
            if not _tries:
                log.error(
                    "Request CSV Download: Exhausted Retries",
                    extra={'tries': _tries,
                           'request_url': request_url,
                           'request_label': request_label}
                )

                raise TuneRequestModuleError(
                    error_message="Request CSV Download: Exhausted Retries",
                    error_code=TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED
                )

            log.info(
                "Request CSV Download: Performing Retry",
                extra={'tries': _tries,
                       'delay': _delay,
                       'request_url': request_url,
                       'request_label': request_label}
            )

            time.sleep(_delay)

        log.info(
            "Request CSV Download: Finished",
            extra={
                'request_label': request_label,
                'file_path': tmp_csv_file_path,
                'file_size': bytes_to_human(tmp_csv_file_size),
                'encoding_read': encoding_read
            }
        )

        log.info("Request CSV Download: Disk Usage: Finished", extra=disk_usage(tmp_directory))
        log.info("Request CSV Download: Memory Usage: Finished", extra=mem_usage())

        with open(file=tmp_csv_file_path, mode='r', encoding=encoding_read) as csv_file_r:
            if read_first_row:
                csv_report_name = csv_file_r.readline()
                csv_report_name = re.sub('\"', '', csv_report_name)
                csv_report_name = re.sub('\n', '', csv_report_name)
                log.info("Request CSV Download: Report '{}'".format(csv_report_name))
            elif skip_first_row:
                next(csv_file_r)

            csv_file_header = next(csv_file_r)
            csv_header_actual = \
                [h.strip() for h in csv_file_header.split(csv_delimiter)]

            csv_header_hr = []
            index = 0
            for column_name in csv_header_actual:
                csv_header_hr.append({'index': index, 'name': column_name})
                index += 1

            log.info("Request CSV Download: Content Header", extra={'csv_header': csv_header_hr})

            csv_fieldnames = csv_header if csv_header else csv_header_actual

            csv_dict_reader = csv.DictReader(csv_file_r, fieldnames=csv_fieldnames, delimiter=csv_delimiter)

            if skip_last_row:
                for row in csv_skip_last_row(csv_dict_reader):
                    yield row
            else:
                for row in csv_dict_reader:
                    yield row

    def request_json_download(
        self,
        request_method,
        request_url,
        tmp_json_file_name,
        tmp_directory='./',
        request_params=None,
        request_data=None,
        request_retry=None,
        request_retry_func=None,
        request_retry_excps=None,
        request_retry_excps_func=None,
        request_headers=None,
        request_auth=None,
        request_label=None,
        build_request_curl=False,
        allow_redirects=True,
        verify=True,
        encoding_write=None,
        encoding_read=None,
    ):
        """Download and Read JSON file.

        Args:
            request_method: request_method for the new :class:`Request` object.
            request_url: URL for the new :class:`Request` object.
            tmp_json_file_name: Provide temporary name for downloaded CSV
            tmp_directory: Provide temporary directory to hold downloaded CSV
            request_params: (optional) Dictionary or bytes to be sent in the query
                string for the :class:`Request`.
            request_data: (optional) Dictionary, bytes, or file-like object to
                send in the body of the :class:`Request`.
            request_retry: (optional) Retry configuration.
            request_headers: (optional) Dictionary of HTTP Headers to
                send with the :class:`Request`.
            request_auth: (optional) Auth tuple to enable
                Basic/Digest/Custom HTTP Auth.
            build_request_curl: (optional) Build a copy-n-paste curl for command line
                that provides same request as this call.
            allow_redirects: (optional) Boolean. Set to True if
                POST/PUT/DELETE redirect following is allowed.
            verify: (optional) whether the SSL cert will be verified. A
                CA_BUNDLE path can also be provided. Defaults to ``True``.
            encoding_write:
            encoding_read:
            decode_unicode:

        Returns:
            Generator containing JSON data by rows in JSON dictionary format.

        """
        log.info(
            "Request JSON Download: Start",
            extra={
                'request_url': request_url,
                'encoding_write': encoding_write,
                'encoding_read': encoding_read,
                'request_label': request_label
            }
        )

        timer_start = dt.datetime.now()

        _attempts = 0
        _tries = 60
        _delay = 10

        log.info("Request JSON Download: Disk Usage: Start", extra=disk_usage(tmp_directory))
        log.info("Request JSON Download: Memory Usage: Start", extra=mem_usage())

        while _tries:
            _attempts += 1

            log.debug(
                "Request JSON Download",
                extra={'attempts': _attempts,
                       'request_url': request_url,
                       'request_label': request_label}
            )

            response = self.mv_request.request(
                request_method=request_method,
                request_url=request_url,
                request_params=request_params,
                request_data=request_data,
                request_retry=request_retry,
                request_retry_func=request_retry_func,
                request_retry_excps=request_retry_excps,
                request_retry_excps_func=request_retry_excps_func,
                request_headers=request_headers,
                request_auth=request_auth,
                build_request_curl=build_request_curl,
                allow_redirects=allow_redirects,
                verify=verify,
                stream=True,
                request_label=request_label
            )

            if response is None:
                log.error(
                    "Request JSON Download: No response",
                    extra={'request_url': request_url,
                           'request_label': request_label}
                )

                raise TuneRequestModuleError(
                    error_message="Request JSON Download: No response",
                    error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST
                )

            http_status_code = response.status_code

            timer_end = dt.datetime.now()
            timer_delta = timer_end - timer_start
            response_time_secs = timer_delta.seconds
            response_headers = None

            if hasattr(response, 'headers'):
                response_headers = \
                    json.loads(
                        json.dumps(
                            dict(response.headers)
                        )
                    )

            log.debug(
                "Request JSON Download: Response Status",
                extra={
                    'http_status_code': http_status_code,
                    'response_time_secs': response_time_secs,
                    'response_url': response.url,
                    'response_headers': safe_dict(response_headers),
                    'request_label': request_label
                }
            )

            if not os.path.exists(tmp_directory):
                os.mkdir(tmp_directory)

            tmp_json_file_path = \
                "{tmp_directory}/{tmp_json_file_name}".format(
                    tmp_directory=tmp_directory,
                    tmp_json_file_name=tmp_json_file_name
                )

            if os.path.exists(tmp_json_file_path):
                log.debug("Request JSON Download: Removing", extra={'file_path': tmp_json_file_path})
                os.remove(tmp_json_file_path)

            mode_write = 'wb' if encoding_write is None else 'w'

            log.debug(
                "Request JSON Download: Finished",
                extra={
                    'file_path': tmp_json_file_path,
                    'mode_write': mode_write,
                    'encoding_write': encoding_write,
                    'request_label': request_label
                }
            )

            log.info("Request JSON Download: Disk Usage: Finished", extra=disk_usage(tmp_directory))
            log.info("Request JSON Download: Memory Usage: Finished", extra=mem_usage())

            chunk_total_sum = 0

            with open(file=tmp_json_file_path, mode=mode_write, encoding=encoding_write) as json_raw_file_w:
                log.debug(
                    "Request JSON Download: Response Raw: Started",
                    extra={'file_path': tmp_json_file_path,
                           'request_label': request_label}
                )

                _tries -= 1
                error_exception = None
                error_details = None
                chunk_size = 8192
                try:
                    raw_response = response.raw
                    while True:
                        chunk = raw_response.read(chunk_size, decode_content=True)
                        if not chunk:
                            break

                        chunk_total_sum += chunk_size

                        json_raw_file_w.write(chunk)
                        json_raw_file_w.flush()
                        os.fsync(json_raw_file_w.fileno())

                    log.debug(
                        "Request JSON Download: By Chunk: Completed",
                        extra={'file_path': tmp_json_file_path,
                               'request_label': request_label}
                    )

                    break

                except requests.exceptions.ChunkedEncodingError as chunked_encoding_ex:
                    error_exception = base_class_name(chunked_encoding_ex)
                    error_details = get_exception_message(chunked_encoding_ex)

                    log.warning(
                        "Request JSON Download: {}".format(error_exception),
                        extra={
                            'error_details': error_details,
                            'chunk_total_sum': chunk_total_sum,
                            'request_label': request_label
                        }
                    )

                    if not _tries:
                        log.error("Request JSON Download: {}: Exhausted Retries".format(error_exception))
                        raise

                except http_client.IncompleteRead as incomplete_read_ex:
                    error_exception = base_class_name(incomplete_read_ex)
                    error_details = get_exception_message(incomplete_read_ex)

                    log.warning(
                        "Request JSON Download: IncompleteRead",
                        extra={
                            'error_exception': error_exception,
                            'error_details': error_details,
                            'chunk_total_sum': chunk_total_sum,
                            'request_label': request_label
                        }
                    )

                    if not _tries:
                        log.error("Request JSON Download: {}: Exhausted Retries".format(error_exception))
                        raise

                except requests.exceptions.RequestException as request_ex:
                    log.error(
                        "Request JSON Download: Request Exception",
                        extra={
                            'error_exception': base_class_name(request_ex),
                            'error_details': get_exception_message(request_ex),
                            'chunk_total_sum': chunk_total_sum,
                            'request_label': request_label
                        }
                    )
                    raise

                except Exception as ex:
                    log.error(
                        "Request JSON Download: Unexpected Exception",
                        extra={
                            'error_exception': base_class_name(ex),
                            'error_details': get_exception_message(ex),
                            'chunk_total_sum': chunk_total_sum,
                            'request_label': request_label
                        }
                    )
                    raise

                if not _tries:
                    log.error(
                        "Request JSON Download: Exhausted Retries",
                        extra={'tries': _tries,
                               'request_url': request_url,
                               'request_label': request_label}
                    )

                    raise TuneRequestModuleError(
                        error_message=("Request JSON Download: Exhausted Retries: {}: {}").format(
                            request_label, request_url
                        ),
                        error_request_curl=self.built_request_curl,
                        error_code=TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED
                    )

                log.info(
                    "Request JSON Download: Performing Retry",
                    extra={
                        'tries': _tries,
                        'delay': _delay,
                        'request_url': request_url,
                        'request_label': request_label
                    }
                )

                time.sleep(_delay)

        tmp_json_file_size = os.path.getsize(tmp_json_file_path)
        bom_enc, bom_len, bom_header = detect_bom(tmp_json_file_path)

        log.info(
            "Request JSON Download: By Chunk: Completed: Details",
            extra={
                'file_path': tmp_json_file_path,
                'file_size': bytes_to_human(tmp_json_file_size),
                'chunk_total_sum': chunk_total_sum,
                'bom_encoding': bom_enc
            }
        )

        if bom_enc == 'gzip':
            tmp_json_gz_file_path = "{}.gz".format(tmp_json_file_path)

            os.rename(src=tmp_json_file_path, dst=tmp_json_gz_file_path)

            with open(file=tmp_json_file_path, mode=mode_write, encoding=encoding_write) as json_file_w:
                log.debug(
                    "Request JSON Download: GZip: Started",
                    extra={'file_path': tmp_json_file_path,
                           'request_label': request_label}
                )

                with gzip.open(tmp_json_gz_file_path, 'r') as gzip_file_r:
                    json_file_w.write(gzip_file_r.read())

        response_extra = {
            'file_path': tmp_json_file_path,
            'file_size': bytes_to_human(tmp_json_file_size),
            'request_label': request_label
        }

        log.info("Request JSON Download: Read Downloaded", extra=response_extra)

        json_download = None
        with open(tmp_json_file_path, mode='r') as json_file_r:
            json_file_content = json_file_r.read()
            try:
                json_download = json.loads(json_file_content)
            except json.decoder.JSONDecodeError as json_decode_ex:
                pprint(json_file_content)

                response_extra.update({
                    'json_file_content': json_file_content,
                    'json_file_content_len': len(json_file_content)
                })

                handle_json_decode_error(
                    response_decode_ex=json_decode_ex,
                    response=response,
                    response_extra=response_extra,
                    request_label=request_label,
                    request_curl=self.built_request_curl
                )

            except Exception as ex:
                pprint(json_file_content)

                response_extra.update({
                    'json_file_content': json_file_content,
                    'json_file_content_len': len(json_file_content)
                })

                log.error("Request JSON Download: Failed: Exception", extra=response_extra)

                handle_json_decode_error(
                    response_decode_ex=ex,
                    response=response,
                    response_extra=response_extra,
                    request_label=request_label,
                    request_curl=self.built_request_curl
                )

        response_extra.update({'json_file_content_len': len(json_download)})

        log.info("Request JSON Download: Finished", extra=response_extra)

        return json_download

    def download_csv(
        self,
        response,
        tmp_directory,
        tmp_csv_file_name,
        request_label=None,
        encoding_write=None,
        decode_unicode=False,
    ):
        log.info("Request Download CSV: Start")

        if not os.path.exists(tmp_directory):
            os.mkdir(tmp_directory)

        tmp_csv_file_path = \
            "{tmp_directory}/{tmp_csv_file_name}".format(
                tmp_directory=tmp_directory,
                tmp_csv_file_name=tmp_csv_file_name
            )

        if os.path.exists(tmp_csv_file_path):
            log.debug("Removing previous CSV", extra={'file_path': tmp_csv_file_path})
            os.remove(tmp_csv_file_path)

        mode_write = 'wb' if encoding_write is None else 'w'

        log.debug(
            "Download CSV: Details",
            extra={
                'file_path': tmp_csv_file_path,
                'mode_write': mode_write,
                'encoding_write': encoding_write,
                'request_label': request_label
            }
        )

        log.info("Download CSV: Disk Usage: Start", extra=disk_usage(tmp_directory))
        log.info("Download CSV: Memory Usage: Start", extra=mem_usage())

        chunk_total_sum = 0

        with open(file=tmp_csv_file_path, mode=mode_write, encoding=encoding_write) as csv_file_wb:
            log.debug(
                "Download CSV: By Chunk: Started",
                extra={'file_path': tmp_csv_file_path,
                       'request_label': request_label}
            )

            error_exception = None
            error_details = None

            try:
                for chunk in response.iter_content(chunk_size=8192, decode_unicode=decode_unicode):
                    if not chunk:
                        break

                    chunk_total_sum += 8192

                    csv_file_wb.write(chunk)
                    csv_file_wb.flush()
                    os.fsync(csv_file_wb.fileno())

                log.debug(
                    "Download CSV: By Chunk: Completed",
                    extra={'file_path': tmp_csv_file_path,
                           'request_label': request_label}
                )

            except requests.exceptions.ChunkedEncodingError as chunked_encoding_ex:
                error_exception = base_class_name(chunked_encoding_ex)
                error_details = get_exception_message(chunked_encoding_ex)

                log.warning(
                    "Download CSV: ChunkedEncodingError",
                    extra={
                        'error_exception': error_exception,
                        'error_details': error_details,
                        'chunk_total_sum': bytes_to_human(chunk_total_sum),
                        'request_label': request_label
                    }
                )

                return (None, 0)

            except http_client.IncompleteRead as incomplete_read_ex:
                error_exception = base_class_name(incomplete_read_ex)
                error_details = get_exception_message(incomplete_read_ex)

                log.warning(
                    "Download CSV: IncompleteRead",
                    extra={
                        'error_exception': error_exception,
                        'error_details': error_details,
                        'chunk_total_sum': bytes_to_human(chunk_total_sum),
                        'request_label': request_label
                    }
                )

                return (None, 0)

            except requests.exceptions.RequestException as request_ex:
                log.error(
                    "Download CSV: Request Exception",
                    extra={
                        'error_exception': base_class_name(request_ex),
                        'error_details': get_exception_message(request_ex),
                        'chunk_total_sum': bytes_to_human(chunk_total_sum),
                        'request_label': request_label
                    }
                )
                raise

            except Exception as ex:
                log.error(
                    "Download CSV: Unexpected Exception",
                    extra={
                        'error_exception': base_class_name(ex),
                        'error_details': get_exception_message(ex),
                        'chunk_total_sum': bytes_to_human(chunk_total_sum),
                        'request_label': request_label
                    }
                )
                raise

        tmp_csv_file_size = os.path.getsize(tmp_csv_file_path)
        bom_enc, bom_len, bom_header = detect_bom(tmp_csv_file_path)

        log.debug(
            "Request Download CSV: By Chunk: Completed: Details",
            extra={
                'file_path': tmp_csv_file_path,
                'file_size': bytes_to_human(tmp_csv_file_size),
                'chunk_total_sum': bytes_to_human(chunk_total_sum),
                'bom_encoding': bom_enc
            }
        )

        log.info("Download CSV: Disk Usage: Finished", extra=disk_usage(tmp_directory))
        log.info("Download CSV: Memory Usage: Finished", extra=mem_usage())

        tmp_csv_file_name_wo_ext = \
            os.path.splitext(
                os.path.basename(tmp_csv_file_name)
            )[0]

        tmp_csv_file_path_wo_bom = \
            "{tmp_directory}/{tmp_csv_file_name}_wo_bom.csv".format(
                tmp_directory=tmp_directory,
                tmp_csv_file_name=tmp_csv_file_name_wo_ext
            )

        if os.path.exists(tmp_csv_file_path_wo_bom):
            os.remove(tmp_csv_file_path_wo_bom)

        bom_enc, bom_len = remove_bom(tmp_csv_file_path, tmp_csv_file_path_wo_bom)

        log.debug("Request Download CSV: Encoding", extra={'bom_enc': bom_enc, 'bom_len': bom_len})

        if bom_len > 0:
            tmp_csv_file_path = tmp_csv_file_path_wo_bom

        return (tmp_csv_file_path, tmp_csv_file_size)

    def stream_csv(
        self,
        request_url,
        request_params,
        csv_delimiter=',',
        tmp_directory='./',
        request_retry=None,
        request_headers=None,
        chunk_size=1024,
        decode_unicode=False,
        remove_bom_length=0
    ):
        """Stream CSV and Yield JSON

        Args:
            request_url:
            request_params:
            csv_delimiter:
            request_retry:
            request_headers:
            chunk_size:
            decode_unicode:
            remove_bom_length:

        Returns:

        """
        log.info("Stream CSV: Start", extra={'report_url': request_url})

        log.info("Stream CSV: Disk Usage: Start", extra=disk_usage(tmp_directory))
        log.info("Stream CSV: Memory Usage: Start", extra=mem_usage())

        response = self.mv_request.request(
            request_method="GET",
            request_url=request_url,
            request_params=request_params,
            request_retry=request_retry,
            request_headers=request_headers,
            stream=True,
            request_label="Stream CSV"
        )

        log.info(
            "Stream CSV: Response",
            extra={
                'response_status_code': response.status_code,
                'response_headers': response.headers,
                'report_url': request_url
            }
        )

        request_curl = command_line_request_curl(
            request_method="GET",
            request_url=request_url,
            request_params=request_params,
            request_headers=request_headers,
        )

        validate_response(response=response, request_curl=request_curl, request_label="Stream CSV")

        response_content_type = response.headers.get('Content-Type', None)
        response_transfer_encoding = response.headers.get('Transfer-Encoding', None)
        response_http_status_code = response.status_code

        log.debug(
            "Request Stream CSV: Status: Details",
            extra={
                'response_content_type': response_content_type,
                'response_transfer_encoding': response_transfer_encoding,
                'response_http_status_code': response_http_status_code
            }
        )

        log.info("Stream CSV: Disk Usage: Finished", extra=disk_usage(tmp_directory))
        log.info("Stream CSV: Memory Usage: Finished", extra=mem_usage())

        line_count = 0
        csv_keys_str = None
        csv_keys_list = None
        csv_keys_list_len = None
        pre_str_line = None

        for bytes_line in response.iter_lines(chunk_size=chunk_size, decode_unicode=decode_unicode):

            if bytes_line:  # filter out keep-alive new chunks
                line_count += 1

                str_line = bytes_line.decode("utf-8")
                if line_count == 1:
                    if remove_bom_length > 0:
                        str_line = str_line[remove_bom_length:]
                    csv_keys_list = str_line.split(csv_delimiter)
                    csv_keys_list = [csv_key.strip() for csv_key in csv_keys_list]
                    csv_keys_list_len = len(csv_keys_list)
                    continue

                if pre_str_line is not None:
                    str_line = pre_str_line + str_line
                    pre_str_line = None

                csv_values_str = str_line.replace('\n', ' ').replace('\r', ' ')

                csv_values_str_io = io.StringIO(csv_values_str)
                reader = csv.reader(csv_values_str_io, delimiter=csv_delimiter)
                csv_values_list = None
                for row in reader:
                    csv_values_list = row

                csv_values_list_len = len(csv_values_list)

                if csv_values_list_len < csv_keys_list_len:
                    pre_str_line = str_line
                    continue

                if csv_keys_list_len != csv_values_list_len:
                    log.error(
                        "Mismatch: CSV Key",
                        extra={
                            'line': line_count,
                            'csv_keys_list_len': csv_keys_list_len,
                            'csv_keys_str': csv_keys_str,
                            'csv_keys_list': csv_keys_list,
                            'csv_values_list_len': csv_values_list_len,
                            'csv_values_str': csv_values_str,
                            'csv_values_list': csv_values_list,
                        }
                    )
                    raise TuneRequestModuleError(
                        error_message="Mismatch: CSV Key '{}': Values '{}'".format(csv_keys_str, csv_values_str),
                        error_code=TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_VALUE
                    )

                json_data_row = {}
                for idx, csv_key in enumerate(csv_keys_list):
                    csv_value = csv_values_list[idx]
                    json_data_row.update({csv_key: csv_value.strip('"')})

                yield json_data_row
