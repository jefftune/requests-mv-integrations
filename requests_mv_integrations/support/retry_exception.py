#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

import logging
import requests

from requests_mv_integrations import (
    __python_required_version__,
)
from requests_mv_integrations.errors import (
    get_exception_message,
    TuneRequestErrorCodes,
)
from requests_mv_integrations.exceptions.custom import (
    TuneRequestBaseError,
)
from requests_mv_integrations.support.utils import (
    base_class_name,
    python_check_version,
)

log = logging.getLogger(__name__)
python_check_version(__python_required_version__)


def mv_request_retry_excps_func(excp, request_label=None):
    """Request Retry Exception Function

    :param excp:
    :param request_label:
    :return:
    """
    _request_label = 'Request Upload Exception'
    request_label = '{}: {}'.format(request_label, _request_label) if request_label is not None else _request_label

    error_exception = base_class_name(excp)
    error_details = get_exception_message(excp)

    if isinstance(excp, TuneRequestBaseError):
        log.debug(
            f'{request_label}: Expected',
            extra={
                'error_exception': error_exception,
                'error_details': error_details,
            }
        )
    else:
        log.debug(
            f'{request_label}: Unexpected',
            extra={
                'error_exception': error_exception,
                'error_details': error_details,
            }
        )

    if isinstance(excp, requests.exceptions.ConnectionError):
        if error_details.find('RemoteDisconnected') >= 0 or error_details.find('ConnectionResetError') >= 0:
            log.debug(
                f'{request_label}: Retry',
                extra={
                    'error_exception': error_exception,
                    'error_details': error_details,
                }
            )
            return True

    if isinstance(excp, TuneRequestBaseError) and excp.error_code == TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT:
        if error_details.find('RemoteDisconnected') >= 0 or error_details.find('ConnectionResetError') >= 0:
            log.debug(
                f'{request_label}: Retry',
                extra={
                    'error_exception': error_exception,
                    'error_details': error_details,
                }
            )
            return True

    log.debug(
        f'{request_label}: No Retry',
        extra={
            'error_exception': error_exception,
            'error_details': error_details,
        }
    )
    return False
