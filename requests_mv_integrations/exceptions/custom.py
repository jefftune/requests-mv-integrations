#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

from requests_mv_integrations.errors.error_codes import TuneRequestErrorCodes
from requests_mv_integrations.exceptions.base import (TuneRequestBaseError)


class TuneRequestError(TuneRequestBaseError):
    pass


class TuneRequestClientError(TuneRequestBaseError):
    pass


class TuneRequestServiceError(TuneRequestBaseError):
    pass


class TuneRequestModuleError(TuneRequestBaseError):
    pass


class TuneRequestClientGoneError(TuneRequestModuleError):
    """Request Mv Integration: Value error"""

    def __init__(self, **kwargs):
        error_code = kwargs.pop('error_code', None) or \
            TuneRequestErrorCodes.GONE
        super(TuneRequestClientGoneError, self).__init__(error_code=error_code, **kwargs)


class TuneRequestValueError(TuneRequestModuleError):
    """Request Mv Integration: Value error"""

    def __init__(self, **kwargs):
        error_code = kwargs.pop('error_code', None) or \
            TuneRequestErrorCodes.REQ_ERR_ARGUMENT
        super(TuneRequestValueError, self).__init__(error_code=error_code, **kwargs)


class TuneRequestAuthenticationError(TuneRequestModuleError):
    """Request Mv Integration: Authentication error"""

    def __init__(self, **kwargs):
        error_code = kwargs.pop('error_code', None) or \
            TuneRequestErrorCodes.REQ_ERR_AUTH_ERROR
        super(TuneRequestAuthenticationError, self).__init__(error_code=error_code, **kwargs)
