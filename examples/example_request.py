#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

import logging

from pprintpp import pprint
from requests_mv_integrations import (
    RequestMvIntegrationDownload,
    __version__,
)
from requests_mv_integrations.support import (HEADER_CONTENT_TYPE_APP_JSON)
from logging_mv_integrations import (
    TuneLogging,
    TuneLoggingFormat,
)

URL_TUNE_MAT_API_COUNTRIES = \
    'https://api.mobileapptracking.com/v2/countries/find.json'

tune_requests_mv_intgs = RequestMvIntegrationDownload(logger_level=logging.DEBUG)

log = TuneLogging(
    logger_name=__name__.split('.')[0],
    logger_version=__version__,
    logger_level=logging.DEBUG,
    logger_format=TuneLoggingFormat.JSON
)

log.info("Start")

result = \
    tune_requests_mv_intgs.request(
        request_method='GET',
        request_url=URL_TUNE_MAT_API_COUNTRIES,
        request_params=None,
        request_retry=None,
        request_headers=HEADER_CONTENT_TYPE_APP_JSON,
        request_label="TMC Countries"
    )

log.info("Completed", extra=vars(result))

json_tune_mat_countries = result.json()

pprint(json_tune_mat_countries)
