#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

import logging

from pprintpp import pprint
from requests_mv_integrations import (
    RequestMvIntegrationDownload,
)
from requests_mv_integrations.support import (
    HEADER_CONTENT_TYPE_APP_JSON
)
from logging_mv_integrations import (
    LoggingFormat,
    LoggingOutput
)

URL_TUNE_MAT_API_COUNTRIES = \
    'https://api.mobileapptracking.com/v2/countries/find.json'

request_download = RequestMvIntegrationDownload(
    logger_level=logging.DEBUG,
    logger_output=LoggingOutput.FILE,
    logger_format=LoggingFormat.JSON,
)

request_download.logger.note(request_download.logger.getLevelName().lower())
request_download.logger.info("Start".upper())

result = \
    request_download.request(
        request_method='GET',
        request_url=URL_TUNE_MAT_API_COUNTRIES,
        request_params=None,
        request_retry=None,
        request_headers=HEADER_CONTENT_TYPE_APP_JSON,
        request_label="TMC Countries"
    )

request_download.logger.info("Completed".upper(), extra=vars(result))

pprint(f"Logger file path: {request_download.logger.logger_path}")

logger_fp = open(request_download.logger.logger_path, 'r')
pprint(logger_fp.readlines())

pprint(request_download.logger.getLevelName())

json_tune_mat_countries = result.json()
pprint(json_tune_mat_countries)
