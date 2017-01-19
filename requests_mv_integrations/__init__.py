#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

__title__ = 'requests-mv-integrations'
__version__ = '0.03.1'
__build__ = 0x000301
__version_info__ = tuple(__version__.split('.'))

__author__ = 'jefft@tune.com'
__license__ = 'MIT License'

__python_required_version__ = (3, 0)

from requests_mv_integrations.support.tune_request import (TuneRequest)

from .request_mv_integration import (RequestMvIntegration)
from .request_mv_integration_download import (RequestMvIntegrationDownload)
from .request_mv_integration_upload import (RequestMvIntegrationUpload)
