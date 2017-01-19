#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integration

import pytest
# from pprintpp import pprint

from requests_mv_integrations.support.utils import (python_check_version, full_class_name,urlencode_dict)
from requests_mv_integrations import (
    __python_required_version__,
    RequestMvIntegration,
)

def test_python_check_version_good():
    assert python_check_version(__python_required_version__) == 0

def test_python_check_version_bad(capsys):
    with pytest.raises(SystemExit):
        python_check_version((4, 0))

    out, err = capsys.readouterr()
    assert err

def test_full_class_name():
    assert full_class_name(RequestMvIntegration()) == \
        "requests_mv_integrations.request_mv_integration.RequestMvIntegration"

def test_urlencode_dict():
    assert urlencode_dict({'a': 1, 'b': 2, 'c': 3}) in \
        [ "c=3&b=2&a=1", "b=2&a=1&c=3", "a=1&b=2&c=3", 'b=2&c=3&a=1' ]