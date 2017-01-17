#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integration

import pytest

from requests_mv_integrations.support.response import validate_response, validate_json_response
from requests_mv_integrations.exceptions import TuneRequestModuleError
from requests_toolbelt.utils import dump
from requests_mv_integrations.errors import TuneRequestErrorCodes
from requests.models import Response, codes

response_ok = Response()
response_ok.status_code = codes.ok
response_bad = Response()
response_bad.status_code = codes.bad

_test_validate_responce_input_output = [('response_ok', True), ('response_bad', False)]

_test_validate_json_responce_input_output = [
    ('response_ok_no_headers', TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_CONTENT_TYPE_RETURNED),
    ('response_bad', TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_SOFTWARE),
    ('response_ok_with_valid_json_content', None, None),
    ('response_ok_with_invalid_json_content', TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_SOFTWARE),
    (
        'response_ok_with_valid_html_content', TuneRequestModuleError,
        TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_CONTENT_TYPE_RETURNED
    ),
    (
        'response_ok_with_invalid_html_content', TuneRequestModuleError,
        TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_CONTENT_TYPE_RETURNED
    ),
]


@pytest.mark.parametrize("response, expected", _test_validate_responce_input_output)
def test_validate_response(response, expected, responses_dict):
    res = True
    try:
        validate_response(
            response=responses_dict[response],
            request_curl="Not important request curl",
            request_label="Not important request label",
        )
    except TuneRequestModuleError:
        res = False
    assert res == expected


@pytest.mark.parametrize(
    "request_response, expected_exception_type, expected_exception_error_code",
    _test_validate_json_responce_input_output
)
def test_validate_json_response(
    request_response,
    expected_exception_type,
    expected_exception_error_code,
    responses_dict,
    monkeypatch,
):
    monkeypatch.setattr(dump, 'dump_all', lambda x: b'Test')
    try:
        validate_json_response(
            response=responses_dict[request_response],
            request_curl="curl --verbose -X GET -H 'Content-Type: application/json' -H 'User-Agent: (requests-mv-integrations/0.2.2, Python/3.5.2)' --connect-timeout 60 -L -G --data 'apiKey=abcdefg-10hi-42j9-kl31-m0no5p35qr72' --data 'type=byoffer' --data 'fromDate=2016-08-12' --data 'toDate=2016-08-12' 'http://dashboard.unittests.com/dashboardapi/unittestsreports'",
            request_label="Unit Testing validate_json_response()",
        )
    except Exception as e:
        assert (type(e) == expected_exception_type)
        if expected_exception_error_code is not None:
            assert (e.error_code == expected_exception_error_code)
