#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integration

import pytest
from deepdiff import DeepDiff
from requests.auth import HTTPBasicAuth
# from pprintpp import pprint

from requests_mv_integrations.support.curl import command_line_request_curl, parse_curl
from requests_mv_integrations.support.constants import __MODULE_VERSION__, __PYTHON_VERSION__

_test_command_line_request_curl_get = [(
    'GET',
    'https://api.partner.com/find',
    {
        'Content-Type': 'application/json'
    },
    'api_key=11111111222222223333333344444444',
    (
        "curl --verbose -X GET "
        "-H 'Content-Type: application/json' "
        "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
        "--connect-timeout 60 -L -G --data 'api_key=11111111222222223333333344444444' "
        "'https://api.partner.com/find'"
    ).format(
        module_version=__MODULE_VERSION__, python_version=__PYTHON_VERSION__
    ),
),]

_test_command_line_request_curl_get_auth = [(
    'GET',
    'https://api.partner.com/find',
    {
        'Content-Type': 'application/json'
    },
    HTTPBasicAuth('username', 'password'),
    (
        "curl --verbose -X GET "
        "-H 'Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=' "
        "-H 'Content-Type: application/json' "
        "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
        "--connect-timeout 60 -L -G "
        "'https://api.partner.com/find'"
    ).format(
        module_version=__MODULE_VERSION__, python_version=__PYTHON_VERSION__
    ),
),]


@pytest.mark.parametrize(
    "request_method, request_url, request_headers, request_data, curl_expected", _test_command_line_request_curl_get
)
def test_curl_get_data(request_method, request_url, request_data, request_headers, curl_expected):
    curl_actual = command_line_request_curl(
        request_method=request_method,
        request_url=request_url,
        request_headers=request_headers,
        request_data=request_data
    )

    parsed_curl_actual = parse_curl(curl_actual)
    parsed_curl_expected = parse_curl(curl_expected)
    ddiff = DeepDiff(parsed_curl_actual, parsed_curl_expected, ignore_order=True)

    assert ddiff == {}


@pytest.mark.parametrize(
    "request_method, request_url, request_headers, request_params, curl_expected", _test_command_line_request_curl_get
)
def test_curl_get_params(request_method, request_url, request_params, request_headers, curl_expected):
    curl_actual = command_line_request_curl(
        request_method=request_method,
        request_url=request_url,
        request_headers=request_headers,
        request_params=request_params
    )

    parsed_curl_actual = parse_curl(curl_actual)
    parsed_curl_expected = parse_curl(curl_expected)
    ddiff = DeepDiff(parsed_curl_actual, parsed_curl_expected, ignore_order=True)

    assert ddiff == {}


@pytest.mark.parametrize(
    "request_method, request_url, request_headers, request_auth, curl_expected",
    _test_command_line_request_curl_get_auth
)
def test_curl_get_auth(request_method, request_url, request_auth, request_headers, curl_expected):
    curl_actual = command_line_request_curl(
        request_method=request_method,
        request_url=request_url,
        request_headers=request_headers,
        request_auth=request_auth
    )

    parsed_curl_actual = parse_curl(curl_actual)
    parsed_curl_expected = parse_curl(curl_expected)

    assert len(parsed_curl_actual) == len(parsed_curl_expected)
