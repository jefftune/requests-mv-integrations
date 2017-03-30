#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

import pytest
from deepdiff import DeepDiff
from requests.auth import HTTPBasicAuth
# from pprintpp import pprint

from requests_mv_integrations.support.curl import command_line_request_curl, parse_curl
from requests_mv_integrations.support.constants import __MODULE_VERSION__, __PYTHON_VERSION__
from requests.cookies import cookiejar_from_dict

_test_command_line_request_curl_get_data_str = [
    (
        'GET', 'https://api.partner.com/find', {
            'Content-Type': 'application/json'
        }, None, 'api_key=11111111222222223333333344444444', None, None, (
            "curl --verbose -X GET "
            "-H 'Content-Type: application/json' "
            "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
            "--connect-timeout 60 -L -G --data 'api_key=11111111222222223333333344444444' "
            "'https://api.partner.com/find'"
        ).format(module_version=__MODULE_VERSION__, python_version=__PYTHON_VERSION__), False,
    ),
]

_test_command_line_request_curl_get_data_dict = [
    (
        'GET', 'https://api.partner.com/find', {
            'Content-Type': 'application/json'
        }, None, {
            'api_key': '11111111222222223333333344444444'
        }, None, None, (
            "curl --verbose -X GET "
            "-H 'Content-Type: application/json' "
            "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
            "--connect-timeout 60 -L -G --data 'api_key=11111111222222223333333344444444' "
            "'https://api.partner.com/find'"
        ).format(module_version=__MODULE_VERSION__, python_version=__PYTHON_VERSION__), False,
    ),
]

_test_command_line_request_curl_get_params_str = [
    (
        'GET', 'https://api.partner.com/find', {
            'Content-Type': 'application/json'
        }, 'api_key=11111111222222223333333344444444', None, None, None, (
            "curl --verbose -X GET "
            "-H 'Content-Type: application/json' "
            "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
            "--connect-timeout 60 -L -G --data 'api_key=11111111222222223333333344444444' "
            "'https://api.partner.com/find'"
        ).format(module_version=__MODULE_VERSION__, python_version=__PYTHON_VERSION__), False,
    ),
]

_test_command_line_request_curl_get_params_dict = [
    (
        'GET', 'https://api.partner.com/find', {
            'Content-Type': 'application/json'
        }, {
            'api_key': '11111111222222223333333344444444'
        }, None, None, None, (
            "curl --verbose -X GET "
            "-H 'Content-Type: application/json' "
            "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
            "--connect-timeout 60 -L -G --data 'api_key=11111111222222223333333344444444' "
            "'https://api.partner.com/find'"
        ).format(module_version=__MODULE_VERSION__, python_version=__PYTHON_VERSION__), False,
    ),
]

_test_command_line_request_curl_get_auth = [
    (
        'GET', 'https://api.partner.com/find', {
            'Content-Type': 'application/json'
        }, None, None, HTTPBasicAuth('username', 'password'), None, (
            "curl --verbose -X GET "
            "-H 'Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=' "
            "-H 'Content-Type: application/json' "
            "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
            "--connect-timeout 60 -L -G "
            "'https://api.partner.com/find'"
        ).format(module_version=__MODULE_VERSION__, python_version=__PYTHON_VERSION__), True,
    ),
]

_test_command_line_request_curl_put = [
    (
        'PUT', 'https://api.partner.com/endpoint', {
            'Content-Type': 'application/json'
        }, None, 'start_date=2016-06-24&end_date=2016-06-24&timezone=UTC', cookiejar_from_dict({
            'myacinfo':
            'NoNsense123Value',
        }), None, (
            "curl --verbose -X PUT "
            "-H 'Content-Type: application/json' "
            "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
            "--connect-timeout 60 "
            "--cookie \"myacinfo=NoNsense123Value\" "
            "-L --data 'start_date=2016-06-24&end_date=2016-06-24&timezone=UTC' "
            "'https://api.partner.com/endpoint'"
        ).format(module_version=__MODULE_VERSION__, python_version=__PYTHON_VERSION__), False,
    ),
    (
        'PUT', 'https://api.partner.com/endpoint', {
            'Content-Type': 'application/json'
        }, None, None, cookiejar_from_dict({
            'myacinfo': 'NoNsense123Value',
        }), None, (
            "curl --verbose -X PUT "
            "-H 'Content-Type: application/json' "
            "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
            "--connect-timeout 60 "
            "--cookie \"myacinfo=NoNsense123Value\" "
            "-L 'https://api.partner.com/endpoint'"
        ).format(module_version=__MODULE_VERSION__, python_version=__PYTHON_VERSION__), False,
    ),
]

_test_command_line_request_curl_post = [
    (
        'POST', 'https://api.partner.com/endpoint', {
            'Content-Type': 'application/json'
        }, None, None, cookiejar_from_dict({
            'myacinfo': 'NoNsense123Value',
        }), None, (
            "curl --verbose -X POST "
            "-H 'Content-Type: application/json' "
            "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
            "--connect-timeout 60 "
            "--cookie \"myacinfo=NoNsense123Value\" "
            "-L 'https://api.partner.com/endpoint'"
        ).format(module_version=__MODULE_VERSION__, python_version=__PYTHON_VERSION__), False,
    ),
    (
        'POST', 'https://api.partner.com/endpoint', {
            'Content-Type': 'application/json'
        }, {
            'end_date': '2016-06-24',
            'start_date': '2016-06-24',
            'timezone': 'UTC',
        }, None, HTTPBasicAuth('username', 'password'), None, (
            "curl --verbose -X POST "
            "-H 'Content-Type: application/json' "
            "-H 'Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=' "
            "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
            "--connect-timeout 60 "
            "-L 'https://api.partner.com/endpoint?end_date=2016-06-24&start_date=2016-06-24&timezone=UTC'"
        ).format(module_version=__MODULE_VERSION__, python_version=__PYTHON_VERSION__), False,
    ),
    (
        'POST', 'https://api.partner.com/endpoint', {
            'Content-Type': 'application/json'
        }, None, 'start_date=2016-06-24&end_date=2016-06-24&timezone=UTC&by_country=y',
        HTTPBasicAuth('username', 'password'), None, (
            "curl --verbose -X POST "
            "-H 'Content-Type: application/json' "
            "-H 'Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=' "
            "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
            "--connect-timeout 60 -L "
            "--data 'start_date=2016-06-24&end_date=2016-06-24&timezone=UTC&by_country=y' "
            "'https://api.partner.com/endpoint'"
        ).format(module_version=__MODULE_VERSION__, python_version=__PYTHON_VERSION__), False,
    ),
    (
        'POST', 'https://api.partner.com/endpoint', {
            'Content-Type': 'application/json'
        }, None, None, HTTPBasicAuth('username', 'password'), {
            'type': 'campaigns',
        }, (
            "curl --verbose -X POST "
            "-H 'Content-Type: application/json' "
            "-H 'Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=' "
            "-H 'User-Agent: (requests-mv-integrations/{module_version}, Python/{python_version})' "
            "--connect-timeout 60 -L "
            "--data {request_json} "
            "'https://api.partner.com/endpoint'"
        ).format(
            module_version=__MODULE_VERSION__,
            python_version=__PYTHON_VERSION__,
            request_json="'{\"type\":\"campaigns\"}'"
        ), False,
    ),
]

_all_tests_params = (
    _test_command_line_request_curl_get_params_str + _test_command_line_request_curl_get_params_dict +
    _test_command_line_request_curl_get_data_str + _test_command_line_request_curl_get_data_dict +
    _test_command_line_request_curl_get_auth + _test_command_line_request_curl_post +
    _test_command_line_request_curl_put
)


@pytest.mark.parametrize(
    "request_method, request_url, request_headers, request_params, request_data, "
    "request_auth, request_json, curl_expected, is_check_lenghth_only",
    _all_tests_params,
)
def test_command_line_request_curl(
    request_method,
    request_url,
    request_headers,
    request_params,
    request_data,
    request_auth,
    request_json,
    curl_expected,
    is_check_lenghth_only,
):
    curl_actual = command_line_request_curl(
        request_method=request_method,
        request_url=request_url,
        request_headers=request_headers,
        request_params=request_params,
        request_data=request_data,
        request_auth=request_auth,
        request_json=request_json,
    )
    parsed_curl_actual = parse_curl(curl_actual)
    parsed_curl_expected = parse_curl(curl_expected)
    if is_check_lenghth_only:
        assert len(parsed_curl_actual) == len(parsed_curl_expected)
    else:
        ddiff = DeepDiff(parsed_curl_actual, parsed_curl_expected, ignore_order=True)
        assert ddiff == {}
