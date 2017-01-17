#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

import re
import json
import urllib.parse
from .constants import (__USER_AGENT__)
from base64 import b64encode
import requests
import shlex
import argparse

# from pprintpp import pprint


def _to_native_string(string, encoding='ascii'):
    """Given a string object, regardless of type, returns a representation of
    that string in the native string type, encoding and decoding where
    necessary. This assumes ASCII unless told otherwise.
    """
    if isinstance(string, str):
        out = string
    else:
        out = string.decode(encoding)

    return out


def _basic_auth_str(username, password):
    """Returns a Basic Auth string."""

    if isinstance(username, str):
        username = username.encode('latin1')

    if isinstance(password, str):
        password = password.encode('latin1')

    authstr = 'Basic ' + _to_native_string(b64encode(b':'.join((username, password))).strip())

    return authstr


def command_line_request_curl(
    request_method,
    request_url,
    request_headers,
    request_params=None,
    request_data=None,
    request_auth=None,
    request_json=None,
    request_timeout=60,
    request_allow_redirects=True
):
    """Command Line: Build Request cUrl

    Args:
        request_method:
        request_url:
        request_headers:
        request_data:
        request_timeout:
        request_allow_redirects:

    Returns:

    """
    key_user_agent = 'User-Agent'
    header_user_agent = {key_user_agent: __USER_AGENT__}

    if request_method == 'GET':
        if request_params:
            assert request_data is None
            if isinstance(request_params, dict):
                request_data = urllib.parse.urlencode(request_params)
            elif isinstance(request_params, str):
                request_data = request_params

    elif request_method in ['POST', 'PUT']:
        if request_params:
            request_url += "?" + urllib.parse.urlencode(request_params)

    if request_auth and isinstance(request_auth, requests.auth.HTTPBasicAuth):
        username = request_auth.username
        password = request_auth.password

        header_basic_auth = {'Authorization': _basic_auth_str(username, password)}

        if request_headers:
            if 'Authorization' not in request_headers:
                request_headers.update(header_basic_auth)
        else:
            request_headers = header_basic_auth

    if request_headers:
        if key_user_agent not in request_headers:
            request_headers.update(header_user_agent)
    else:
        request_headers = header_user_agent

    request_method = request_method.upper()

    command = ("curl" " --verbose" " -X {request_method}" " -H {headers}" " --connect-timeout {timeout}")

    if request_allow_redirects:
        command += " -L"

    if request_method == 'GET':
        if request_data:
            params = request_data.split("&")

            command += (" -G" " --data {params}" " '{url}'")

            params = ["'{0}'".format(urllib.parse.unquote(param)) for param in params]
            params = " --data ".join(params)

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method,
                headers=headers,
                params=params,
                timeout=request_timeout,
                url=request_url,
            )
        else:
            command += (" '{url}'")

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method,
                headers=headers,
                timeout=request_timeout,
                url=request_url,
            )

    elif request_method == 'POST':
        if request_data:
            command += (" --data '{data}'" " '{url}'")

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method,
                headers=headers,
                data=request_data,
                timeout=request_timeout,
                url=request_url
            )
        elif request_json:
            command += (" --data '{data}'" " '{url}'")

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method,
                headers=headers,
                data=json.dumps(request_json),
                timeout=request_timeout,
                url=request_url
            )
        else:
            command += (" '{url}'")

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)
            return command.format(
                request_method=request_method,
                headers=headers,
                timeout=request_timeout,
                url=request_url,
            )

    elif request_method == 'PUT':
        if request_data:
            rows = re.split(r'\n', request_data)
            row = None
            if rows and len(rows) > 0:
                row = rows[0]

            command += (" --data '{data}'" " '{url}'")

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method,
                headers=headers,
                data=row,
                timeout=request_timeout,
                url=request_url,
            )
        else:
            command += (" '{url}'")

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)
            return command.format(
                request_method=request_method,
                headers=headers,
                timeout=request_timeout,
                url=request_url,
            )


def parse_curl(curl_command):

    parser = argparse.ArgumentParser()
    parser.add_argument('command')
    parser.add_argument('url')
    parser.add_argument('-d', '--data')
    parser.add_argument('-X', '--request', help="Specify request command to use", default="GET")
    parser.add_argument('-v', '--verbose', help="increase output verbosity", action="store_true")
    parser.add_argument('-V', '--version', help="Show version number and quit", action="store_true")
    parser.add_argument('-G', '--get', help="Send the -d data with a HTTP GET", action="store_true")
    parser.add_argument('-L', '--location', help="Follow redirects", action="store_true")
    parser.add_argument('-b', '--data-binary', default=None)
    parser.add_argument('-H', '--header', action='append', default=[])
    parser.add_argument('--compressed', action='store_true')
    parser.add_argument('--connect-timeout', default=None)

    tokens = shlex.split(curl_command)
    parsed_args = parser.parse_args(tokens)

    parsed_curl = vars(parsed_args)

    return parsed_curl
