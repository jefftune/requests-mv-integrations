#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)

import requests
from requests_mv_integrations.support import (
    mv_request_retry_excps_func,
)

def test_request_retry_excps_func_failed():
    assert not mv_request_retry_excps_func(excp=Exception)

def test_request_retry_excps_func_connectionerror_failed():
    assert not mv_request_retry_excps_func(excp=requests.exceptions.ConnectionError)

def test_request_retry_excps_func_connectionerror_remotedisconnected():
    assert mv_request_retry_excps_func(excp=requests.exceptions.ConnectionError('RemoteDisconnected'))

def test_request_retry_excps_func_connectionerror_connectionreseterror():
    assert mv_request_retry_excps_func(excp=requests.exceptions.ConnectionError('ConnectionResetError'))