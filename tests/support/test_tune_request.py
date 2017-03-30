#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)

import pytest
import requests
import requests_mv_integrations


def test_request():
    request_object = requests_mv_integrations.support.TuneRequest()
    assert isinstance(request_object, requests_mv_integrations.support.TuneRequest)
    assert isinstance(request_object.session, requests.Session)


def test_session():
    request_session = requests.Session()
    assert isinstance(request_session, requests.Session)
    request_object = requests_mv_integrations.support.TuneRequest(session=request_session)
    assert request_object.session is request_session


def test_session_not_same():
    request_object = requests_mv_integrations.support.TuneRequest()
    assert isinstance(request_object, requests_mv_integrations.support.TuneRequest)
    request_object2 = requests_mv_integrations.support.TuneRequest()
    assert isinstance(request_object2, requests_mv_integrations.support.TuneRequest)
    assert request_object is not request_object2
    assert isinstance(request_object.session, requests.Session)
    assert isinstance(request_object2.session, requests.Session)
    assert request_object.session is not request_object2.session


@pytest.mark.parametrize(
    "retry_code",
    (500, 501, 502),
)
def test_retries_throws_error(retry_code):
    obj = requests_mv_integrations.support.TuneRequest(retry_codes=[retry_code])
    with pytest.raises(requests.exceptions.RetryError):
        obj.request('GET', "http://localhost:8998/status/" + str(retry_code))


@pytest.mark.parametrize("retry_code, status", ((501, 500), (502, 503),))
def test_no_retries(retry_code, status):
    obj = requests_mv_integrations.support.TuneRequest(retry_codes=[retry_code])
    obj.request('GET', "http://localhost:8998/status/" + str(status))
