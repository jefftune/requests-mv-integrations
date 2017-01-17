#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integration

import pytest
import requests
import requests_mock

from requests_mv_integrations import RequestMvIntegration
from requests_mv_integrations.exceptions import (
    TuneRequestBaseError,
    TuneRequestServiceError,
    TuneRequestModuleError,
)

from requests_mv_integrations.errors import TuneRequestErrorCodes

from requests_mv_integrations import TuneRequest

from requests.models import Response

from requests.exceptions import ReadTimeout

request_raised_exceptions_test_object = (
    (requests.exceptions.ConnectTimeout, TuneRequestServiceError, TuneRequestErrorCodes.GATEWAY_TIMEOUT),
    (requests.exceptions.ReadTimeout, TuneRequestServiceError, TuneRequestErrorCodes.GATEWAY_TIMEOUT),
    (requests.exceptions.Timeout, TuneRequestServiceError, TuneRequestErrorCodes.GATEWAY_TIMEOUT),
    (requests.exceptions.HTTPError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_HTTP),
    (BrokenPipeError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT),
    (ConnectionError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT),
    (
        requests.packages.urllib3.exceptions.ProtocolError, TuneRequestModuleError,
        TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT
    ),
    (
        requests.packages.urllib3.exceptions.ReadTimeoutError, TuneRequestServiceError,
        TuneRequestErrorCodes.GATEWAY_TIMEOUT
    ),
    (requests.exceptions.TooManyRedirects, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_REDIRECTS),
    (requests.exceptions.RequestException, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST),
    (TuneRequestBaseError, TuneRequestBaseError, TuneRequestErrorCodes.REQ_ERR_UNEXPECTED),
    (Exception, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_SOFTWARE),
)


@pytest.fixture
def custom_matcher(request):
    resp = requests.Response()
    if 'OK' in request.path_url:
        resp.status_code = requests.codes.ok
        resp._content = 'All Good!'
    elif 'BAD' in request.path_url:
        resp.status_code = requests.codes.bad
        resp._content = 'Bad Request!'
    else:
        del resp
        resp = None
    return resp


@pytest.fixture
def request_mv_integration_object():
    """
    :return: A RequestMvIntegration object
    """
    obj = RequestMvIntegration()
    obj.retry_tries, obj.retry_delay, obj.timeout = 3, 1, 10
    obj.request_retry_excps = [ReadTimeout]
    return obj


@pytest.fixture
def tune_request_object():
    """
    Create a TuneRequest object.
    Tweak the session data member by mounting a mock adapter on it.
    When a request is initiated, the mocked adapter will build a response according
    to the path url, as implemented in the fixture <custom_matcher>
    :return: A TuneRequest instance with a custom adapter
    """
    obj = TuneRequest()
    session = requests.Session()
    adapter = requests_mock.Adapter()
    session.mount('mock', adapter)
    adapter.add_matcher(custom_matcher)
    obj.session = session
    return obj


@pytest.fixture
def ok_request_args_dict():
    """
    :return: A dictionary of arguments for a request, which should return an OK response.
    """
    return {
        'allow_redirects': True,
        'headers': {
            'Content-Type': 'application/json',
            'User-Agent': '(requests-mv-integrations/0.2.1, Python/3.5.2)'
        },
        'params': 'key=11111111222222223333333344444444',
        'request_method': 'GET',
        'request_url': 'mock://test.com/path/OK',
        'timeout': (240, 240),
        'verify': True
    }


class RequestRetryException(TuneRequestBaseError):
    pass


_request_retry_test_object = (
    ('RequestRetryException', None),
    ('TuneRequestBaseError', None),
    ('Exception', None),
    ('TuneRequestModuleError', TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED),
    ('TuneRequestModuleError', TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_VALUE),
)

try_send_request_test_object = (
    (
        None,
        None,
        'response_none',
        None,
        'response=None',
        None,
        None,
        None,
        'TuneRequestModuleError',
        TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_VALUE,
        False,
    ),
    (
        1,
        3,
        'response_ok_with_valid_json_content',
        None,
        'OK reponse && request_retry_func=True',
        lambda x: True,
        None,
        'www.requesturl.com',
        None,
        None,
        None,
    ),
    (
        2,
        0,
        'response_ok_with_valid_json_content',
        None,
        'OK reponse && request_retry_func=True && Request tries exhausted',
        lambda x: True,
        None,
        'www.requesturl.com',
        'TuneRequestModuleError',
        TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED,
        False,
    ),
    (
        1,
        3,
        'response_ok_with_valid_json_content',
        None,
        'OK reponse && request_retry_func=False',
        lambda x: False,
        None,
        'www.requesturl.com',
        None,
        None,
        True,
    ),
    (
        1,
        3,
        'response_ok_with_valid_json_content',
        ReadTimeout,
        'Request Retry Exception thrown && tries>0',
        lambda x: False,
        None,
        'www.requesturl.com',
        None,
        None,
        False,
    ),
    (
        1,
        0,
        'response_ok_with_valid_json_content',
        ReadTimeout,
        'Request Retry Exception thrown && tries==0',
        lambda x: False,
        None,
        'www.requesturl.com',
        'ReadTimeout',
        None,
        False,
    ),
    (
        1,
        3,
        'response_ok_with_valid_json_content',
        TuneRequestServiceError,
        'TuneRequestServiceError && request_retry_excps_func==False',
        lambda x: False,
        lambda x, y: False,
        'www.requesturl.com',
        'TuneRequestServiceError',
        None,
        False,
    ),
    (
        1,
        3,
        'response_ok_with_valid_json_content',
        TuneRequestServiceError,
        'TuneRequestServiceError && request_retry_excps_func==True && tries>0',
        lambda x: False,
        lambda x, y: True,
        'www.requesturl.com',
        None,
        None,
        False,
    ),
    (
        1,
        0,
        'response_ok_with_valid_json_content',
        TuneRequestServiceError,
        'TuneRequestServiceError && request_retry_excps_func==True && tries==0',
        lambda x: False,
        lambda x, y: True,
        'www.requesturl.com',
        'TuneRequestServiceError',
        None,
        False,
    ),
    (
        1,
        3,
        'response_ok_with_valid_json_content',
        Exception,
        'General Exception && request_retry_excps_func==False',
        lambda x: False,
        lambda x, y: False,
        'www.requesturl.com',
        'Exception',
        None,
        False,
    ),
    (
        1,
        3,
        'response_ok_with_valid_json_content',
        Exception,
        'General Exception && request_retry_excps_func==True && tries>0',
        lambda x: False,
        lambda x, y: True,
        'www.requesturl.com',
        None,
        None,
        False,
    ),
    (
        1,
        0,
        'response_ok_with_valid_json_content',
        Exception,
        'General Exception && request_retry_excps_func==True && tries==0',
        lambda x: False,
        lambda x, y: True,
        'www.requesturl.com',
        'TuneRequestModuleError',
        TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED,
        False,
    ),
)


@pytest.fixture(scope='session')
def exceptions():
    exceptions_dict = dict()
    exceptions_dict[RequestRetryException.__name__] = RequestRetryException()
    exceptions_dict[TuneRequestBaseError.__name__] = TuneRequestBaseError()
    exceptions_dict[Exception.__name__] = Exception()
    exceptions_dict[TuneRequestModuleError.__name__] = dict()
    exceptions_dict[TuneRequestModuleError.__name__][TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED
                                                     ] = TuneRequestModuleError(
                                                         error_code=TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED
                                                     )
    exceptions_dict[TuneRequestModuleError.__name__][TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_VALUE
                                                     ] = TuneRequestModuleError(
                                                         error_code=TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_VALUE
                                                     )
    return exceptions_dict


class TestRequestMvIntegration:
    """
    A test class, for testing RequestMvIntegration methods.
    """

    @pytest.mark.parametrize("requests_error, mv_integration_error, error_code", request_raised_exceptions_test_object)
    def test_request_raised_exceptions(
        self, monkeypatch, request_mv_integration_object, requests_error, mv_integration_error, error_code
    ):
        """
        Test RequestMvIntegration.request() exception handling, my mocking the call
        to RequestMvIntegration._request_retry()
        :param monkeypatch:
        :param request_mv_integration_object: An instance of RequestMvIntegration.
        :param requests_error: The exception which the mock function of
        RequestMvIntegration._request_retry() throws.
        :param mv_integration_error: The exception which tested RequestMvIntegration.request()
        should throw in response to <requests_error>.
        :return: assert that the expected thrown exception of RequestMvIntegration.request()
        is the correct one.
        """

        def mock__request_retry(*args, **kwargs):
            if requests_error == requests.packages.urllib3.exceptions.ReadTimeoutError:
                raise requests_error('pool', 'url', 'message')
            raise requests_error

        req = request_mv_integration_object
        monkeypatch.setattr(req, '_request_retry', mock__request_retry)
        try:
            req.request(request_method="Doesn't matter", request_url="Doesn't matter")
        except Exception as e:
            assert (isinstance(e, mv_integration_error))
            assert (e.error_code == error_code)

    def test_request_happy_path(self, request_mv_integration_object, tune_request_object, ok_request_args_dict):
        """
        A test for a happy path:
        Call RequestMvIntegration.request() and expect to receive a requests.Response object
        with a requests.codes.ok status
        This is a full path test. The only mocked part, is the requests.Session object, which is
        a 3rd party package.
        :param request_mv_integration_object: A fixture that returns a RequestMvIntegration instance
        :param tune_request_object: A fixture that returns a TuneRequest instance with a custom adapter
        :param ok_request_args_dict: A dictionary of arguments for the request, which should return an OK response.
        :return: Assert
        """
        req = request_mv_integration_object
        tr = tune_request_object
        req.__tune_request = tr
        request_args = ok_request_args_dict
        resp = req.request(request_method=request_args['request_method'], request_url=request_args['request_url'])
        assert (resp.status_code == requests.codes.ok)

    @pytest.mark.parametrize("exception_type_name, error_code", _request_retry_test_object)
    def test__request_retry(
        self, exception_type_name, error_code, exceptions, request_mv_integration_object, monkeypatch
    ):
        def mock_try_send_request(_attempts, _tries, request_func, request_label, request_retry_func, request_url):
            if exception_type_name in exceptions:
                all_exception_type_exceptions = exceptions[exception_type_name]
                if error_code is not None:
                    if error_code in all_exception_type_exceptions:
                        exception_instance = all_exception_type_exceptions[error_code]
                        raise exception_instance
                    else:
                        raise Exception(
                            "Bad input to test: No {} exception with error code {}".
                            format(exception_type_name, error_code)
                        )
                else:
                    exception_instance = all_exception_type_exceptions
                    raise exception_instance
            else:
                raise Exception("Bad input to test: No {} exceptions".format(exception_type_name))

        monkeypatch.setattr(request_mv_integration_object, 'try_send_request', mock_try_send_request)
        request_mv_integration_object.request_retry_excps = [RequestRetryException]
        try:
            request_mv_integration_object._request_retry(call_func=lambda *args, **kwargs: None)
        except Exception as e:
            assert (type(e).__name__ == exception_type_name)
            if error_code is not None:
                assert (e.error_code == error_code)

    @pytest.mark.parametrize(
        "attempts, tries, response_type, exception_thrown_by_request_func, request_label, request_retry_func, request_retry_excps_func, request_url, expected_exception_name, expected_error_code, is_expected_response",
        try_send_request_test_object
    )
    def test_try_send_request(
        self,
        attempts,
        tries,
        response_type,
        exception_thrown_by_request_func,
        request_label,
        request_retry_func,
        request_retry_excps_func,
        request_url,
        expected_exception_name,
        expected_error_code,
        is_expected_response,
        request_mv_integration_object,
        responses_dict,
    ):
        def mock_request_func():
            assert (
                exception_thrown_by_request_func is not None or response_type is not None and
                response_type in responses_dict
            )
            if exception_thrown_by_request_func is not None:
                raise exception_thrown_by_request_func
            if response_type is not None:
                return responses_dict[response_type]

        request_mv_integration_object.request_retry_excps_func = request_retry_excps_func

        to_raise_exception, to_return_response = request_mv_integration_object.try_send_request(
            attempts,
            tries,
            mock_request_func,
            request_label,
            request_retry_func,
            request_url,
        )
        # Can't have a result of both throwing an exception and returning a valid response
        assert (to_raise_exception is None or to_return_response is None)
        # In case if throwing an exception, check that the expected type is thrown,
        # with the expected error code if provided
        if expected_exception_name is not None:
            assert (type(to_raise_exception).__name__ == expected_exception_name)
        else:
            assert (to_raise_exception is None)
        if expected_error_code is not None:
            assert (to_raise_exception.error_code == expected_error_code)
        if is_expected_response:
            assert (isinstance(to_return_response, Response))
