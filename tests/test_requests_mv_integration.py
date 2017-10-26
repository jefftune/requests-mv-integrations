#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

import pytest
import requests
import requests_mock

from requests_mv_integrations import RequestMvIntegration
from requests_mv_integrations.exceptions import (
    TuneRequestBaseError,
    TuneRequestServiceError,
    TuneRequestModuleError,
    TuneRequestValueError,
)

from requests_mv_integrations.errors import TuneRequestErrorCodes
from requests_mv_integrations import TuneRequest
from requests.models import Response
from requests.exceptions import ReadTimeout

from pyhttpstatus_utils import status_dicts, http_status_code_to_type

from .resources.mockserver import run_server

assert run_server  # Silence Pyflakes

request_raised_exceptions_test_object = (
    (requests.exceptions.ConnectTimeout, TuneRequestServiceError, TuneRequestErrorCodes.GATEWAY_TIMEOUT),
    (requests.exceptions.ReadTimeout, TuneRequestServiceError, TuneRequestErrorCodes.GATEWAY_TIMEOUT),
    (requests.exceptions.Timeout, TuneRequestServiceError, TuneRequestErrorCodes.GATEWAY_TIMEOUT),
    (requests.exceptions.HTTPError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_HTTP),
    (requests.exceptions.ConnectionError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT),
    (requests.exceptions.ProxyError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT),
    (requests.exceptions.SSLError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT),
    (BrokenPipeError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_CONNECT),
    (ConnectionError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_CONNECT), (
        requests.packages.urllib3.exceptions.ProtocolError, TuneRequestModuleError,
        TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT
    ), (
        requests.packages.urllib3.exceptions.ReadTimeoutError, TuneRequestServiceError,
        TuneRequestErrorCodes.GATEWAY_TIMEOUT
    ), (requests.exceptions.TooManyRedirects, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST_REDIRECTS),
    (requests.exceptions.RetryError, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED),
    (requests.exceptions.RequestException, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_REQUEST),
    (TuneRequestBaseError, TuneRequestBaseError, TuneRequestErrorCodes.REQ_ERR_UNEXPECTED),
    (Exception, TuneRequestModuleError, TuneRequestErrorCodes.REQ_ERR_SOFTWARE),

    #The "http status code specific RetryError" case is tested differently and therfore is missing from the above list
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


test_request_retry_details = (('RequestRetryException', None), ('TuneRequestBaseError', None), ('Exception', None),
                              ('TuneRequestModuleError', TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED),
                              ('TuneRequestModuleError', TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_VALUE),)

test_try_send_request_details = (
    (
        None,  # attempts
        None,  # tries
        'response_none',  # response_type
        None,  # exception_thrown_by_request_func
        'response=None',  # request_label
        None,  # request_retry_func
        None,  # request_retry_excps_func
        None,  # request_url
        'TuneRequestModuleError',  # expected_exception_name
        TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_VALUE,  # expected_error_code
        False,  # is_expected_response
    ),
    (
        1,  # attempts
        3,  # tries
        'response_ok_with_valid_json_content',  # response_type
        None,  # exception_thrown_by_request_func
        'OK reponse && request_retry_func=True',  # request_label
        lambda x: True,  # request_retry_func
        None,  # request_retry_excps_func
        'www.requesturl.com',  # request_url
        None,  # expected_exception_name
        None,  # expected_error_code
        None,  # is_expected_response
    ),
    (
        2,  # attempts
        0,  # tries
        'response_ok_with_valid_json_content',  # response_type
        None,  # exception_thrown_by_request_func
        'OK reponse && request_retry_func=True && Request tries exhausted',  # request_label
        lambda x: True,  # request_retry_func
        None,  # request_retry_excps_func
        'www.requesturl.com',  # request_url
        'TuneRequestModuleError',  # expected_exception_name
        TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED,  # expected_error_code
        False,  # is_expected_response
    ),
    (
        1,  # attempts
        3,  # tries
        'response_ok_with_valid_json_content',  # response_type
        None,  # exception_thrown_by_request_func
        'OK reponse && request_retry_func=False',  # request_label
        lambda x: False,  # request_retry_func
        None,  # request_retry_excps_func
        'www.requesturl.com',  # request_url
        None,  # expected_exception_name
        None,  # expected_error_code
        True,  # is_expected_response
    ),
    (
        1,  # attempts
        3,  # tries
        'response_ok_with_valid_json_content',  # response_type
        ReadTimeout,  # exception_thrown_by_request_func
        'Request Retry Exception thrown && tries>0',  # request_label
        lambda x: False,  # request_retry_func
        None,  # request_retry_excps_func
        'www.requesturl.com',  # request_url
        None,  # expected_exception_name
        None,  # expected_error_code
        False,  # is_expected_response
    ),
    (
        1,  # attempts
        0,  # tries
        'response_ok_with_valid_json_content',  # response_type
        ReadTimeout,  # exception_thrown_by_request_func
        'Request Retry Exception thrown && tries==0',  # request_label
        lambda x: False,  # request_retry_func
        None,  # request_retry_excps_func
        'www.requesturl.com',  # request_url
        'ReadTimeout',  # expected_exception_name
        None,  # expected_error_code
        False,  # is_expected_response
    ),
    (
        1,  # attempts
        3,  # tries
        'response_ok_with_valid_json_content',  # response_type
        TuneRequestServiceError,  # exception_thrown_by_request_func
        'TuneRequestServiceError && request_retry_excps_func==False',  # request_label
        lambda x: False,  # request_retry_func
        lambda x, y: False,  # request_retry_excps_func
        'www.requesturl.com',  # request_url
        'TuneRequestServiceError',  # expected_exception_name
        None,  # expected_error_code
        False,  # is_expected_response
    ),
    (
        1,  # attempts
        3,  # tries
        'response_ok_with_valid_json_content',  # response_type
        TuneRequestServiceError,  # exception_thrown_by_request_func
        'TuneRequestServiceError && request_retry_excps_func==True && tries>0',  # request_label
        lambda x: False,  # request_retry_func
        lambda x, y: True,  # request_retry_excps_func
        'www.requesturl.com',  # request_url
        None,  # expected_exception_name
        None,  # expected_error_code
        False,  # is_expected_response
    ),
    (
        1,  # attempts
        0,  # tries
        'response_ok_with_valid_json_content',  # response_type
        TuneRequestServiceError,  # exception_thrown_by_request_func
        'TuneRequestServiceError && request_retry_excps_func==True && tries==0',  # request_label
        lambda x: False,  # request_retry_func
        lambda x, y: True,  # request_retry_excps_func
        'www.requesturl.com',  # request_url
        'TuneRequestServiceError',  # expected_exception_name
        None,  # expected_error_code
        False,  # is_expected_response
    ),
    (
        1,  # attempts
        3,  # tries
        'response_ok_with_valid_json_content',  # response_type
        Exception,  # exception_thrown_by_request_func
        'General Exception && request_retry_excps_func==False',  # request_label
        lambda x: False,  # request_retry_func
        lambda x, y: False,  # request_retry_excps_func
        'www.requesturl.com',  # request_url
        'Exception',  # expected_exception_name
        None,  # expected_error_code
        False,  # is_expected_response
    ),
    (
        1,  # attempts
        3,  # tries
        'response_ok_with_valid_json_content',  # response_type
        Exception,  # exception_thrown_by_request_func
        'General Exception && request_retry_excps_func==True && tries>0',  # request_label
        lambda x: False,  # request_retry_func
        lambda x, y: True,  # request_retry_excps_func
        'www.requesturl.com',  # request_url
        None,  # expected_exception_name
        None,  # expected_error_code
        False,  # is_expected_response
    ),
    (
        1,  # attempts
        0,  # tries
        'response_ok_with_valid_json_content',  # response_type
        Exception,  # exception_thrown_by_request_func
        'General Exception && request_retry_excps_func==True && tries==0',  # request_label
        lambda x: False,  # request_retry_func
        lambda x, y: True,  # request_retry_excps_func
        'www.requesturl.com',  # request_url
        'TuneRequestModuleError',  # expected_exception_name
        TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED,  # expected_error_code
        False,  # is_expected_response
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


def get_http_responses_4xx_5xx():
    client_error_type = status_dicts.type[400]
    server_error_type = status_dicts.type[500]

    ignore_list = [419, 425, 509]  # Uncommon http responses excluded from the test

    # Collect all possible 4xx and 5xx http responses
    http_responses = [
        code for code in status_dicts.name if http_status_code_to_type(code) in [client_error_type, server_error_type]
    ]
    http_responses = [code for code in http_responses if code not in ignore_list]
    return http_responses


http_responses_4xx_5xx = get_http_responses_4xx_5xx()


class TestRequestMvIntegration:
    """
    A test class, for testing RequestMvIntegration methods.
    """

    @pytest.mark.parametrize(
        "requests_error, mv_integration_error, error_code",
        request_raised_exceptions_test_object,
    )
    def test_request_raised_exceptions(
        self,
        monkeypatch,
        request_mv_integration_object,
        requests_error,
        mv_integration_error,
        error_code,
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

        def mock_request_retry(*args, **kwargs):
            if requests_error == requests.packages.urllib3.exceptions.ReadTimeoutError:
                raise requests_error('pool', 'url', 'message')
            raise requests_error

        req = request_mv_integration_object
        monkeypatch.setattr(req, '_request_retry', mock_request_retry)
        try:
            req.request(
                request_method='Does not matter',
                request_url='Does not matter',
            )
        except Exception as e:
            assert (isinstance(e, mv_integration_error))
            assert (e.error_code == error_code)

    @pytest.mark.parametrize('tested_http_response', http_responses_4xx_5xx)
    def test_request_http_response_4xx_5xx(self, tested_http_response, request_mv_integration_object, run_server):
        """
        Test RequestMvIntegration.request() handling of receiving a 4xx or 5xx response
        This also tests handling of RetryError raised when retries are exhausted (for some of the http response
        codes are designated for retry).

          The Tests asserts that the output exit code is equal to the mocked http response code
        :param request_mv_integration_object: An instance of RequestMvIntegration.
        :return:
        """
        try:
            request_mv_integration_object.request('GET', 'http://localhost:8998/status/' + str(tested_http_response))
        except Exception as ex:
            assert ex.error_code == tested_http_response, f"Expected: {tested_http_response}, Actual: {ex.error_code}"

    def test_request_raised_exceptions_method_none(self, request_mv_integration_object):
        """
        Test RequestMvIntegration.request() exception handling, my mocking the call
        to RequestMvIntegration._request_retry()
        :param request_mv_integration_object: An instance of RequestMvIntegration.
        """

        req = request_mv_integration_object
        try:
            req.request(
                request_method=None,
                request_url=None,
            )
        except Exception as e:
            assert (isinstance(e, TuneRequestValueError))
            assert (e.error_code == TuneRequestErrorCodes.REQ_ERR_ARGUMENT)

    def test_request_raised_exceptions_url_none(self, request_mv_integration_object):
        """
        Test RequestMvIntegration.request() exception handling, my mocking the call
        to RequestMvIntegration._request_retry()
        :param request_mv_integration_object: An instance of RequestMvIntegration.
        """

        req = request_mv_integration_object
        try:
            req.request(
                request_method='GET',
                request_url=None,
            )
        except Exception as e:
            assert (isinstance(e, TuneRequestValueError))
            assert (e.error_code == TuneRequestErrorCodes.REQ_ERR_ARGUMENT)

    def test_request_happy_path(
        self,
        request_mv_integration_object,
        tune_request_object,
        ok_request_args_dict,
    ):
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
        assert request_mv_integration_object
        assert tune_request_object
        req = request_mv_integration_object
        req.tune_request = tune_request_object
        request_args = ok_request_args_dict
        resp = req.request(
            request_method=request_args['request_method'],
            request_url=request_args['request_url'],
        )
        assert (resp.status_code == requests.codes.ok)

    @pytest.mark.parametrize(
        "exception_type_name, error_code",
        test_request_retry_details,
    )
    def test_request_retry(
        self,
        exception_type_name,
        error_code,
        exceptions,
        request_mv_integration_object,
        monkeypatch,
    ):
        def mock_try_send_request(_attempts, _tries, request_func, request_retry_func, request_url, request_label=None):
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
                raise Exception(f"Bad input to test: No {exception_type_name} exceptions")

        monkeypatch.setattr(
            request_mv_integration_object,
            'try_send_request',
            mock_try_send_request,
        )
        request_mv_integration_object.request_retry_excps = [RequestRetryException]
        try:
            request_mv_integration_object._request_retry(call_func=lambda *args, **kwargs: None)
        except Exception as e:
            assert (type(e).__name__ == exception_type_name)
            if error_code is not None:
                assert (e.error_code == error_code)

    @pytest.mark.parametrize(
        "attempts, tries, response_type, exception_thrown_by_request_func, request_label, request_retry_func, request_retry_excps_func, request_url, expected_exception_name, expected_error_code, is_expected_response",
        test_try_send_request_details
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
                exception_thrown_by_request_func is not None or
                response_type is not None and response_type in responses_dict
            )
            if exception_thrown_by_request_func is not None:
                raise exception_thrown_by_request_func
            if response_type is not None:
                return responses_dict[response_type]

        request_mv_integration_object.request_retry_excps_func = request_retry_excps_func

        to_raise_exception, to_return_response = request_mv_integration_object.try_send_request(
            attempts=attempts,
            tries=tries,
            request_func=mock_request_func,
            request_retry_func=request_retry_func,
            request_url=request_url,
            request_label=request_label,
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
