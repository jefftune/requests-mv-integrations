#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

import pytest

from requests.models import Response, codes


class EmptyResponse(object):
    def __init__(self):
        super(EmptyResponse, self).__init__()

        self.status_code = None
        self.headers = {}


@pytest.fixture(scope='module')
def responses_dict():
    response_types = [
        'response_ok_no_headers',
        'response_bad',
        'response_ok_with_valid_json_content',
        'response_ok_with_invalid_json_content',
        'response_ok_with_valid_html_content',
        'response_ok_with_invalid_html_content',
        'response_ok_with_no_text',
    ]

    responses = dict()
    responses['response_none'] = None
    for rt in response_types:
        responses[rt] = Response()

    responses['response_ok_no_headers'].status_code = codes.ok
    responses['response_ok'] = responses['response_ok_no_headers']

    responses['response_bad'].status_code = codes.bad

    responses['response_ok_with_valid_json_content'].status_code = codes.ok
    responses['response_ok_with_valid_json_content'].headers['Content-Type'] = 'application/json'
    responses[
        'response_ok_with_valid_json_content'
    ]._content = b'[{"offerId":"a7b6c5d4e3f2g1","targetedCountries":["AU","CA","GB","IE","NL","NO","NZ","SE","US"],"incentivized":3,"storeId":"2","targetPlatform":"iOS","active":false,"appId":"abcdefghijklmn","appName":"Testing App","appIconUrl":"http://www.requests_response_json_mock.com/creatives/abcdefghijklmn.png","productId":"12ab3cd456789e","advertiserName":"unittester@tune.com","capDetails":null,"id":"a1b2c3d4e5f6g7","name":"Testing App Multiverse campaign","clicks":324,"cr":4.01,"conversions":13,"spent":13.0}]'

    responses['response_ok_with_invalid_json_content'].status_code = codes.ok
    responses['response_ok_with_invalid_json_content'].headers['Content-Type'] = 'application/json'
    responses[
        'response_ok_with_invalid_json_content'
    ]._content = b'[{"offerId":"a7b6c5d4e3f2g1","targetedCountries":["AU","CA","GB","IE","NL","NO","NZ","SE","US"],"incentivized":3,"storeId":"2","targetPlatform":"iOS","active":false,"appId":"abcdefghijklmn","appName":"Testing App","appIconUrl":"http://www.requests_response_json_mock.com/creatives/abcdefghijklmn.png","productId":"12ab3cd456789e","advertiserName":"unittester@tune.com","capDetails":null,"id":"a1b2c3d4e5f6g7","name":"Testing App Multiverse campaign","clicks":324,"cr":4.01,"conversions":13,"spent":13.0'

    responses['response_ok_with_valid_html_content'].status_code = codes.ok
    responses['response_ok_with_valid_html_content'].headers['Content-Type'] = 'text/html'
    responses[
        'response_ok_with_valid_html_content'
    ]._content = b'<!DOCTYPE html><html><title>HTML Document</title><body><h1>This is a heading</h1><p>This is a paragraph.</p></body></html>'

    responses['response_ok_with_invalid_html_content'].status_code = codes.ok
    responses['response_ok_with_invalid_html_content'].headers['Content-Type'] = 'text/html'
    responses['response_ok_with_invalid_html_content']._content = b'Definitely not an HTML'

    responses['response_ok_with_no_text'] = EmptyResponse()
    responses['response_ok_with_no_text'].status_code = codes.ok
    responses['response_ok_with_no_text'].headers['Content-Type'] = 'application/json'
    responses['response_ok_with_no_text'].headers['Transfer-Encoding'] = 'chunked'
    responses['response_ok_with_no_text'].headers['Content-Encoding'] = 'gzip'

    return responses
