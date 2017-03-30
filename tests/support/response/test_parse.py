#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

import requests
import requests_mv_integrations


def test_requests_response_text_html():
    response = requests.get('http://httpbin.org/html')
    assert response
    response_html = requests_mv_integrations.support.response.requests_response_text_html(response)
    assert response_html
    assert isinstance(response_html, list)


def test_requests_response_text_xml():
    response = requests.get('http://httpbin.org/xml')
    assert response
    response_xml = requests_mv_integrations.support.response.requests_response_text_xml(response)
    assert response_xml
    assert isinstance(response_xml, dict)
