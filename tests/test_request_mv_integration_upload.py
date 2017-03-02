#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integration

import pytest
import os

TMP_DIRECTORY = os.path.dirname(os.path.realpath(__file__)) + '/tmp'

from .resources.mockserver import run_server
from requests_mv_integrations import (
    RequestMvIntegrationUpload,
)
from requests_mv_integrations.exceptions import (TuneRequestValueError)

__all__ = [run_server]

current_path = os.path.dirname(os.path.realpath(__file__))
test_config_path = "%s/tests/resources/uploadtestfile.json" % os.path.dirname(current_path)
test_url = "http://localhost:8998/upload.json"


@pytest.fixture
def request_object():
    print("creating object")
    obj = RequestMvIntegrationUpload()
    return obj


class TestRequestMvIntegrationUpload:
    @pytest.mark.parametrize('upload_request_url, upload_data_file_path', (('url', 'path'), ('url', test_config_path),))
    def test_request_upload_json_file_url_fail(self, request_object, upload_request_url, upload_data_file_path):

        with pytest.raises(AssertionError) as ex_assert:
            request_object.request_upload_json_file(
                upload_request_url=upload_request_url,
                upload_data_file_path=upload_data_file_path,
                upload_data_file_size=1,
                is_upload_gzip=None,
                request_label="test_request_upload_json_file_url_fail",
            )

        assert ex_assert

    @pytest.mark.parametrize(
        'upload_request_url, upload_data_file_path', ((test_url, 'path'), ('url', test_config_path),)
    )
    def test_request_upload_json_file_path_fail(self, request_object, upload_request_url, upload_data_file_path):

        with pytest.raises(AssertionError) as ex_assert:
            request_object.request_upload_json_file(
                upload_request_url=upload_request_url,
                upload_data_file_path=upload_data_file_path,
                upload_data_file_size=1,
                is_upload_gzip=None,
                request_label="test_request_upload_json_file_path_fail",
            )

        assert ex_assert

    @pytest.mark.parametrize(
        'is_gzip, content_type', ((True, 'application/gzip'), (None, 'application/json; charset=utf8'),)
    )
    def test_request_upload_json_file_pass(self, request_object, is_gzip, content_type, run_server):
        response = request_object.request_upload_json_file(
            upload_request_url=test_url,
            upload_data_file_path=test_config_path,
            upload_data_file_size=1,
            is_upload_gzip=is_gzip,
            request_label="test_request_upload_json_file_pass",
        )

        assert content_type in response.headers["Content-Type"]

    @pytest.mark.parametrize('upload_request_url, data', (('http', 'data'), ('www.example.com', 'data'),))
    def test_request_upload_data_fail(self, request_object, upload_request_url, data):
        with pytest.raises(TuneRequestValueError) as ex_assert:
            request_object.request_upload_data(
                upload_request_url=upload_request_url,
                upload_data=data,
                upload_data_size=1,
                request_label="test_request_upload_data_fail",
            )

        assert ex_assert

    @pytest.mark.parametrize('url, data', ((test_url, "text"),))
    def test_request_upload_data_pass(self, request_object, url, data, run_server):

        response = request_object.request_upload_data(url, data, upload_data_size=1)
        assert 'application/json; charset=utf8' in response.headers["Content-Type"]
