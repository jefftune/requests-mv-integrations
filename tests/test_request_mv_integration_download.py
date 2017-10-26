#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

import pytest
import os
import tempfile
import csv
from os import sep
from subprocess import Popen, PIPE
from .resources.mockserver import (run_server, HTTP_SERVER_PORT, StaticFilesHandler)
from requests_mv_integrations import (
    RequestMvIntegrationDownload,
)
from requests_mv_integrations.exceptions.custom import (
    TuneRequestModuleError,
)

tmpdir = tempfile.mkdtemp()

__all__ = [run_server]


@pytest.fixture(scope='session')
def request_mv_integration_download_object():
    obj = RequestMvIntegrationDownload()
    return obj


current_path = os.path.dirname(os.path.realpath(__file__))
test_csv_download_url = f"http://localhost:{HTTP_SERVER_PORT}/download.csv"
test_json_download_url = f"http://localhost:{HTTP_SERVER_PORT}/download.json"
test_csv_stream_url = f"http://localhost:{HTTP_SERVER_PORT}/stream.csv"
TMP_CSV_FILE_NAME = 'csv_mock.csv'
TMP_JSON_FILE_NAME = 'json_mock.json'
TMP_DIRECTORY = tmpdir


def compare_csv_file_to_csv_list(csv_file_path, csv_list):
    with open(csv_file_path, 'rt') as csv_file:
        # Read CSV file from disk
        csv_reader = csv.reader(csv_file)

        rows = list(csv_reader)
        fields = rows[0]
        values_list = rows[1:]

        # Parse CSV file to a list of dictionaries containing field:value pairs
        list_of_dicts = list()
        for values in values_list:
            field_to_value_dict = dict()
            for idx, field in enumerate(fields):
                field_to_value_dict[field] = values[idx]
            list_of_dicts.append(field_to_value_dict)

        # Now, compare two lists of dicts. The order of the dictionaries in the lists is important.
        len1 = len(csv_list)
        len2 = len(list_of_dicts)
        if len1 != len2:
            return False
        for i in range(len1):
            if csv_list[i] != list_of_dicts[i]:
                return False

    return True


def compare_csv_files(file_path_1, file_path_2):
    with open(file_path_1, 'rt') as csvfile1:
        with open(file_path_2, 'rt') as csvfile2:
            reader1 = csv.reader(csvfile1)
            reader2 = csv.reader(csvfile2)

            rows1 = [row for row in reader1]
            rows2 = [row for row in reader2]

            if len(rows1) != len(rows2):
                return False

            n = len(rows1)
            for row_idx in range(n):
                row1 = rows1[row_idx]
                row2 = rows2[row_idx]

                if len(row1) != len(row2):
                    return False

                m = len(row1)
                for col_idx in range(m):
                    if row1[col_idx] != row2[col_idx]:
                        return False
    return True


class TestRequestMvIntegrationDownload:

    def test_request_csv_download(self, request_mv_integration_download_object, run_server):
        # RequestMvIntegrationDownload.request_csv_download(...) returns a
        # generator containing CSV data by rows in JSON dictionary format.
        # Converting the generator to a list, causes yielding all rows values.
        csv_as_list = list(
            request_mv_integration_download_object.request_csv_download(
                request_method='GET',
                request_url=test_csv_download_url,
                tmp_csv_file_name=TMP_CSV_FILE_NAME,
                tmp_directory=tmpdir,
            )
        )
        # as a side effect, the method saves a csv file in <TMP_DIRECTORY>/<TMP_CSV_FILE_NAME>.
        # Check, whether the method has yielded the CSV file values correctly ( We mocked an
        # HTTP GET server to return in the response, the content of a predefined csv file )
        downloaded_file_path = tmpdir + sep + TMP_CSV_FILE_NAME
        assert (compare_csv_files(StaticFilesHandler.csv_file_name(), downloaded_file_path))

        # Now, check that the content of the list of csv dictionary rows, is correct
        assert (compare_csv_file_to_csv_list(StaticFilesHandler.csv_file_name(), csv_as_list))

    @pytest.mark.parametrize(
        'read_first_row, skip_last_row, skip_first_row', (
                (True, False, False),
                (False, True, False),
                (False, False, True),
        )
    )
    def test_request_csv_download_special(self, request_mv_integration_download_object,
                                  read_first_row, skip_last_row, skip_first_row, run_server):
        # RequestMvIntegrationDownload.request_csv_download(...) returns a
        # generator containing CSV data by rows in JSON dictionary format.
        # Converting the generator to a list, causes yielding all rows values.
        csv_as_list = list(
            request_mv_integration_download_object.request_csv_download(
                request_method='GET',
                request_url=test_csv_download_url,
                tmp_csv_file_name=TMP_CSV_FILE_NAME,
                tmp_directory=tmpdir,
                read_first_row=read_first_row,
                skip_first_row=skip_first_row,
                skip_last_row=skip_last_row
            )
        )

        assert csv_as_list is not None

    def test_request_csv_download_fail(self, request_mv_integration_download_object, run_server):
        # RequestMvIntegrationDownload.request_csv_download(...) returns a
        # generator containing CSV data by rows in JSON dictionary format.
        # Converting the generator to a list, causes yielding all rows values.
        csv_as_list = None
        with pytest.raises(TuneRequestModuleError) as info:
            csv_as_list = list(
                request_mv_integration_download_object.request_csv_download(
                    request_method='GET',
                    request_url="bad url",
                    tmp_csv_file_name=TMP_CSV_FILE_NAME,
                    tmp_directory=tmpdir,
                )
            )
        assert csv_as_list is None
        assert "Invalid URL" in str(info.value)

    def test_request_json_download(self, request_mv_integration_download_object, run_server):
        # RequestMvIntegrationDownload.request_json_download(...) should save the content of a response to
        # a GET request to <test_json_download_url>, as a json file at <TMP_DIRECTORY>/<TMP_JSON_FILE_NAME>
        request_mv_integration_download_object.request_json_download(
            request_method='GET',
            request_url=test_json_download_url,
            tmp_json_file_name=TMP_JSON_FILE_NAME,
            tmp_directory=tmpdir,
        )

        # Check, whether the method has saved the file correctly ( We mocked the an HTTP GET server to return a
        # predefined json file )
        downloaded_file_path = tmpdir + sep + TMP_JSON_FILE_NAME
        mock_file_path = StaticFilesHandler.json_file_name()

        # Compare two files by running a diff command in shell
        sts = Popen(['diff', downloaded_file_path, mock_file_path], stdout=PIPE, stderr=PIPE, stdin=PIPE)
        diff_res = sts.stdout.read()
        assert (diff_res == b'')

    def test_stream_csv(self, request_mv_integration_download_object, run_server):
        # RequestMvIntegrationDownload.stream_csv(...) return a generator.
        # Converting the generator to a list, causes yielding all values.
        csv_as_list = list(
            request_mv_integration_download_object.stream_csv(
                request_url=test_csv_stream_url,
                request_params=None,
            )
        )

        # Check, wether the method has streamed the CSV file correctly ( We mocked the an HTTP GET server to
        # return in the response, the content of a predefined csv file )
        assert (compare_csv_file_to_csv_list(StaticFilesHandler.csv_file_name(), csv_as_list))

    def test_session(self, request_mv_integration_download_object, run_server):
        assert request_mv_integration_download_object.session is not None

    def test_tune_request(self, request_mv_integration_download_object, run_server):
        assert request_mv_integration_download_object.tune_request is not None

    def test_mv_request(self, request_mv_integration_download_object, run_server):
        assert request_mv_integration_download_object.mv_request is not None
