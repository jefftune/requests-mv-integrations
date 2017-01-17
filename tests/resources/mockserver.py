#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace tune_mv_integration

import pytest
from os import sep
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

import json
HTTP_SERVER_PORT = 8998
CSV_DOWNLOAD_FILE_NAME = 'downloadtestfile.csv'
JSON_DOWNLOAD_FILE_NAME = 'downloadtestfile.json'

from pyhttpstatus_utils.status_code import HttpStatusCode
import errno
import os


class StaticFilesHandler(BaseHTTPRequestHandler):
    current_path = os.path.dirname(os.path.realpath(__file__))

    @staticmethod
    def json_file_name():
        return StaticFilesHandler.current_path + sep + JSON_DOWNLOAD_FILE_NAME

    @staticmethod
    def csv_file_name():
        return StaticFilesHandler.current_path + sep + CSV_DOWNLOAD_FILE_NAME

    def do_GET(self):
        try:
            if self.path.endswith("download.json"):
                f = open(StaticFilesHandler.json_file_name())
                self.send_response(HttpStatusCode.OK)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(f.read().encode())
                f.close()
            elif self.path.endswith('download.csv') or self.path.endswith('stream.csv'):
                f = open(StaticFilesHandler.csv_file_name())
                self.send_response(HttpStatusCode.OK)
                self.send_header('Content-type', 'application/csv')
                self.end_headers()
                self.wfile.write(f.read().encode())
                f.close()
            elif "status" in self.path:
                status = self.path[-3:]
                self.send_response(int(status))
                self.send_header('Content-type', 'application/json')
                self.end_headers()

        except IOError:
            self.send_error(404, 'File Not Found: %s' % self.path)

    def do_PUT(self):
        try:
            if self.path.endswith('upload.json'):
                self.send_response(200)
                self.send_header("Content-Type", self.headers['Content-Type'])
                self.end_headers()
        except IOError:
            self.send_error(404, 'File Not Found: %s' % self.path)


@pytest.fixture(scope='module')
def run_server(server_class=HTTPServer, handler_class=StaticFilesHandler):
    try:
        try:
            server_address = ('localhost', HTTP_SERVER_PORT)
            httpd = server_class(server_address, handler_class)
            thread = threading.Thread(target=httpd.serve_forever)
            thread.daemon = True
            thread.start()
            # yield thread.start()
        except OSError as e:
            # If, we've already ran the HTTP server, then we should get this exception, and let it be.
            if e.errno != errno.EADDRINUSE:
                raise
        # Teardown code can be placed here
    except Exception as ex:
        print(ex)
        raise

    return
