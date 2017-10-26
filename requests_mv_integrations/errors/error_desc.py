#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

from pyhttpstatus_utils.status_dicts import description as http_status_desc
from pyhttpstatus_utils.status_dicts import name as http_status_codes

tune_reporting_error_names = {
    -1: 'Unassigned',
    0: 'Success',
    600: 'Module Error',
    601: 'Argument Error',
    602: 'Request Error',
    603: 'Software Error',
    604: 'Unexpected Value',
    605: 'Request HTTP',
    606: 'Request Connect',
    607: 'Request Redirect',
    608: 'Retry Exhausted',
    609: 'Unexpected content-type returned',
    610: 'Upload Data Error',
    611: 'Auth Error',
    612: 'Auth JSON Error',
    613: 'Auth Response Error',
    614: 'JSON Decoding Error',
    699: 'Unexpected Error'
}

tune_reporting_error_descs = {
    -1: 'Unassiged exit condition',
    0: 'Successfully completed',
    600: 'Error occurred somewhere within module',
    601: 'Invalid or missing argument provided',
    602: 'Unexpected request failure',
    603: 'Unexpected software error was detected',
    604: 'Unexpected value returned',
    605: 'Request HTTP error occurred',
    606: 'Request Connection error occurred',
    607: 'Request Redirect',
    608: 'Retry Exhausted',
    609: 'Unexpected content-type returned',
    610: 'Upload Data Error',
    611: 'Auth Error',
    612: 'Auth JSON Error',
    613: 'Auth Response Error',
    614: 'JSON Decoding Error',
    699: 'Unexpected Error'
}


def error_name(error_code, return_bool=False):
    """Provide definition of Error Code

    Args:
        error_code:

    Returns:

    """
    if error_code is None or not isinstance(error_code, int):
        return f"Error Code: Invalid Type: {error_code}"

    exit_code_name_ = http_status_codes.get(error_code, None)
    if exit_code_name_ is not None:
        return exit_code_name_

    exit_code_name_ = tune_reporting_error_names.get(error_code, None)
    if exit_code_name_ is not None:
        return exit_code_name_

    return False if return_bool else f"Error Code: Undefined: {error_code}"


def error_desc(error_code, return_bool=False):
    """Provide definition of Error Code

    Args:
        error_code:

    Returns:

    """
    if error_code is None or not isinstance(error_code, int):
        return f"Error Code: Invalid Type: {error_code}"

    exit_code_description_ = http_status_desc.get(error_code, None)
    if exit_code_description_ is not None:
        return exit_code_description_

    exit_code_description_ = tune_reporting_error_descs.get(error_code, None)
    if exit_code_description_ is not None:
        return exit_code_description_

    return False if return_bool else f"Error Code: Undefined: {error_code}"
