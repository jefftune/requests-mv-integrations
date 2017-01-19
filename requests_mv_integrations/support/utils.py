#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations
"""Helpers: Functions for commonly used utilities.
"""

import sys
import psutil


#  Check Python Version
#
def python_check_version(required_version):
    """Check Python Version
    :param: required_version
    """
    assert isinstance(required_version, tuple)

    current_version = sys.version_info
    if current_version[0] == required_version[0] and \
       current_version[1] >= required_version[1]:
        pass
    elif current_version[0] > required_version[0]:
        pass
    else:
        sys.stderr.write(
            "[%s] - Error: Python interpreter must be %d.%d or greater"
            " to use this library, current version is %d.%d.\n" %
            (sys.argv[0], required_version[0], required_version[1], current_version[0], current_version[1])
        )
        sys.exit(-1)
    return 0


def bytes_to_human(size, precision=2):
    # http://code.activestate.com/recipes/578019
    # >>> bytes_to_human(10000)
    # '9.8K'
    # >>> bytes_to_human(100001221)
    # '95.4M'
    suffixes = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, suffix in enumerate(suffixes):
        prefix[suffix] = 1 << (i + 1) * 10
    for suffix in reversed(suffixes):
        if size >= prefix[suffix]:
            value = float(size) / prefix[suffix]
            return '%.*f %sB' % (precision, value, suffix)
    return "%s B" % size


def mem_usage():
    virt = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        'Mem': {
            'total': bytes_to_human(virt.total),
            'used': bytes_to_human(virt.used),
            'free': bytes_to_human(virt.free / 1024),
            'shared': bytes_to_human(getattr(virt, 'shared', 0)),
            'buffers': bytes_to_human(getattr(virt, 'buffers', 0)),
            'cached': bytes_to_human(getattr(virt, 'cached', 0))
        },
        'Swap:': {
            'total': bytes_to_human(swap.total),
            'used': bytes_to_human(swap.used),
            'free': bytes_to_human(swap.free)
        }
    }


def disk_usage(dir):
    usage = psutil.disk_usage(dir)
    return {
        'total': bytes_to_human(usage.total),
        'used': bytes_to_human(usage.used),
        'free': bytes_to_human(usage.free),
        'percent': int(usage.percent)
    }


def base_class_name(obj):
    return obj.__class__.__name__


def full_class_name(obj):
    try:
        return obj.__module__ + "." + obj.__class__.__name__
    except Exception as ex:
        return obj.__class__.__name__


def urlencode_dict(request_data):
    assert isinstance(request_data, dict)

    request_data_query = ""
    for key in request_data.keys():
        request_data_query += str(key) + '=' + str(request_data[key]) + "&"

    return request_data_query[:-1]
