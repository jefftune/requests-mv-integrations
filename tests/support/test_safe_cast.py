#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integration

from requests_mv_integrations.support.safe_cast import (
    safe_float,
    safe_str,
    safe_dict,
    safe_int,
)


def test_safe_str():
    assert isinstance(safe_str(0), str)
    assert isinstance(safe_str(0.0), str)
    assert isinstance(safe_str('0'), str)


def test_safe_int():
    assert isinstance(safe_int(0), int)
    assert isinstance(safe_int(0.0), int)
    assert isinstance(safe_int('0'), int)


def test_safe_float():
    assert isinstance(safe_float(0), float)
    assert isinstance(safe_float(0.0), float)


def test_safe_dict():
    assert isinstance(safe_dict({'key': 'value'}), dict)
