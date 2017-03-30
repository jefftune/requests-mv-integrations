#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

from requests_mv_integrations.support.usage import (
    mem_usage,
    disk_usage,
    env_usage,
)


def test_mem_usage():
    usage = mem_usage()
    assert isinstance(usage, dict)
    assert len(usage) > 0


def test_disk_usage():
    usage = disk_usage()
    assert isinstance(usage, dict)
    assert len(usage) > 0


def test_env_usage():
    usage = env_usage()
    assert isinstance(usage, dict)
    assert len(usage) > 0