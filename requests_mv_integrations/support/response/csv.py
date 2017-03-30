#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)


def csv_skip_last_row(iterator):
    """Skip last CSV row.

    Args:
        iterator:

    Returns:

    """
    prev = next(iterator)
    for item in iterator:
        yield prev
        prev = item
