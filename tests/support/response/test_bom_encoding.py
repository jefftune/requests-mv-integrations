#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2017 TUNE, Inc. (http://www.tune.com)

import codecs
from requests_mv_integrations.support import (get_bom_encoding)


def test_bom_encoding():
    bom_enc, bom_len = get_bom_encoding(b'\xc4\x8f\xc2\xbb\xc5\xbc')
    assert bom_len == 6
    assert bom_enc == 'cp1250'

    bom_enc, bom_len = get_bom_encoding(b'\xd0\xbf\xc2\xbb\xd1\x97')
    assert bom_len == 6
    assert bom_enc == 'cp1251'

    bom_enc, bom_len = get_bom_encoding(codecs.BOM_UTF32_BE)
    assert bom_len == 4
    assert bom_enc == 'UTF-32BE'

    bom_enc, bom_len = get_bom_encoding(b'\x1f\x8b')
    assert bom_len == 2
    assert bom_enc == 'gzip'
