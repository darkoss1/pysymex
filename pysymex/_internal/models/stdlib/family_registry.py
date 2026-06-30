# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Family-level registry assembly for stdlib models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.models.stdlib.array.models import array_models
from pysymex._internal.models.stdlib.base64.models import base64_models
from pysymex._internal.models.stdlib.binascii.models import binascii_models
from pysymex._internal.models.stdlib.bz2.models import bz2_models
from pysymex._internal.models.stdlib.calendar.models import calendar_models
from pysymex._internal.models.stdlib.codecs.models import codecs_models
from pysymex._internal.models.stdlib.configparser.models import configparser_models
from pysymex._internal.models.stdlib.copyreg.models import copyreg_models
from pysymex._internal.models.stdlib.csv.models import csv_models
from pysymex._internal.models.stdlib.decimal.models import decimal_models
from pysymex._internal.models.stdlib.fnmatch.models import fnmatch_models
from pysymex._internal.models.stdlib.fractions.models import fractions_models
from pysymex._internal.models.stdlib.glob.models import glob_models
from pysymex._internal.models.stdlib.gzip.models import gzip_models
from pysymex._internal.models.stdlib.hashlib.models import hashlib_models
from pysymex._internal.models.stdlib.hmac.models import hmac_models
from pysymex._internal.models.stdlib.html.models import html_models
from pysymex._internal.models.stdlib.importlib.models import importlib_models
from pysymex._internal.models.stdlib.inspect.models import inspect_models
from pysymex._internal.models.stdlib.ipaddress.models import ipaddress_models
from pysymex._internal.models.stdlib.keyword.models import keyword_models
from pysymex._internal.models.stdlib.logging.models import logging_models
from pysymex._internal.models.stdlib.lzma.models import lzma_models
from pysymex._internal.models.stdlib.marshal.models import marshal_models
from pysymex._internal.models.stdlib.mimetypes.models import mimetypes_models
from pysymex._internal.models.stdlib.ntpath.models import ntpath_models
from pysymex._internal.models.stdlib.numbers.models import numbers_models
from pysymex._internal.models.stdlib.pickle.models import pickle_models
from pysymex._internal.models.stdlib.platform.models import platform_models
from pysymex._internal.models.stdlib.posixpath.models import posixpath_models
from pysymex._internal.models.stdlib.pprint.models import pprint_models
from pysymex._internal.models.stdlib.queue.models import queue_models
from pysymex._internal.models.stdlib.quopri.models import quopri_models
from pysymex._internal.models.stdlib.secrets.models import secrets_models
from pysymex._internal.models.stdlib.shlex.models import shlex_models
from pysymex._internal.models.stdlib.shutil.models import shutil_models
from pysymex._internal.models.stdlib.socket.models import socket_models
from pysymex._internal.models.stdlib.stat.models import stat_models
from pysymex._internal.models.stdlib.statistics.models import statistics_models
from pysymex._internal.models.stdlib.string.models import string_models
from pysymex._internal.models.stdlib.struct.models import struct_models
from pysymex._internal.models.stdlib.tempfile.models import tempfile_models
from pysymex._internal.models.stdlib.textwrap.models import textwrap_models
from pysymex._internal.models.stdlib.threading.models import threading_models
from pysymex._internal.models.stdlib.time.models import time_models
from pysymex._internal.models.stdlib.tomllib.models import tomllib_models
from pysymex._internal.models.stdlib.typing.models import typing_models
from pysymex._internal.models.stdlib.unicodedata.models import unicodedata_models
from pysymex._internal.models.stdlib.urllib.models import urllib_parse_models
from pysymex._internal.models.stdlib.uuid.models import uuid_models
from pysymex._internal.models.stdlib.zlib.models import zlib_models

if TYPE_CHECKING:
    from pysymex._internal.models.contracts.function import FunctionModel

stdlib_family_models: list[FunctionModel] = [
    *array_models,
    *base64_models,
    *binascii_models,
    *bz2_models,
    *calendar_models,
    *codecs_models,
    *configparser_models,
    *copyreg_models,
    *csv_models,
    *decimal_models,
    *fnmatch_models,
    *fractions_models,
    *glob_models,
    *gzip_models,
    *hashlib_models,
    *html_models,
    *hmac_models,
    *importlib_models,
    *inspect_models,
    *ipaddress_models,
    *keyword_models,
    *lzma_models,
    *logging_models,
    *marshal_models,
    *mimetypes_models,
    *ntpath_models,
    *numbers_models,
    *pickle_models,
    *platform_models,
    *posixpath_models,
    *pprint_models,
    *queue_models,
    *quopri_models,
    *secrets_models,
    *shlex_models,
    *shutil_models,
    *socket_models,
    *stat_models,
    *statistics_models,
    *string_models,
    *struct_models,
    *tempfile_models,
    *threading_models,
    *time_models,
    *textwrap_models,
    *tomllib_models,
    *typing_models,
    *unicodedata_models,
    *urllib_parse_models,
    *uuid_models,
    *zlib_models,
]
