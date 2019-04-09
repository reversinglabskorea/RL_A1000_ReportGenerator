#!/usr/bin/python
#-*- coding: utf-8 -*-

from jinja2 import Template, Environment, FileSystemLoader

import sys
import os
import requests
import base64
import json
import argparse
import urllib.request
import hashlib

def generate_headers(user, password):
    data = '%s:%s' % (user, password)
    auth = base64.b64encode(data.encode('utf-8')).decode()
    headers = {
        'Authorization': 'Basic %s' % (auth,)
    }
    return headers
