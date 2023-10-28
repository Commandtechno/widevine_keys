# uncompyle6 version 3.7.3
# Python bytecode 3.6 (3379)
# Decompiled from: Python 3.7.8 (tags/v3.7.8:4b47a5b6ba, Jun 28 2020, 08:53:46) [MSC v.1916 64 bit (AMD64)]
# Embedded file name: pywidevine\decrypt\wvdecryptcustom.py
import logging, subprocess, re, base64
from api import Api


class WvDecrypt(object):
    def __init__(self, init_data_b64, cert_data_b64, device):
        self.api = Api()
        self.init_data_b64 = init_data_b64
        self.cert_data_b64 = cert_data_b64
        self.api.set_cert(self.cert_data_b64)

    def log_message(self, msg):
        return "{}".format(msg)

    def start_process(self):
        keyswvdecrypt = []
        try:
            for key in self.api.get_keys(self.session):
                if key.type == "CONTENT":
                    keyswvdecrypt.append(
                        self.log_message("{}:{}".format(key.kid.hex(), key.key.hex()))
                    )

        except Exception:
            return (False, keyswvdecrypt)
        else:
            return (True, keyswvdecrypt)

    def get_challenge(self):
        return self.api.get_license_challenge(self.init_data_b64)

    def update_license(self, license_b64):
        self.cdm.provide_license(self.session, license_b64)
        return True
