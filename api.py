import requests
import binascii
import base64

url = ""
token = ""


class Key:
    def __init__(self, kid, type, key, permissions=[]):
        self.kid = kid
        self.type = type
        self.key = key
        self.permissions = permissions

    def __repr__(self):
        if self.type == "OPERATOR_SESSION":
            return "key(kid={}, type={}, key={}, permissions={})".format(
                self.kid, self.type, binascii.hexlify(self.key), self.permissions
            )
        else:
            return "key(kid={}, type={}, key={})".format(
                self.kid, self.type, binascii.hexlify(self.key)
            )


class Api:
    def __init__(self):
        self.cert = None

    def set_cert(self, cert):
        self.cert = cert

    def req(self, method, params):
        res = requests.post(
            url, json={"method": method, "params": params, "token": token}
        ).json()

        if res.get("status_code") != 200:
            raise ValueError(
                f"CDM API returned an error: {res['status_code']} - {res['message']}"
            )

        return res["message"]

    def get_license_challenge(self, pssh):
        res = self.req(
            "GetChallenge",
            {
                "init": pssh,
                "cert": self.cert,
            },
        )

        self.api_session_id = res["session_id"]

        return base64.b64decode(res["challenge"])

    def get_keys(self, session, license_res):
        if isinstance(license_res, bytes):
            license_res = base64.b64encode(license_res).decode()

        res = self.req(
            "GetKeys",
            {"cdmkeyresponse": license_res, "session_id": self.api_session_id},
        )

        return [
            Key(
                kid=bytes.fromhex(x["kid"]),
                key_type=x.get("type", "CONTENT"),
                key=bytes.fromhex(x["key"]),
            )
            for x in res["keys"]
        ]
