import hashlib
import hmac

import sqreen

sqreen.start()
from flask import Flask, jsonify, request

app = Flask(__name__)

secret_key = b'7ed451496901b03b6f6af20e83468c3bc8719bab197a908e58a4f3838211eaaa'


class InvalidUsage(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


def check_signature(s_key, request_signature, request_body):
    hasher = hmac.new(s_key, request_body, hashlib.sha256)
    dig = hasher.hexdigest()

    return hmac.compare_digest(dig, request_signature)


@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/security_alert', methods=['POST'])
def security_alert():
    req_body = request.get_data()
    req_sig = request.headers['X-Sqreen-Integrity']

    if not check_signature(secret_key, req_sig, req_body):
        raise InvalidUsage('wrong signature', 400)

    return 'ok'


@app.errorhandler(InvalidUsage)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


if __name__ == '__main__':
    app.debug = True
    app.run()
