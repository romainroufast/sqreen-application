import sqreen

sqreen.start()
import hashlib
import hmac
import os
import signal
import json

from flask import Flask, jsonify, request
from backend import Backends, LogSqreenWebhookManager, SlackSqreenWebhookManager
from worker import SqreenAlertDispatchWorker, SecurityAlertQueueEvent

"""initiate the Flask app main controller"""
app = Flask(__name__)

"""
environment variables:
   - SQREEN_SECRET key validates the signature of any alert
   - SLACK_TOKEN used for slack backend integration
   - SLACK_CHANNEL for alert publication
   - LOG_PATH where security alerts will be written (default ./logs.txt)
   - NB_WORKER_THREAD for number of worker threads that will manage dispatching alerts through the different backends (default 1) 
"""
secret_key = str.encode(os.environ.get("SQREEN_SECRET"))
slack_token = os.environ.get("SLACK_TOKEN") or None
slack_channel = os.environ.get("SLACK_CHANNEL") or None
num_fetch_threads = os.environ.get("NB_WORKER_THREAD") or 1
num_fetch_threads = int(num_fetch_threads)
log_path = os.environ.get("LOG_PATH") or "./logs.txt"


"""
backends contains all of the alert dispatchers
all of the backends must implement SqreenWebhookManagerInterface
"""
log_backend = LogSqreenWebhookManager('./logs.txt')
slack_backend = SlackSqreenWebhookManager(api_token=slack_token, public_channel=slack_channel)
backends = Backends(log_backend, slack_backend)

"""
we set a bunch of background workers to dispatch the alerts to not block the main thread
logging & alerting should impact minimum of the application main thread resources
"""
security_alerts_queue_manager = SqreenAlertDispatchWorker(num_fetch_threads=num_fetch_threads)


def check_signature(s_key, request_signature, request_body):
    """check equality of signatures between hex(hmacsha26(secret,body)) and request_signature"""
    hasher = hmac.new(s_key, request_body, hashlib.sha256)
    dig = hasher.hexdigest()

    return hmac.compare_digest(dig, request_signature)


@app.route('/')
def hello_sqreen():
    """route under attack"""
    return 'Hello Sqreen!'


@app.route('/security_alert', methods=['POST'])
def security_alert():
    """
    callback url for alerts triggered by sqreen webhooks
    see https://docs.sqreen.com/integrations/webhooks/#configure-a-webhook
    in case of a real world application, we should separate the controller from the application logic
    manage security alerts from sqreen platform
    first check the signature of the message
    then push events to a queue
    """
    req_body = request.get_data()
    req_sig = request.headers['X-Sqreen-Integrity']

    """signature check"""
    if not check_signature(secret_key, req_sig, req_body):
        raise InvalidUsage('wrong signature', 400)

    """
    dispatch alerts
    put the event in the queue
    """
    json_body = request.get_json()
    security_alerts_queue_manager.push(SecurityAlertQueueEvent(backends=backends, event=json_body))

    return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}


"""api error management"""


class InvalidUsage(Exception):
    """api exception class"""
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


@app.errorhandler(InvalidUsage)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


"""handle end of program"""


def close():
    iter_close = backends.get()
    for b in iter_close:
        b.close()


if __name__ == '__main__':
    signal.signal(signal.SIGQUIT, close)
    signal.signal(signal.SIGKILL, close)
    signal.signal(signal.SIGTERM, close)
