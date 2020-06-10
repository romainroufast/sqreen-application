import abc
from typing import List, Iterator, TextIO, Dict
from multiprocessing import Lock
from slack import WebClient
from slack.errors import SlackApiError

SQREEN_SECURITY_EVENT_TYPE = 'security_event'
SQREEN_MESSAGE_TYPE = 'message_type'
SQREEN_MESSAGE = 'message'
SQREEN_RETRY_COUNT = 'retry_count'
SQREEN_RISK_COEFFICIENT = 'risk_coefficient'
SQREEN_EVENT_CATEGORY = 'event_category'
SQREEN_DATE_OCCURRED = 'date_occurred'
SQREEN_APPLICATION_NAME = 'application_name'
SQREEN_DESCRIPTION = 'humanized_description'
SQREEN_EVENT_URL = 'event_url'

"""mutex to handle concurrency"""
file_logger_mu = Lock()


class BackendError:
    """all of the errors returned by backends must inherit from BackendError"""
    err = None

    def __init__(self, message: str):
        self.err = message

    def get_message(self):
        """
        get error message as txt
        :return: error message
        """
        return self.err


class SqreenWebhookManagerInterface(metaclass=abc.ABCMeta):
    """interface-like webhook manager for sqreen events"""

    @classmethod
    def __subclasshook__(cls, subclass):
        return (hasattr(subclass, 'dispatch_security_alert') and
                callable(subclass.dispatch_security_alert) or
                NotImplemented)

    @abc.abstractmethod
    def dispatch_security_alert(self, events: List[Dict]) -> List[BackendError]:
        """
        dispatch a security alert from sqreen webhook
        logger have to be ready concurrency
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_name(self) -> str:
        """
        get the backend name (e.g. 'log')
        :return: backend unique name
        """
        raise NotImplementedError

    @abc.abstractmethod
    def close(self):
        """release resources"""
        raise NotImplementedError


class LogSqreenWebhookManager(SqreenWebhookManagerInterface):
    """log alerts in txt file"""
    filepath: str = "./sqreen_logs.txt"
    f: TextIO = None

    def __init__(self, filepath: str):
        """
        create/append mode file open for the logs
        :param filepath: logs file path
        """
        if filepath is not None:
            self.filepath = filepath
        self.f = open(self.filepath, "w+")

    def dispatch_security_alert(self, events: List[Dict]) -> List[BackendError]:
        """
        dispatch a security alert in a log file
        :param events: alerts that need to be persisted in log file
        :return: a list of errors
        """
        errors: List[BackendError] = list()
        for e in events:
            try:
                if e[SQREEN_MESSAGE_TYPE] == SQREEN_SECURITY_EVENT_TYPE:
                    m = e[SQREEN_MESSAGE]
                    txt = "%s %s [%s] (retry:%d, coeff.:%d) %s" % (m[SQREEN_DATE_OCCURRED], m[SQREEN_APPLICATION_NAME],
                                                                   m[SQREEN_EVENT_CATEGORY], e[SQREEN_RETRY_COUNT],
                                                                   m[SQREEN_RISK_COEFFICIENT], m[SQREEN_DESCRIPTION])
                    with file_logger_mu:
                        write_response = self.f.write(txt + '\r\n')
                        if write_response <= 0:
                            errors.append(BackendError('error writing log file: ' + txt))
                        else:
                            self.f.flush()
            except Exception as e:
                errors.append(BackendError('unexpected error writing log file: ' + str(e)))

        return errors

    def get_name(self) -> str:
        return 'log'

    def close(self):
        """release resources"""
        if self.f is not None:
            self.f.close()


class SlackSqreenWebhookManager(SqreenWebhookManagerInterface):
    """trigger alerts in slack channel"""
    public_channel: str = 'general'
    client: WebClient = None

    def __init__(self, api_token: str, public_channel: str):
        """
        initialize slack web client
        :param api_token: slack api token
        :param public_channel: target channel to send messages
        """
        if public_channel is not None:
            self.public_channel = public_channel
        self.client = WebClient(token=api_token)

    def dispatch_security_alert(self, events: List[Dict]) -> List[BackendError]:
        """
        dispatch a security alert in a specific slack channel
        :param events: alerts that need to be sent to slack api
        :return: a list of errors
        """
        ch = '#' + self.public_channel
        errors: List[BackendError] = list()
        for e in events:
            if e[SQREEN_MESSAGE_TYPE] == SQREEN_SECURITY_EVENT_TYPE:
                m = e[SQREEN_MESSAGE]
                txt = "%s (%s): %s - %s" % (m[SQREEN_APPLICATION_NAME], m[SQREEN_EVENT_CATEGORY], m[SQREEN_DESCRIPTION],
                                            m[SQREEN_EVENT_URL])
                try:
                    response = self.client.chat_postMessage(
                        channel=ch,
                        text=txt)
                    if response["message"]["text"] != txt:
                        errors.append(BackendError('response text different than sent text'))
                except SlackApiError as e:
                    if e.response["ok"] is False or e.response["error"]:
                        errors.append(BackendError(e.response['error']))

        return errors

    def get_name(self) -> str:
        return 'slack'

    def close(self):
        """release resources"""
        pass


class Backends(object):
    """
    create a list of backends
    all of the backend object must implement the SqreenWebhookManagerInterface
    """
    backends: List[SqreenWebhookManagerInterface] = list()

    def __init__(self, *args: SqreenWebhookManagerInterface):
        """
        raise an exception when arg does not implement SqreenWebhookManagerInterface
        :param args: alerts dispatchers implementing SqreenWebhookManagerInterface
        """
        for b in args:
            if not isinstance(b, SqreenWebhookManagerInterface):
                raise TypeError(
                    type(b).__name__ + ' does not implement ' + type(SqreenWebhookManagerInterface).__name__)
            self.backends.append(b)

    def get(self) -> Iterator[SqreenWebhookManagerInterface]:
        """get all of the backends as an iterator"""
        return iter(self.backends)
