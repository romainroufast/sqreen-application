import unittest
import tempfile
from backend import LogSqreenWebhookManager, SlackSqreenWebhookManager

alert_events = [{'message_id': None, 'api_version': '2', 'date_created': '2020-06-08T19:30:16.039128+00:00',
                 'message_type': 'security_event', 'retry_count': 0,
                 'message': {'risk_coefficient': 25, 'event_category': 'http_error', 'event_kind': 'waf',
                             'application_id': '5ede853e66ff200020ad47db', 'application_name': 'romain_test',
                             'environment': 'development', 'date_occurred': '2020-06-08T18:41:14.475000+00:00',
                             'event_id': '5ede864a699b1000110a9d81',
                             'event_url': 'https://my.sqreen.com/application/5ede853e66ff200020ad47db/events/5ede864a699b1000110a9d81',
                             'humanized_description': 'Attack tentative from 127.0.0.1', 'ips': [
                         {'address': '127.0.0.1', 'is_tor': False, 'geo': {},
                          'date_resolved': '2020-06-08T18:41:14.636000+00:00'}]}}]


class TestSqreenAlertManagers(unittest.TestCase):

    def test_log_backend(self):
        """
        we are testing here that:
        - logs filepath is correct
        - logs file content is correct
        - logs file content after append operation is correct
        - logs file content not correct
        - close file descriptor
        """
        fo = tempfile.NamedTemporaryFile()
        log_backend = LogSqreenWebhookManager(filepath=fo.name)
        self.assertEqual(log_backend.filepath, fo.name, f'logs filepath should be {fo.name}')

        """check log file content"""
        expected = b'2020-06-08T18:41:14.475000+00:00 romain_test [http_error] (retry:0, coeff.:25) Attack tentative ' \
                   b'from 127.0.0.1\r\n'
        errors = log_backend.dispatch_security_alert(alert_events)
        self.assertEqual(len(errors), 0, 'there should be no error')
        content = fo.read()
        self.assertEqual(content, expected, f'content from log file should be {expected}')

        """check append correctly to log file """
        expected = b'2020-06-08T18:41:14.475000+00:00 romain_test [http_error] (retry:0, coeff.:25) Attack tentative ' \
                   b'from 127.0.0.1\r\n'
        errors = log_backend.dispatch_security_alert(alert_events)
        self.assertEqual(len(errors), 0, 'there should be no error')
        content = fo.read()
        self.assertEqual(content, expected, f'content from log file should be {expected}')

        """check wrong log file content"""
        expected = b'T2020-06-08T18:41:14.475000+00:00 romain_test [http_error] (retry:0, coeff.:25) Attack tentative ' \
                   b'from 127.0.0.1\r\n'
        errors = log_backend.dispatch_security_alert(alert_events)
        self.assertEqual(len(errors), 0, 'there should be no error')
        content = fo.read()
        self.assertNotEqual(content, expected, f'content from log file should be {expected}')

        """test close file descriptor"""
        log_backend.f.close()
        errors = log_backend.dispatch_security_alert(alert_events)
        self.assertEqual(len(errors), 1, 'should be one error')
        err = errors[0]
        self.assertEqual(err.get_message(), "unexpected error writing log file: I/O operation on closed file.",
                         'wrong error')

        """close file descriptors"""
        fo.close()
        log_backend.close()

    def test_slack_backend(self):
        """
        we are testing here that:
        - public channel is correct
        - invalid auth
        """
        expected_public_channel = 'general'
        expected_api_token = 'test'
        slack_backend = SlackSqreenWebhookManager(public_channel=expected_public_channel, api_token=expected_api_token)
        self.assertEqual(slack_backend.public_channel, expected_public_channel,
                         f'channel should be {expected_public_channel}')

        errors = slack_backend.dispatch_security_alert(alert_events)
        self.assertEqual(len(errors), 1, 'should be one error')
        expected_error = 'invalid_auth'
        err = errors[0]
        self.assertEqual(err.get_message(), expected_error, 'wrong error returned')

        slack_backend.close()


if __name__ == '__main__':
    unittest.main()
