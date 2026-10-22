from __future__ import annotations

import json
import socket
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from rabanito.server import RabanitoHandler, ThreadingHTTPServer


class HttpFramingTests(unittest.TestCase):
    def setUp(self):
        handler = type('FixtureHandler', (RabanitoHandler,), {'request_read_timeout': .2,
                        'log_message': lambda *args: None, 'settings':SimpleNamespace(max_context_chars=6000)})
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.origin = f'http://127.0.0.1:{self.server.server_port}'

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def connect(self, headers, body=b'', eof=False, path='/api/context'):
        client = socket.create_connection(self.server.server_address, timeout=1)
        client.settimeout(1)
        request = (f'POST {path} HTTP/1.0\r\nHost: 127.0.0.1:{self.server.server_port}\r\n'
                   f'Origin: {self.origin}\r\nContent-Type: application/json\r\n' + headers + '\r\n').encode()
        client.sendall(request + body)
        if eof:
            client.shutdown(socket.SHUT_WR)
        return client

    def response(self, client):
        with client:
            data = b''
            while True:
                try:
                    part = client.recv(8192)
                except ConnectionResetError:
                    break
                if not part:
                    break
                data += part
        status = int(data.split(b' ', 2)[1])
        payload = json.loads(data.split(b'\r\n\r\n', 1)[1])
        return status, payload

    def test_duplicate_lengths_rejected_without_dispatch(self):
        with patch('rabanito.server.retrieve_context') as operation:
            status, payload = self.response(self.connect('Content-Length: 2\r\nContent-Length: 2\r\n', b'{}'))
        self.assertEqual(status, 400)
        self.assertEqual(payload, {'error':'invalid_request_framing'})
        operation.assert_not_called()

    def test_invalid_lengths_and_transfer_encoding_rejected(self):
        for headers in ('Content-Length: -1\r\n', 'Content-Length: +2\r\n',
                        'Content-Length: 2, 2\r\n', 'Content-Length: 2\r\nTransfer-Encoding: chunked\r\n'):
            with self.subTest(headers=headers), patch('rabanito.server.retrieve_context') as operation:
                self.assertEqual(self.response(self.connect(headers, b'{}'))[0], 400)
                operation.assert_not_called()

    def test_excessive_body_rejected_before_read(self):
        status, payload = self.response(self.connect('Content-Length: 16385\r\n'))
        self.assertEqual((status, payload), (413, {'error':'request_size_limit'}))

    def test_truncated_body_rejected_even_when_prefix_is_valid_json(self):
        with patch('rabanito.server.retrieve_context') as operation:
            status, payload = self.response(self.connect('Content-Length: 10\r\n', b'{}', eof=True))
        self.assertEqual((status, payload), (400, {'error':'incomplete_request_body'}))
        operation.assert_not_called()

    def test_incomplete_body_times_out_and_closes_without_dispatch(self):
        with patch('rabanito.server.retrieve_context') as operation:
            started = time.monotonic()
            status, payload = self.response(self.connect('Content-Length: 10\r\n', b'{'))
        self.assertEqual((status, payload), (408, {'error':'request_body_timeout'}))
        self.assertLess(time.monotonic() - started, .9)
        operation.assert_not_called()

    def test_stalled_client_does_not_block_valid_concurrent_request(self):
        stalled = self.connect('Content-Length: 10\r\n', b'{')
        with patch('rabanito.server.retrieve_context', return_value={'fragments':[]}) as operation:
            result = self.response(self.connect('Content-Length: 2\r\n', b'{}'))
            self.assertEqual(result, (200, {'fragments':[]}))
            self.assertEqual(self.response(stalled)[0], 408)
            operation.assert_called_once()

    def test_incomplete_headers_have_a_connection_deadline(self):
        client = socket.create_connection(self.server.server_address, timeout=1)
        client.settimeout(1)
        started = time.monotonic()
        with client:
            client.sendall(b'POST /api/context HTTP/1.0\r\nHost: 127.0.0.1')
            self.assertEqual(client.recv(128), b'')
        self.assertLess(time.monotonic() - started, .9)

    def test_trickling_body_does_not_reset_total_read_deadline(self):
        client = self.connect('Content-Length: 20\r\n', b'{')
        def trickle():
            for _ in range(10):
                time.sleep(.06)
                try: client.sendall(b' ')
                except OSError: break
        sender = threading.Thread(target=trickle, daemon=True)
        sender.start()
        started = time.monotonic()
        self.assertEqual(self.response(client), (408, {'error':'request_body_timeout'}))
        self.assertLess(time.monotonic() - started, .55)
        sender.join(timeout=1)

    def test_document_rejection_drain_also_has_a_total_deadline(self):
        started = time.monotonic()
        with patch('rabanito.server.document_content') as operation:
            status, payload = self.response(self.connect(
                'Origin: http://example.invalid\r\nContent-Length: 20\r\n', b'{', path='/api/doc/content'))
            self.assertEqual((status, payload), (403, {'error':'same_origin_required'}))
            operation.assert_not_called()
        self.assertLess(time.monotonic() - started, .9)


if __name__ == '__main__':
    unittest.main()
