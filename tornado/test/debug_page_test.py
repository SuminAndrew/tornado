# coding=utf-8

from __future__ import absolute_import, division, print_function, with_statement

import base64

from tornado import gen
from tornado.escape import json_decode
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application, HTTPError, RequestHandler


class DebugPageHandler(RequestHandler):
    @gen.coroutine
    def get(self, *args, **kwargs):
        self.add_header("X-Foo", "Bar")
        self.set_status(400)

        self.write("chunk1\n")
        yield self.flush()
        self.write("chunk2\n")
        yield self.flush()
        self.finish("chunk3")


class ErrorPageHandler(RequestHandler):
    def get(self, *args, **kwargs):
        raise HTTPError(503, 'Error message')


class DebugPageTest(AsyncHTTPTestCase):
    def get_app(self):
        app_settings = {
            "debug_param_name": "debug",
            "enable_debug_page": True
        }

        return Application([
            ("/simple", DebugPageHandler),
            ("/error", ErrorPageHandler),
        ], **app_settings)

    def test_debug_content(self):
        response = self.fetch("/simple?debug")
        self.assertEqual(response.code, 200)

        debug_data = json_decode(response.body)

        self.assertEqual(debug_data["status_code"], 400)
        self.assertEqual(debug_data["reason"], "Bad Request")

        self.assertEqual(debug_data["headers"]["X-Foo"], "Bar")
        self.assertIn("text/html", debug_data["headers"]["Content-Type"])

        self.assertEqual(
            [b"chunk1\n", b"chunk2\n", b"chunk3"],
            [base64.b64decode(c) for c in debug_data["chunks_base64"]]
        )

    def test_http_error(self):
        response = self.fetch("/error?debug")
        self.assertEqual(response.code, 200)

        debug_data = json_decode(response.body)

        self.assertEqual(
            [b"<html><title>503: Service Unavailable</title><body>503: Service Unavailable</body></html>"],
            [base64.b64decode(c) for c in debug_data["chunks_base64"]]
        )
