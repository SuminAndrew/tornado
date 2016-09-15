from tornado.routing import host_matches, path_matches, ReversibleRouter, Rule, RuleRouter
from tornado.testing import AsyncHTTPTestCase
from tornado.web import Application, RequestHandler
from tornado.wsgi import WSGIContainer


def get_named_handler(handler_name):
    class Handler(RequestHandler):
        def get(self, *args, **kwargs):
            if self.application.settings.get("app_name") is not None:
                self.write(self.application.settings["app_name"] + ": ")

            self.finish(handler_name + ": " + self.reverse_url(handler_name))

    return Handler


FirstHandler = get_named_handler("first_handler")
SecondHandler = get_named_handler("second_handler")


class CustomRouter(ReversibleRouter):
    def __init__(self):
        super(CustomRouter, self).__init__()
        self.routes = {}

    def add_handlers(self, handlers):
        self.routes.update(handlers)

    def find_handler(self, request, **kwargs):
        if request.path in self.routes:
            app, handler = self.routes[request.path]
            return app.get_handler_delegate(request, handler)

    def reverse_url(self, name, *args):
        handler_path = '/' + name
        return handler_path if handler_path in self.routes else None


class CustomRouterTestCase(AsyncHTTPTestCase):
    def get_app(self):
        class CustomApplication(Application):
            def reverse_url(self, name, *args):
                return router.reverse_url(name, *args)

        router = CustomRouter()
        app1 = CustomApplication(app_name="app1")
        app2 = CustomApplication(app_name="app2")

        router.add_handlers({
            "/first_handler": (app1, FirstHandler),
            "/second_handler": (app2, SecondHandler),
            "/first_handler_second_app": (app2, FirstHandler),
        })

        return router

    def test_custom_router(self):
        response = self.fetch("/first_handler")
        self.assertEqual(response.body, b"app1: first_handler: /first_handler")
        response = self.fetch("/second_handler")
        self.assertEqual(response.body, b"app2: second_handler: /second_handler")
        response = self.fetch("/first_handler_second_app")
        self.assertEqual(response.body, b"app2: first_handler: /first_handler")


class RuleRouterTest(AsyncHTTPTestCase):
    def get_app(self):
        app = Application()

        app.add_handlers(".*", [
            (host_matches("www.example.com"), [
                (path_matches("/first_handler"), SecondHandler, {}, "second_handler")
            ]),
            Rule(path_matches("/first_handler"), FirstHandler, name="first_handler"),
        ])

        return app

    def test_rule_based_router(self):
        response = self.fetch("/first_handler")
        self.assertEqual(response.body, b"first_handler: /first_handler")
        response = self.fetch("/first_handler", headers={'Host': 'www.example.com'})
        self.assertEqual(response.body, b"second_handler: /first_handler")

        response = self.fetch("/404")
        self.assertEqual(response.code, 404)


class WSGIContainerTestCase(AsyncHTTPTestCase):
    def get_app(self):
        wsgi_app = WSGIContainer(self.wsgi_app)

        class Handler(RequestHandler):
            def get(self, *args, **kwargs):
                self.finish(self.reverse_url("tornado"))

        return RuleRouter([
            (path_matches("/tornado.*"), Application([(r"/tornado/test", Handler, {}, "tornado")])),
            (path_matches("/wsgi"), wsgi_app),
        ])

    def wsgi_app(self, environ, start_response):
        start_response("200 OK", [])
        return [b"WSGI"]

    def test_wsgi_container(self):
        response = self.fetch("/tornado/test")
        self.assertEqual(response.body, b"/tornado/test")

        response = self.fetch("/wsgi")
        self.assertEqual(response.body, b"WSGI")
