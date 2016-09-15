import re
from functools import partial

from tornado import httputil
from tornado.httpserver import _CallableAdapter
from tornado.escape import url_escape, url_unescape, utf8
from tornado.log import app_log
from tornado.util import basestring_type, import_object, re_unescape, unicode_type


class Router(httputil.HTTPServerConnectionDelegate):
    def add_handlers(self, *args):
        pass

    def find_handler(self, request, **kwargs):
        raise NotImplementedError()

    def start_request(self, server_conn, request_conn):
        return _RoutingDelegate(self, request_conn)


class ReversibleRouter(Router):
    def reverse_url(self, name, *args):
        raise NotImplementedError()


class _RoutingDelegate(httputil.HTTPMessageDelegate):
    def __init__(self, router, request_conn):
        self.connection = request_conn
        self.delegate = None
        self.router = router

    def headers_received(self, start_line, headers):
        request = httputil.HTTPServerRequest(
            connection=self.connection, start_line=start_line,
            headers=headers)

        self.delegate = self.router.find_handler(request)
        return self.delegate.headers_received(start_line, headers)

    def data_received(self, chunk):
        return self.delegate.data_received(chunk)

    def finish(self):
        self.delegate.finish()

    def on_connection_close(self):
        self.delegate.on_connection_close()


class RuleRouter(Router):
    def __init__(self, rules=None):
        self.rules = []
        if rules:
            self.add_handlers(rules)

    def add_handlers(self, handlers):
        for rule in handlers:
            if isinstance(rule, (tuple, list)):
                assert len(rule) in (2, 3, 4)
                if isinstance(rule[0], basestring_type):
                    rule = URLSpec(*rule)
                else:
                    rule = Rule(*rule)

            self.rules.append(self.process_rule(rule))

    def process_rule(self, rule):
        return rule

    def find_handler(self, request, **kwargs):
        for rule in self.rules:
            target_params = rule.matcher(request)
            if target_params is not None:
                if rule.target_kwargs:
                    target_params['target_kwargs'] = rule.target_kwargs

                delegate = self.get_target_delegate(
                    rule.target, request, **target_params)

                if delegate is not None:
                    return delegate

        return None

    def get_target_delegate(self, target, request, **target_params):
        if isinstance(target, Router):
            route = target.find_handler(request, **target_params)
            if route is not None:
                return route

        elif callable(target):
            return _CallableAdapter(
                partial(target, **target_params), request.connection
            )

        return None


class ReversibleRuleRouter(ReversibleRouter, RuleRouter):
    def __init__(self, rules=None):
        self.named_rules = {}
        super(ReversibleRuleRouter, self).__init__(rules)

    def process_rule(self, rule):
        rule = super(ReversibleRuleRouter, self).process_rule(rule)

        if rule.name:
            if rule.name in self.named_rules:
                app_log.warning(
                    "Multiple handlers named %s; replacing previous value",
                    rule.name)
            self.named_rules[rule.name] = rule

        return rule

    def reverse_url(self, name, *args):
        if name in self.named_rules:
            return self.named_rules[name].matcher.reverse(*args)

        for rule in self.rules:
            if isinstance(rule.target, ReversibleRouter):
                reversed_url = rule.target.reverse_url(name, *args)
                if reversed_url is not None:
                    return reversed_url

        return None


class Rule(object):
    def __init__(self, matcher, target, target_kwargs=None, name=None):
        self.matcher = matcher
        self.target = target
        self.target_kwargs = target_kwargs if target_kwargs else {}
        self.name = name

    def reverse(self, *args):
        if isinstance(self.matcher, Matcher):
            return self.matcher.reverse(*args)
        return None

    def __repr__(self):
        return '%s(%r, %s, kwargs=%r, name=%r)' % \
               (self.__class__.__name__, self.matcher,
                self.target, self.target_kwargs, self.name)


class Matcher(object):
    """A complex matcher can be represented as an instance of some
    `Matcher` subclass. It must implement ``__init__`` (for example
    to initialize a regex pattern) and ``__call__`` (which is called
    with a `httpserver.HTTPRequest` argument).
    """

    def __call__(self, request):
        """Matches an instance against the request.

        :returns a dict of parameters (handler_kwargs, path_args, path_kwargs)
        to be passed to the target handler"""
        raise NotImplementedError()

    def reverse(self, *args):
        """Reconstruct URL from matcher instance"""
        return None


ANY_MATCHES = lambda request: {}


class host_matches(Matcher):
    def __init__(self, host_pattern):
        if isinstance(host_pattern, basestring_type):
            if not host_pattern.endswith("$"):
                host_pattern += "$"
            self.host_pattern = re.compile(host_pattern)
        else:
            self.host_pattern = host_pattern

    def __call__(self, request):
        if not hasattr(request, '_host'):
            request._host = httputil.split_host_and_port(request.host.lower())[0]

        if self.host_pattern.match(request._host):
            return {}

        return None


class default_host_matches(Matcher):
    def __init__(self, application, host_pattern):
        self.application = application
        self.host_pattern = host_pattern

    def __call__(self, request):
        # Look for default host if not behind load balancer (for debugging)
        if "X-Real-Ip" not in request.headers:
            if self.host_pattern.match(self.application.default_host):
                return {}
        return None


class path_matches(Matcher):
    def __init__(self, pattern):
        if isinstance(pattern, basestring_type):
            if not pattern.endswith('$'):
                pattern += '$'
            self.regex = re.compile(pattern)
        else:
            self.regex = pattern

        assert len(self.regex.groupindex) in (0, self.regex.groups), \
            ("groups in url regexes must either be all named or all "
             "positional: %r" % self.regex.pattern)

        self._path, self._group_count = self._find_groups()

    def __call__(self, request):
        match = self.regex.match(request.path)
        if match is None:
            return None
        if not self.regex.groups:
            return {}

        path_args, path_kwargs = [], {}

        # Pass matched groups to the handler.  Since
        # match.groups() includes both named and
        # unnamed groups, we want to use either groups
        # or groupdict but not both.
        if self.regex.groupindex:
            path_kwargs = dict(
                (str(k), _unquote_or_none(v))
                for (k, v) in match.groupdict().items())
        else:
            path_args = [_unquote_or_none(s) for s in match.groups()]

        return dict(path_args=path_args, path_kwargs=path_kwargs)

    def reverse(self, *args):
        if self._path is None:
            raise ValueError("Cannot reverse url regex " + self.regex.pattern)
        assert len(args) == self._group_count, "required number of arguments " \
                                               "not found"
        if not len(args):
            return self._path
        converted_args = []
        for a in args:
            if not isinstance(a, (unicode_type, bytes)):
                a = str(a)
            converted_args.append(url_escape(utf8(a), plus=False))
        return self._path % tuple(converted_args)

    def _find_groups(self):
        """Returns a tuple (reverse string, group count) for a url.

        For example: Given the url pattern /([0-9]{4})/([a-z-]+)/, this method
        would return ('/%s/%s/', 2).
        """
        pattern = self.regex.pattern
        if pattern.startswith('^'):
            pattern = pattern[1:]
        if pattern.endswith('$'):
            pattern = pattern[:-1]

        if self.regex.groups != pattern.count('('):
            # The pattern is too complicated for our simplistic matching,
            # so we can't support reversing it.
            return None, None

        pieces = []
        for fragment in pattern.split('('):
            if ')' in fragment:
                paren_loc = fragment.index(')')
                if paren_loc >= 0:
                    pieces.append('%s' + fragment[paren_loc + 1:])
            else:
                try:
                    unescaped_fragment = re_unescape(fragment)
                except ValueError as exc:
                    # If we can't unescape part of it, we can't
                    # reverse this url.
                    return (None, None)
                pieces.append(unescaped_fragment)

        return ''.join(pieces), self.regex.groups


class URLSpec(Rule):
    """Specifies mappings between URLs and handlers."""
    def __init__(self, pattern, handler, kwargs=None, name=None):
        """Parameters:

        * ``pattern``: Regular expression to be matched. Any capturing
          groups in the regex will be passed in to the handler's
          get/post/etc methods as arguments (by keyword if named, by
          position if unnamed. Named and unnamed capturing groups may
          may not be mixed in the same rule).

        * ``handler``: `RequestHandler` subclass to be invoked.

        * ``kwargs`` (optional): A dictionary of additional arguments
          to be passed to the handler's constructor.

        * ``name`` (optional): A name for this handler.  Used by
          `Application.reverse_url`.

        """
        if isinstance(handler, str):
            # import the Module and instantiate the class
            # Must be a fully qualified name (module.ClassName)
            handler = import_object(handler)

        matcher = path_matches(pattern)
        self.regex = matcher.regex
        self.handler_class = handler
        self.kwargs = kwargs

        super(URLSpec, self).__init__(matcher, handler, kwargs, name)

    def __repr__(self):
        return '%s(%r, %s, kwargs=%r, name=%r)' % \
               (self.__class__.__name__, self.regex.pattern,
                self.handler_class, self.kwargs, self.name)


def _unquote_or_none(s):
    """None-safe wrapper around url_unescape to handle unmatched optional
    groups correctly.

    Note that args are passed as bytes so the handler can decide what
    encoding to use.
    """
    if s is None:
        return s
    return url_unescape(s, encoding=None, plus=False)
