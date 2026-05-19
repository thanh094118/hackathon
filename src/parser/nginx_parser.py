from src.parser.apache_parser import ApacheParser


class NginxParser(ApacheParser):
    """
    Parser for Nginx combined log format.

    In this MVP, Nginx combined logs are parsed with the same structure
    as Apache combined logs.
    """

    server_type = "nginx"
