"""Dispatch by Host header: bank.* -> ZenithBank, shop.* -> ShopEasy, anything else -> the original demo/echo site."""
from app import app as legacy
from bank import app as bank
from shop import app as shop


def application(environ, start_response):
    host = environ.get("HTTP_HOST", "").split(":")[0].lower()
    target = bank if host.startswith("bank.") else shop if host.startswith("shop.") else legacy
    return target(environ, start_response)
