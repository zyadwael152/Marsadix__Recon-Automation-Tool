import logging

from marsadix.core.log import setup_logging


def test_setup_logging_preserves_host_handlers():
    root = logging.getLogger()
    sentinel = logging.NullHandler()
    root.addHandler(sentinel)
    try:
        before = tuple(root.handlers)
        setup_logging(verbose=True)
        assert tuple(root.handlers) == before
        assert sentinel in root.handlers
    finally:
        root.removeHandler(sentinel)
