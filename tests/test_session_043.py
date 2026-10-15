"""Warning for memory storage with several processes (0.4.3)."""
import logging

import pytest

from EasyOIDC import SessionHandler
from EasyOIDC.session import detect_multiple_workers


@pytest.mark.parametrize('environ,argv,expected', [
    ({}, ['uvicorn', 'app:app'], False),
    ({'WEB_CONCURRENCY': '1'}, ['uvicorn', 'app:app'], False),
    ({'WEB_CONCURRENCY': '4'}, ['uvicorn', 'app:app'], True),
    ({'WEB_CONCURRENCY': 'x'}, ['uvicorn', 'app:app'], False),
    ({}, ['uvicorn', 'app:app', '--workers', '2'], True),
    ({}, ['uvicorn', 'app:app', '--workers=3'], True),
    ({}, ['uvicorn', 'app:app', '--workers', '1'], False),
    ({}, ['gunicorn', '-w', '4', 'app:app'], True),
    ({}, ['gunicorn', '-w4', 'app:app'], True),
    ({}, ['pytest', '-q'], False),
])
def test_detect_multiple_workers(environ, argv, expected):
    assert bool(detect_multiple_workers(environ, argv)) is expected


def test_memory_mode_warns_with_several_workers(monkeypatch, caplog):
    monkeypatch.setenv('WEB_CONCURRENCY', '4')
    with caplog.at_level(logging.WARNING, logger='EasyOIDC'):
        SessionHandler(mode='memory')
    assert 'WEB_CONCURRENCY=4' in caplog.text and "mode='redis'" in caplog.text


def test_memory_mode_single_process_does_not_warn(monkeypatch, caplog):
    monkeypatch.delenv('WEB_CONCURRENCY', raising=False)
    monkeypatch.setattr('sys.argv', ['uvicorn', 'app:app'])
    with caplog.at_level(logging.WARNING, logger='EasyOIDC'):
        SessionHandler(mode='memory')
    assert caplog.text == ''
