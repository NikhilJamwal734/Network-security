from pathlib import Path
import pytest
from smoke_test import smoke, loopback_url


def test_loopback_only():
    assert loopback_url('http://localhost:8000/')=='http://localhost:8000'
    for candidate in ('https://localhost:8000','http://example.com','http://127.0.0.1:8000/path','http://x:y@localhost:8000'):
        with pytest.raises(ValueError):loopback_url(candidate)


def test_missing_sample_never_uploads(tmp_path):
    ok,message=smoke(tmp_path/'no_file.conf',None,'http://127.0.0.1:8000')
    assert not ok
    assert 'missing' in message.lower()


def test_oversized_sample_never_uploads(tmp_path):
    target=tmp_path/'huge.conf'
    with target.open('wb') as f:
        f.truncate(8*1024*1024+1)
    ok,message=smoke(target,None,'http://127.0.0.1:8000')
    assert not ok
    assert 'exceeds' in message
