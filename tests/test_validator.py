import pytest
from alavitrace.core.validator import validate_target

def test_valid_ipv4():
    target = validate_target("192.168.56.101")
    assert target.is_valid is True
    assert target.normalized == "192.168.56.101"
    assert target.target_type == "IPv4"

def test_ipv4_with_url_prefix():
    target = validate_target("http://10.0.0.1:8080/index.html")
    assert target.is_valid is True
    assert target.normalized == "10.0.0.1"
    assert target.target_type == "IPv4"

def test_valid_domain():
    target = validate_target("scanme.nmap.org")
    assert target.is_valid is True
    assert target.normalized == "scanme.nmap.org"
    assert target.target_type == "Domain"

def test_valid_hostname():
    target = validate_target("metasploitable")
    assert target.is_valid is True
    assert target.normalized == "metasploitable"
    assert target.target_type == "Hostname"

def test_invalid_target_empty():
    target = validate_target("")
    assert target.is_valid is False
    assert target.target_type == "Invalid"

def test_invalid_target_special_chars():
    target = validate_target("192.168.1.1; cat /etc/passwd")
    assert target.is_valid is False
    assert target.target_type == "Invalid"
