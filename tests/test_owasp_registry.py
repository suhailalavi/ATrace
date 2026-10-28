import pytest
from alavitrace.core.models import Target, ScanResult
from alavitrace.assessment.models import (
    OwaspCategory,
    DetectionType,
    AssessmentContext,
    OWASPFinding
)
from alavitrace.assessment.base import (
    BaseAssessmentCheck,
    AccessControlCheckStub,
    CryptographicFailuresCheckStub,
    InjectionCheckStub,
    SecurityMisconfigurationCheckStub,
    VulnerableComponentsCheckStub,
    AuthenticationCheckStub,
    SSRFCheckStub
)
from alavitrace.assessment.registry import CheckRegistry

class MockCheck(BaseAssessmentCheck):
    category = OwaspCategory.A05_2021
    name = "MockSecurityHeadersCheck"
    description = "Mock check for unit testing"
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext):
        return []

class MockInjectionCheck(BaseAssessmentCheck):
    category = OwaspCategory.A03_2021
    name = "MockSQLiCheck"
    description = "Mock SQL injection check"
    detection_type = DetectionType.ACTIVE

    def check(self, context: AssessmentContext):
        return []

def test_registry_registration_and_lookup():
    reg = CheckRegistry()
    assert len(reg) == 0

    chk1 = MockCheck()
    chk2 = MockInjectionCheck()

    reg.register(chk1)
    reg.register(chk2)

    assert len(reg) == 2
    assert "MockSecurityHeadersCheck" in reg
    assert "MockSQLiCheck" in reg

    # Get by name
    assert reg.get("MockSecurityHeadersCheck") is chk1
    assert reg.get("NonExistent") is None

    # Get by category
    a05_checks = reg.get_by_category(OwaspCategory.A05_2021)
    assert len(a05_checks) == 1
    assert a05_checks[0] is chk1

    a03_checks = reg.get_by_category(OwaspCategory.A03_2021)
    assert len(a03_checks) == 1
    assert a03_checks[0] is chk2

    # Get all
    all_checks = reg.get_all()
    assert len(all_checks) == 2

def test_registry_type_validation():
    reg = CheckRegistry()
    with pytest.raises(TypeError, match="Check must inherit from BaseAssessmentCheck"):
        reg.register("NotACheckInstance")  # type: ignore

def test_registry_unregister_and_clear():
    reg = CheckRegistry()
    chk = MockCheck()
    reg.register(chk)
    assert len(reg) == 1

    removed = reg.unregister(chk.name)
    assert removed is chk
    assert len(reg) == 0

    reg.register(chk)
    assert len(reg) == 1
    reg.clear()
    assert len(reg) == 0

def test_future_check_stubs():
    stubs = [
        AccessControlCheckStub(),
        CryptographicFailuresCheckStub(),
        InjectionCheckStub(),
        SecurityMisconfigurationCheckStub(),
        VulnerableComponentsCheckStub(),
        AuthenticationCheckStub(),
        SSRFCheckStub()
    ]

    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target))

    expected_categories = [
        OwaspCategory.A01_2021,
        OwaspCategory.A02_2021,
        OwaspCategory.A03_2021,
        OwaspCategory.A05_2021,
        OwaspCategory.A06_2021,
        OwaspCategory.A07_2021,
        OwaspCategory.A10_2021
    ]

    for stub, expected_cat in zip(stubs, expected_categories):
        assert isinstance(stub, BaseAssessmentCheck)
        assert stub.category == expected_cat
        assert stub.name.endswith("_Stub")
        # Ensure stub safely returns no findings without raising exceptions
        assert stub.check(context) == []
        assert stub.run(context) == []
