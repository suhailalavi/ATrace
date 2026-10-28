import logging
from typing import Dict, List, Optional

from alavitrace.assessment.base import BaseAssessmentCheck
from alavitrace.assessment.models import OwaspCategory

logger = logging.getLogger("AlaviTrace")

class CheckRegistry:
    """
    Registry for managing OWASP Web Security Assessment checks.
    Allows dynamic registration, retrieval, and execution of assessment checks
    without hard-coding check implementations into CLI or engine layers.
    """

    def __init__(self):
        self._checks: Dict[str, BaseAssessmentCheck] = {}

    def register(self, check: BaseAssessmentCheck) -> None:
        """
        Registers an assessment check instance.
        """
        if not isinstance(check, BaseAssessmentCheck):
            raise TypeError(f"Check must inherit from BaseAssessmentCheck (got {type(check)})")

        if check.name in self._checks:
            logger.warning(f"Overwriting existing registered check: {check.name}")

        self._checks[check.name] = check
        logger.debug(f"Registered OWASP check: {check.name} ({check.category.value})")

    def unregister(self, name: str) -> Optional[BaseAssessmentCheck]:
        """
        Unregisters and returns a check by name if present.
        """
        return self._checks.pop(name, None)

    def get(self, name: str) -> Optional[BaseAssessmentCheck]:
        """
        Retrieves a check by name.
        """
        return self._checks.get(name)

    def get_all(self) -> List[BaseAssessmentCheck]:
        """
        Returns all registered assessment checks.
        """
        return list(self._checks.values())

    def get_by_category(self, category: OwaspCategory) -> List[BaseAssessmentCheck]:
        """
        Returns all registered checks matching a specific OWASP category.
        """
        return [chk for chk in self._checks.values() if chk.category == category]

    def clear(self) -> None:
        """
        Clears all registered checks.
        """
        self._checks.clear()

    def __len__(self) -> int:
        return len(self._checks)

    def __contains__(self, name: str) -> bool:
        return name in self._checks


# Global default registry instance
default_registry = CheckRegistry()

def get_default_registry() -> CheckRegistry:
    """Returns the shared default registry instance, populating builtin checks if empty."""
    if len(default_registry) == 0:
        from alavitrace.assessment.base import register_builtin_checks
        register_builtin_checks(default_registry)
    return default_registry

