import logging
from typing import List, Optional
from alavitrace.core.models import Finding
from alavitrace.validation.base import BaseValidator
from alavitrace.validation.validators import (
    SQLInjectionValidator,
    ReflectedXSSValidator,
    ReflectedInputValidator,
    PathTraversalValidator,
    CommandInjectionValidator,
    CSRFValidator,
    SSRFCandidateValidator,
    IDORCandidateValidator,
    AuthenticationSecurityValidator,
    HeaderValidator,
    ResponseBehaviorValidator,
    MisconfigurationValidator,
    ServicePresenceValidator,
    FallbackValidator
)

logger = logging.getLogger("AlaviTrace")

class ValidatorRegistry:
    """
    Registry managing mapping between findings and appropriate validators.
    Maintains priority order among validators with a safety fallback.
    """

    def __init__(self, load_defaults: bool = True):
        self._validators: List[BaseValidator] = []
        if load_defaults:
            self._register_defaults()

    @property
    def validators(self) -> List[BaseValidator]:
        """Returns the registered validators in precedence order."""
        return list(self._validators)

    def _register_defaults(self) -> None:
        """Registers the built-in validators in precedence order."""
        # Order matters: more specific web vulnerability validators first
        self._validators.append(SQLInjectionValidator())
        self._validators.append(ReflectedXSSValidator())
        self._validators.append(PathTraversalValidator())
        self._validators.append(CommandInjectionValidator())
        self._validators.append(CSRFValidator())
        self._validators.append(SSRFCandidateValidator())
        self._validators.append(IDORCandidateValidator())
        self._validators.append(AuthenticationSecurityValidator())
        self._validators.append(HeaderValidator())
        self._validators.append(MisconfigurationValidator())
        self._validators.append(ResponseBehaviorValidator())
        self._validators.append(ServicePresenceValidator())
        self._validators.append(FallbackValidator())

    def register(self, validator: BaseValidator, prepend: bool = False) -> None:
        """Registers a validator instance."""
        if prepend:
            self._validators.insert(0, validator)
        else:
            # Insert before the FallbackValidator if present
            if self._validators and isinstance(self._validators[-1], FallbackValidator):
                self._validators.insert(-1, validator)
            else:
                self._validators.append(validator)

    def get_validator(self, finding: Finding) -> BaseValidator:
        """
        Finds the first registered validator that claims support for the finding.
        Always returns at least FallbackValidator.
        """
        for validator in self._validators:
            try:
                if validator.can_validate(finding):
                    return validator
            except Exception as e:
                logger.warning(f"Error checking can_validate on {validator.name}: {e}")

        return FallbackValidator()

    @property
    def registered_validators(self) -> List[BaseValidator]:
        """Returns list of all currently registered validators."""
        return list(self._validators)
