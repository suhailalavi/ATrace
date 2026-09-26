from abc import ABC, abstractmethod
from typing import Optional
from alavitrace.intelligence.models import VulnQueryResult

class VulnerabilityProvider(ABC):
    """
    Abstract base class for vulnerability intelligence providers (e.g. NVD, local database).
    """

    @abstractmethod
    def search_by_cpe(self, cpe_string: str) -> VulnQueryResult:
        """
        Queries vulnerability database using an exact or formatted CPE string.
        """
        pass

    @abstractmethod
    def search_by_product_version(self, product: str, version: str) -> VulnQueryResult:
        """
        Queries vulnerability database using product and version keyword heuristic fallback.
        """
        pass
