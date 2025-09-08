"""Base scanner interface"""

from abc import ABC, abstractmethod
from typing import Dict

class BaseScanner(ABC):
    """Base class for all security scanners"""
    
    @abstractmethod
    async def scan(self, target_url: str, options: Dict = None) -> Dict:
        """Execute scan and return raw results"""
        pass
    
    @abstractmethod
    async def parse_results(self, raw_results: Dict) -> Dict:
        """Parse raw results into standardized format"""
        pass