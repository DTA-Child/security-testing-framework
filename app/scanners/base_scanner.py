from abc import ABC, abstractmethod
from typing import Dict, Optional

class BaseScanner(ABC):
    """Abstract base class for all security scanners"""
    
    @abstractmethod
    async def scan(self, target_url: str, options: Dict = None) -> Dict:
        """Execute security scan on target URL
        
        Args:
            target_url: URL to scan
            options: Additional scan options
            
        Returns:
            Raw scan results dictionary
        """
        pass
    
    @abstractmethod
    async def parse_results(self, raw_results: Dict) -> Dict:
        """Parse raw scan results into standardized format
        
        Args:
            raw_results: Raw results from scanner
            
        Returns:
            Parsed and standardized results
        """
        pass
    
    def get_scanner_info(self) -> Dict:
        """Get information about this scanner"""
        return {
            'name': self.__class__.__name__,
            'version': getattr(self, 'version', 'unknown'),
            'description': getattr(self, 'description', 'Security scanner')
        }