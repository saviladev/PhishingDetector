# Path: backend/analysis_service.py

"""
Analysis service for sending URLs to n8n webhook
"""
import httpx
from typing import List, Dict, Any
from backend.config import get_settings


class AnalysisService:
    """Service for analyzing URLs via n8n webhook"""
    
    def __init__(self):
        settings = get_settings()
        self.webhook_url = settings.n8n_webhook_url
        self.timeout = 60.0  # 60 seconds timeout per request
    
    async def analyze_single_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a single URL
        
        Args:
            url: URL to analyze
            
        Returns:
            Analysis result or error
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.webhook_url,
                    json={"url": url}
                )
                
                if response.status_code == 200:
                    return {
                        'url': url,
                        'status': 'success',
                        'data': response.json()
                    }
                else:
                    return {
                        'url': url,
                        'status': 'error',
                        'error': f"HTTP {response.status_code}: {response.text}"
                    }
        except httpx.TimeoutException:
            return {
                'url': url,
                'status': 'error',
                'error': 'Request timeout (>60s)'
            }
        except Exception as e:
            return {
                'url': url,
                'status': 'error',
                'error': str(e)
            }
    
    async def analyze_bulk_urls(self, urls: List[str]) -> Dict[str, Any]:
        """
        Analyze multiple URLs sequentially
        
        Args:
            urls: List of URLs to analyze
            
        Returns:
            Bulk analysis results
        """
        results = []
        successful = 0
        failed = 0
        
        for url in urls:
            result = await self.analyze_single_url(url)
            results.append(result)
            
            if result['status'] == 'success':
                successful += 1
            else:
                failed += 1
        
        return {
            'total_urls': len(urls),
            'successful': successful,
            'failed': failed,
            'results': results
        }