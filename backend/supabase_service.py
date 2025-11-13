# Path: backend/supabase_service.py

"""
Supabase service for database operations
"""
from supabase import create_client, Client
from typing import List, Dict, Any, Optional
from datetime import datetime
from backend.config import get_settings


class SupabaseService:
    """Service for interacting with Supabase database"""
    
    def __init__(self):
        settings = get_settings()
        self.client: Client = create_client(
            settings.supabase_url,
            settings.supabase_key
        )
    
    def get_analyses_by_date_range(
        self, 
        start_date: datetime, 
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """
        Get all analysis results within a date range
        
        Args:
            start_date: Start date for filtering
            end_date: End date for filtering
            
        Returns:
            List of analysis results
        """
        try:
            response = self.client.table('analysis_results').select(
                '*'
            ).gte(
                'analysis_date', start_date.isoformat()
            ).lte(
                'analysis_date', end_date.isoformat()
            ).order('analysis_date', desc=True).execute()
            
            return response.data if response.data else []
        except Exception as e:
            print(f"Error fetching analyses: {e}")
            return []
    
    def get_all_analyses(self) -> List[Dict[str, Any]]:
        """Get all analysis results"""
        try:
            response = self.client.table('analysis_results').select(
                '*'
            ).order('analysis_date', desc=True).execute()
            
            return response.data if response.data else []
        except Exception as e:
            print(f"Error fetching all analyses: {e}")
            return []
    
    def get_statistics(
        self, 
        start_date: Optional[datetime] = None, 
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get statistics for analyses
        
        Args:
            start_date: Optional start date for filtering
            end_date: Optional end date for filtering
            
        Returns:
            Dictionary with statistics
        """
        if start_date and end_date:
            data = self.get_analyses_by_date_range(start_date, end_date)
        else:
            data = self.get_all_analyses()
        
        if not data:
            return {
                'total_analyses': 0,
                'phishing_detected': 0,
                'safe_urls': 0,
                'avg_risk_score': 0.0,
                'phishing_percentage': 0.0,
                'risk_distribution': {
                    'low': 0,
                    'medium': 0,
                    'high': 0
                }
            }
        
        total = len(data)
        phishing = sum(1 for item in data if item.get('is_phishing', False))
        safe = total - phishing
        
        risk_scores = [item.get('risk_score', 0) for item in data]
        avg_risk = sum(risk_scores) / total if total > 0 else 0.0
        
        # Risk distribution
        low_risk = sum(1 for score in risk_scores if score < 40)
        medium_risk = sum(1 for score in risk_scores if 40 <= score < 70)
        high_risk = sum(1 for score in risk_scores if score >= 70)
        
        return {
            'total_analyses': total,
            'phishing_detected': phishing,
            'safe_urls': safe,
            'avg_risk_score': round(avg_risk, 2),
            'phishing_percentage': round((phishing / total * 100), 2) if total > 0 else 0.0,
            'risk_distribution': {
                'low': low_risk,
                'medium': medium_risk,
                'high': high_risk
            }
        }
    
    def get_confidence_distribution(
        self, 
        start_date: Optional[datetime] = None, 
        end_date: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get distribution of confidence levels"""
        if start_date and end_date:
            data = self.get_analyses_by_date_range(start_date, end_date)
        else:
            data = self.get_all_analyses()
        
        if not data:
            return {'low': 0, 'medium': 0, 'high': 0}
        
        distribution = {'low': 0, 'medium': 0, 'high': 0}
        for item in data:
            confidence = item.get('confidence_level', 'low')
            if confidence in distribution:
                distribution[confidence] += 1
        
        return distribution
    
    def get_sources_usage(
        self, 
        start_date: Optional[datetime] = None, 
        end_date: Optional[datetime] = None
    ) -> Dict[str, int]:
        """Get usage statistics of different analysis sources"""
        if start_date and end_date:
            data = self.get_analyses_by_date_range(start_date, end_date)
        else:
            data = self.get_all_analyses()
        
        if not data:
            return {}
        
        sources_count = {}
        for item in data:
            sources = item.get('sources_checked', '')
            if sources:
                # Parse sources (handle both string and array formats)
                if isinstance(sources, str):
                    source_list = [s.strip() for s in sources.split(',')]
                else:
                    source_list = sources
                
                for source in source_list:
                    sources_count[source] = sources_count.get(source, 0) + 1
        
        return sources_count
    
    def get_daily_analysis_count(
        self, 
        start_date: datetime, 
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """Get daily count of analyses"""
        data = self.get_analyses_by_date_range(start_date, end_date)
        
        if not data:
            return []
        
        # Group by date
        daily_counts = {}
        for item in data:
            date_str = item.get('analysis_date', '')
            if date_str:
                date_only = date_str.split('T')[0]
                daily_counts[date_only] = daily_counts.get(date_only, 0) + 1
        
        # Convert to list
        result = [
            {'date': date, 'count': count} 
            for date, count in sorted(daily_counts.items())
        ]
        
        return result