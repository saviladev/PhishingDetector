# Path: backend/models.py

"""
Pydantic models for request/response validation
"""
from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class URLAnalysisRequest(BaseModel):
    """Single URL analysis request"""
    url: HttpUrl
    url_id: Optional[str] = None


class BulkURLAnalysisRequest(BaseModel):
    """Bulk URL analysis request"""
    urls: List[str] = Field(..., min_items=1, max_items=100)


class AnalysisResult(BaseModel):
    """Analysis result from n8n workflow"""
    url: str
    is_phishing: bool
    risk_score: int
    confidence_level: str
    analysis_date: str
    sources_checked: str
    error_log: Optional[str] = None


class BulkAnalysisResponse(BaseModel):
    """Response for bulk analysis"""
    total_urls: int
    successful: int
    failed: int
    results: List[Dict[str, Any]]


class StatisticsResponse(BaseModel):
    """Statistics response"""
    total_analyses: int
    phishing_detected: int
    safe_urls: int
    avg_risk_score: float
    date_range: Dict[str, str]


class DateRangeRequest(BaseModel):
    """Date range filter request"""
    start_date: datetime
    end_date: datetime