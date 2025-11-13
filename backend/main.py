# Path: backend/main.py

"""
FastAPI main application
"""
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta, time
from typing import Optional

from backend.models import (
    URLAnalysisRequest,
    BulkURLAnalysisRequest,
    BulkAnalysisResponse,
    StatisticsResponse
)
from backend.supabase_service import SupabaseService
from backend.analysis_service import AnalysisService

app = FastAPI(
    title="Phishing URL Analytics API",
    description="API for analyzing URLs and getting phishing statistics",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Services
supabase_service = SupabaseService()
analysis_service = AnalysisService()


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Phishing URL Analytics API",
        "version": "1.0.0",
        "endpoints": {
            "analyze": "/api/analyze",
            "bulk_analyze": "/api/analyze/bulk",
            "statistics": "/api/statistics",
            "analyses": "/api/analyses"
        }
    }


@app.post("/api/analyze")
async def analyze_url(request: URLAnalysisRequest):
    """
    Analyze a single URL
    
    Args:
        request: URL analysis request
        
    Returns:
        Analysis result
    """
    try:
        result = await analysis_service.analyze_single_url(str(request.url))
        
        if result['status'] == 'error':
            raise HTTPException(status_code=500, detail=result['error'])
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze/bulk", response_model=BulkAnalysisResponse)
async def analyze_bulk_urls(request: BulkURLAnalysisRequest):
    """
    Analyze multiple URLs sequentially
    
    Args:
        request: Bulk URL analysis request
        
    Returns:
        Bulk analysis results
    """
    try:
        result = await analysis_service.analyze_bulk_urls(request.urls)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/statistics")
async def get_statistics(
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)")
):
    """Get analysis statistics"""
    try:
        start = datetime.fromisoformat(start_date) if start_date else None
        end = datetime.fromisoformat(end_date) if end_date else None
        
        # Ajustar end_date para incluir todo el día
        if end:
            from datetime import time
            end = datetime.combine(end.date(), time(23, 59, 59))
        
        stats = supabase_service.get_statistics(start, end)
        confidence_dist = supabase_service.get_confidence_distribution(start, end)
        sources_usage = supabase_service.get_sources_usage(start, end)
        
        return {
            **stats,
            'confidence_distribution': confidence_dist,
            'sources_usage': sources_usage
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid date format: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analyses")
async def get_analyses(
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)")
):
    """Get all analysis results"""
    try:
        if start_date and end_date:
            start = datetime.fromisoformat(start_date)
            end = datetime.fromisoformat(end_date)
            
            # Ajustar end_date para incluir todo el día
            from datetime import time
            end = datetime.combine(end.date(), time(23, 59, 59))
            
            data = supabase_service.get_analyses_by_date_range(start, end)
        else:
            data = supabase_service.get_all_analyses()
        
        return {
            'total': len(data),
            'data': data
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid date format: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/daily-counts")
async def get_daily_counts(
    start_date: str = Query(..., description="Start date (ISO format)"),
    end_date: str = Query(..., description="End date (ISO format)")
):
    """Get daily analysis counts"""
    try:
        start = datetime.fromisoformat(start_date)
        end = datetime.fromisoformat(end_date)
        
        # Ajustar end_date para incluir todo el día
        from datetime import time
        end = datetime.combine(end.date(), time(23, 59, 59))
        
        daily_counts = supabase_service.get_daily_analysis_count(start, end)
        
        return {
            'data': daily_counts
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid date format: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    from backend.config import get_settings
    
    settings = get_settings()
    uvicorn.run(
        "backend.main:app",
        host=settings.backend_host,
        port=settings.backend_port,
        reload=True
    )