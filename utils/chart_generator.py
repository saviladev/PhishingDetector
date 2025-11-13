# Path: utils/chart_generator.py

"""
Chart generation utilities using Plotly
"""
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, Any, List


class ChartGenerator:
    """Generate various charts for phishing analysis visualization"""
    
    @staticmethod
    def create_risk_distribution_chart(risk_dist: Dict[str, int]) -> go.Figure:
        """Create bar chart for risk distribution"""
        categories = ['Low Risk', 'Medium Risk', 'High Risk']
        values = [
            risk_dist.get('low', 0),
            risk_dist.get('medium', 0),
            risk_dist.get('high', 0)
        ]
        colors_map = ['#2ecc71', '#f39c12', '#e74c3c']
        
        fig = go.Figure(data=[
            go.Bar(
                x=categories,
                y=values,
                marker_color=colors_map,
                text=values,
                textposition='auto',
            )
        ])
        
        fig.update_layout(
            title='Risk Score Distribution',
            xaxis_title='Risk Category',
            yaxis_title='Number of URLs',
            template='plotly_white',
            height=400
        )
        
        return fig
    
    @staticmethod
    def create_confidence_distribution_chart(conf_dist: Dict[str, int]) -> go.Figure:
        """Create pie chart for confidence distribution"""
        labels = ['Low', 'Medium', 'High']
        values = [
            conf_dist.get('low', 0),
            conf_dist.get('medium', 0),
            conf_dist.get('high', 0)
        ]
        colors_map = ['#e74c3c', '#f39c12', '#2ecc71']
        
        fig = go.Figure(data=[
            go.Pie(
                labels=labels,
                values=values,
                marker=dict(colors=colors_map),
                hole=0.3
            )
        ])
        
        fig.update_layout(
            title='Confidence Level Distribution',
            template='plotly_white',
            height=400
        )
        
        return fig
    
    @staticmethod
    def create_phishing_detection_pie(stats: Dict[str, Any]) -> go.Figure:
        """Create pie chart for phishing vs safe URLs"""
        labels = ['Phishing', 'Safe']
        values = [
            stats.get('phishing_detected', 0),
            stats.get('safe_urls', 0)
        ]
        colors_map = ['#e74c3c', '#2ecc71']
        
        fig = go.Figure(data=[
            go.Pie(
                labels=labels,
                values=values,
                marker=dict(colors=colors_map),
                textinfo='label+percent+value'
            )
        ])
        
        fig.update_layout(
            title='Phishing Detection Overview',
            template='plotly_white',
            height=400
        )
        
        return fig
    
    @staticmethod
    def create_sources_usage_chart(sources: Dict[str, int]) -> go.Figure:
        """Create bar chart for sources usage"""
        if not sources:
            # Return empty chart
            fig = go.Figure()
            fig.add_annotation(
                text="No data available",
                xref="paper",
                yref="paper",
                x=0.5,
                y=0.5,
                showarrow=False,
                font=dict(size=20, color="gray")
            )
            fig.update_layout(
                title='Analysis Sources Usage',
                template='plotly_white',
                height=400
            )
            return fig
        
        source_names = list(sources.keys())
        source_counts = list(sources.values())
        
        fig = go.Figure(data=[
            go.Bar(
                x=source_names,
                y=source_counts,
                marker_color='#3498db',
                text=source_counts,
                textposition='auto',
            )
        ])
        
        fig.update_layout(
            title='Analysis Sources Usage',
            xaxis_title='Source',
            yaxis_title='Usage Count',
            template='plotly_white',
            height=400
        )
        
        return fig
    
    @staticmethod
    def create_daily_trend_chart(daily_data: List[Dict[str, Any]]) -> go.Figure:
        """Create line chart for daily analysis trends"""
        if not daily_data:
            # Return empty chart
            fig = go.Figure()
            fig.add_annotation(
                text="No data available",
                xref="paper",
                yref="paper",
                x=0.5,
                y=0.5,
                showarrow=False,
                font=dict(size=20, color="gray")
            )
            fig.update_layout(
                title='Daily Analysis Trend',
                template='plotly_white',
                height=400
            )
            return fig
        
        dates = [item['date'] for item in daily_data]
        counts = [item['count'] for item in daily_data]
        
        fig = go.Figure(data=[
            go.Scatter(
                x=dates,
                y=counts,
                mode='lines+markers',
                line=dict(color='#3498db', width=2),
                marker=dict(size=8),
                fill='tozeroy',
                fillcolor='rgba(52, 152, 219, 0.2)'
            )
        ])
        
        fig.update_layout(
            title='Daily Analysis Trend',
            xaxis_title='Date',
            yaxis_title='Number of Analyses',
            template='plotly_white',
            height=400,
            hovermode='x unified'
        )
        
        return fig
    
    @staticmethod
    def create_risk_score_histogram(analyses: List[Dict[str, Any]]) -> go.Figure:
        """Create histogram of risk scores"""
        if not analyses:
            # Return empty chart
            fig = go.Figure()
            fig.add_annotation(
                text="No data available",
                xref="paper",
                yref="paper",
                x=0.5,
                y=0.5,
                showarrow=False,
                font=dict(size=20, color="gray")
            )
            fig.update_layout(
                title='Risk Score Distribution',
                template='plotly_white',
                height=400
            )
            return fig
        
        risk_scores = [item.get('risk_score', 0) for item in analyses]
        
        fig = go.Figure(data=[
            go.Histogram(
                x=risk_scores,
                nbinsx=20,
                marker_color='#9b59b6',
                opacity=0.75
            )
        ])
        
        fig.update_layout(
            title='Risk Score Distribution (Histogram)',
            xaxis_title='Risk Score',
            yaxis_title='Frequency',
            template='plotly_white',
            height=400
        )
        
        return fig