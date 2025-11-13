# Path: utils/pdf_generator.py

"""
PDF report generation utility
"""
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, 
    Table, TableStyle, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
from io import BytesIO
from typing import List, Dict, Any
import plotly.graph_objects as go


class PDFReportGenerator:
    """Generate PDF reports with charts and statistics"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f77b4'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        self.normal_style = ParagraphStyle(
            'CustomNormal',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=12
        )
    
    def _fig_to_image(self, fig: go.Figure, width: int = 600, height: int = 400) -> BytesIO:
        """Convert Plotly figure to image bytes"""
        img_bytes = fig.to_image(format="png", width=width, height=height)
        return BytesIO(img_bytes)
    
    def generate_report(
        self, 
        statistics: Dict[str, Any],
        charts: Dict[str, go.Figure],
        date_range: Dict[str, str],
        output_path: str
    ):
        """
        Generate a complete PDF report
        
        Args:
            statistics: Statistics data
            charts: Dictionary of Plotly figures
            date_range: Date range information
            output_path: Path to save the PDF
        """
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        
        # Title
        title = Paragraph(
            "Phishing URL Analysis Report",
            self.title_style
        )
        story.append(title)
        story.append(Spacer(1, 0.3*inch))
        
        # Date Range
        date_info = Paragraph(
            f"<b>Report Period:</b> {date_range['start']} to {date_range['end']}<br/>"
            f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.normal_style
        )
        story.append(date_info)
        story.append(Spacer(1, 0.3*inch))
        
        # Summary Statistics
        story.append(Paragraph("Executive Summary", self.heading_style))
        
        summary_data = [
            ['Metric', 'Value'],
            ['Total Analyses', str(statistics.get('total_analyses', 0))],
            ['Phishing Detected', str(statistics.get('phishing_detected', 0))],
            ['Safe URLs', str(statistics.get('safe_urls', 0))],
            ['Phishing Rate', f"{statistics.get('phishing_percentage', 0)}%"],
            ['Average Risk Score', str(statistics.get('avg_risk_score', 0))]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.4*inch))
        
        # Add Charts
        chart_sections = [
            ('risk_distribution', 'Risk Distribution'),
            ('confidence_distribution', 'Confidence Level Distribution'),
            ('phishing_pie', 'Phishing Detection Overview'),
            ('sources_usage', 'Analysis Sources Usage')
        ]
        
        for chart_key, chart_title in chart_sections:
            if chart_key in charts:
                story.append(PageBreak())
                story.append(Paragraph(chart_title, self.heading_style))
                story.append(Spacer(1, 0.2*inch))
                
                # Convert figure to image
                img_buffer = self._fig_to_image(charts[chart_key], width=700, height=450)
                img = Image(img_buffer, width=6*inch, height=3.86*inch)
                story.append(img)
                story.append(Spacer(1, 0.3*inch))
        
        # Build PDF
        doc.build(story)
        
        return output_path