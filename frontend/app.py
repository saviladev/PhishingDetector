# Path: frontend/app.py

"""
Streamlit Frontend Application
"""
import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta
from io import BytesIO
import os
import sys
import tempfile
import time

# Add project root to Python path
import pathlib
project_root = pathlib.Path(__file__).parent.parent.absolute()
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Now import from utils
try:
    from utils.chart_generator import ChartGenerator
    from utils.pdf_generator import PDFReportGenerator
except ModuleNotFoundError as e:
    st.error(f"Error importing modules: {e}")
    st.error(f"Python path: {sys.path}")
    st.error(f"Project root: {project_root}")
    st.stop()

# Page configuration
st.set_page_config(
    page_title="Phishing URL Analytics",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

# Initialize chart generator
chart_gen = ChartGenerator()


def fetch_statistics(start_date: str = None, end_date: str = None):
    """Fetch statistics from API"""
    params = {}
    if start_date:
        params['start_date'] = start_date
    if end_date:
        params['end_date'] = end_date
    
    try:
        response = requests.get(f"{API_BASE_URL}/api/statistics", params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error fetching statistics: {e}")
        return None


def fetch_analyses(start_date: str = None, end_date: str = None):
    """Fetch analysis results from API"""
    params = {}
    if start_date:
        params['start_date'] = start_date
    if end_date:
        params['end_date'] = end_date
    
    try:
        response = requests.get(f"{API_BASE_URL}/api/analyses", params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error fetching analyses: {e}")
        return None


def fetch_daily_counts(start_date: str, end_date: str):
    """Fetch daily analysis counts"""
    params = {
        'start_date': start_date,
        'end_date': end_date
    }
    
    try:
        response = requests.get(f"{API_BASE_URL}/api/daily-counts", params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error fetching daily counts: {e}")
        return None


def analyze_bulk_urls(urls: list):
    """Send bulk URLs for analysis"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/api/analyze/bulk",
            json={"urls": urls},
            timeout=300
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error analyzing URLs: {e}")
        return None


def display_analysis_results(result):
    """Display analysis results in cards"""
    st.markdown("---")
    st.subheader("🎯 Resultados del Análisis")
    
    # Resumen
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total URLs", result['total_urls'])
    with col2:
        st.metric("✅ Exitosos", result['successful'])
    with col3:
        st.metric("❌ Fallidos", result['failed'])
    
    st.markdown("---")
    
    # Mostrar cada URL analizada
    for idx, item in enumerate(result['results'], 1):
        if item['status'] == 'success' and 'data' in item:
            data = item['data']
            url = item['url']
            
            # Determinar si es phishing
            is_phishing = data.get('is_phishing', False)
            risk_score = data.get('risk_score', 0)
            confidence = data.get('confidence_level', 'unknown').upper()
            
            # Color según resultado
            if is_phishing:
                border_color = "#e74c3c"
                emoji = "⚠️"
                verdict = "PHISHING DETECTADO"
            else:
                border_color = "#2ecc71"
                emoji = "✅"
                verdict = "URL SEGURA"
            
            # Card de resultado
            st.markdown(f"""
            <div style="
                border-left: 5px solid {border_color};
                padding: 15px;
                margin: 10px 0;
                background-color: rgba(255,255,255,0.05);
                border-radius: 5px;
            ">
                <h4 style="margin:0; color:{border_color};">
                    {emoji} Análisis #{idx}: {verdict}
                </h4>
                <p style="margin:5px 0; font-size:14px; color:gray;">
                    <strong>URL:</strong> {url}
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            # Métricas en columnas
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric(
                    "🎯 Risk Score",
                    f"{risk_score}/100",
                    help="Score de riesgo (0=seguro, 100=muy peligroso)"
                )
            
            with col2:
                st.metric(
                    "🔍 Confidence",
                    confidence,
                    help="Nivel de confianza del análisis"
                )
            
            with col3:
                sources = data.get('sources_checked', 'N/A')
                if isinstance(sources, str):
                    source_count = len(sources.split(','))
                else:
                    source_count = len(sources) if sources else 0
                st.metric(
                    "📡 Fuentes",
                    source_count,
                    help=f"Fuentes: {sources}"
                )
            
            with col4:
                duration = data.get('analysis_duration_ms', 0)
                duration_sec = duration / 1000 if duration else 0
                st.metric(
                    "⏱️ Tiempo",
                    f"{duration_sec:.1f}s",
                    help="Tiempo de análisis"
                )
            
            # Detalles expandibles
            with st.expander("🔬 Ver Detalles Técnicos"):
                col_a, col_b = st.columns(2)
                
                with col_a:
                    st.markdown("**VirusTotal:**")
                    vt = data.get('virustotal_result')
                    if vt and isinstance(vt, dict):
                        st.json(vt)
                    else:
                        st.text(vt if vt else "No disponible")
                
                with col_b:
                    st.markdown("**Heurísticas:**")
                    heur = data.get('heuristic_result')
                    if heur and isinstance(heur, dict):
                        st.json(heur)
                    else:
                        st.text(heur if heur else "No disponible")
            
            st.markdown("---")
        
        elif item['status'] == 'error':
            # Card de error
            url = item['url']
            error = item.get('error', 'Error desconocido')
            
            st.markdown(f"""
            <div style="
                border-left: 5px solid #95a5a6;
                padding: 15px;
                margin: 10px 0;
                background-color: rgba(255,255,255,0.05);
                border-radius: 5px;
            ">
                <h4 style="margin:0; color:#95a5a6;">
                    ❌ Análisis #{idx}: ERROR
                </h4>
                <p style="margin:5px 0; font-size:14px; color:gray;">
                    <strong>URL:</strong> {url}
                </p>
                <p style="margin:5px 0; font-size:13px; color:#e74c3c;">
                    <strong>Error:</strong> {error}
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("---")


def main():
    """Main Streamlit application"""
    
    # Título
    st.title("🔒 Panel de Análisis de URLs de Phishing")
    st.markdown("---")
    
    # Barra lateral
    with st.sidebar:
        st.header("⚙️ Configuración")
        
        # Filtro por rango de fechas
        st.subheader("Filtro por Rango de Fechas")
        
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input(
                "Fecha de inicio",
                value=datetime.now() - timedelta(days=30),
                max_value=datetime.now()
            )
        with col2:
            end_date = st.date_input(
                "Fecha de fin",
                value=datetime.now(),
                max_value=datetime.now()
            )
        
        apply_filter = st.button("📊 Aplicar Filtro", use_container_width=True)
        
        st.markdown("---")
        
        # Análisis masivo de URLs
        st.subheader("🔍 Análisis Masivo de URLs")
        urls_input = st.text_area(
            "Ingrese las URLs (una por línea)",
            height=150,
            placeholder="https://ejemplo1.com\nhttps://ejemplo2.com"
        )
        
        analyze_button = st.button("🚀 Analizar URLs", use_container_width=True)
    
    # Convert dates to ISO format
    start_date_iso = start_date.isoformat()
    end_date_iso = end_date.isoformat()
    
    # Handle bulk URL analysis FIRST
    if analyze_button and urls_input.strip():
        urls = [url.strip() for url in urls_input.split('\n') if url.strip()]
        
        if urls:
            with st.spinner(f"🔄 Analizando {len(urls)} URLs..."):
                result = analyze_bulk_urls(urls)
            
            if result:
                # Mostrar resultados
                display_analysis_results(result)
                
                # Actualizar datos
                with st.spinner("🔄 Actualizando estadísticas..."):
                    time.sleep(2)  # Dar tiempo a Supabase
                    st.session_state.statistics = fetch_statistics(start_date_iso, end_date_iso)
                    st.session_state.analyses = fetch_analyses(start_date_iso, end_date_iso)
                    st.session_state.daily_counts = fetch_daily_counts(start_date_iso, end_date_iso)
                
                st.success("✅ Dashboard actualizado exitosamente")
                st.markdown("---")
                st.markdown("### 📊 Estadísticas Actualizadas")
                st.info("💡 Los gráficos abajo ya incluyen los análisis recientes")
                st.markdown("---")
            else:
                st.error("❌ Error al realizar el análisis masivo")
        else:
            st.warning("⚠️ Por favor ingresa al menos una URL")
    
    # Fetch data
    if apply_filter or 'statistics' not in st.session_state:
        with st.spinner("Cargando datos..."):
            st.session_state.statistics = fetch_statistics(start_date_iso, end_date_iso)
            st.session_state.analyses = fetch_analyses(start_date_iso, end_date_iso)
            st.session_state.daily_counts = fetch_daily_counts(start_date_iso, end_date_iso)
    
    statistics = st.session_state.get('statistics')
    analyses = st.session_state.get('analyses')
    daily_counts = st.session_state.get('daily_counts')
    
    # Check if data exists
    if not statistics or statistics.get('total_analyses', 0) == 0:
        st.warning("📭 Sin datos - No hay análisis en el rango de fechas seleccionado")
        st.info(f"📅 Rango seleccionado: {start_date_iso} a {end_date_iso}")
        return
    
    # Display metrics
    st.subheader("📈 Métricas Clave")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Análisis Totales",
            statistics.get('total_analyses', 0),
            help="Número total de URLs analizadas"
        )
    
    with col2:
        st.metric(
            "Phishing Detectado",
            statistics.get('phishing_detected', 0),
            delta=f"{statistics.get('phishing_percentage', 0)}%",
            delta_color="inverse",
            help="Número de URLs de phishing detectadas"
        )
    
    with col3:
        st.metric(
            "URLs Seguras",
            statistics.get('safe_urls', 0),
            help="Número de URLs seguras"
        )
    
    with col4:
        st.metric(
            "Puntuación de Riesgo Promedio",
            f"{statistics.get('avg_risk_score', 0):.1f}",
            help="Puntuación de riesgo promedio en todos los análisis"
        )
    
    st.markdown("---")
    
    # Charts
    st.subheader("📊 Visualizaciones")
    
    # Row 1: Risk and Confidence Distribution
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Distribución de Riesgos")
        risk_chart = chart_gen.create_risk_distribution_chart(
            statistics.get('risk_distribution', {})
        )
        st.plotly_chart(risk_chart, use_container_width=True, key="risk_dist")
        
        risk_chart_bytes = risk_chart.to_image(format="png")
        st.download_button(
            label="💾 Descargar Gráfico",
            data=risk_chart_bytes,
            file_name="distribucion_riesgos.png",
            mime="image/png",
            key="download_risk"
        )
    
    with col2:
        st.markdown("### Distribución de Confianza")
        conf_chart = chart_gen.create_confidence_distribution_chart(
            statistics.get('confidence_distribution', {})
        )
        st.plotly_chart(conf_chart, use_container_width=True, key="conf_dist")
        
        conf_chart_bytes = conf_chart.to_image(format="png")
        st.download_button(
            label="💾 Descargar Gráfico",
            data=conf_chart_bytes,
            file_name="distribucion_confianza.png",
            mime="image/png",
            key="download_conf"
        )
    
    # Row 2: Phishing Overview and Sources Usage
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Resumen de Detección de Phishing")
        phishing_chart = chart_gen.create_phishing_detection_pie(statistics)
        st.plotly_chart(phishing_chart, use_container_width=True, key="phishing_pie")
        
        phishing_chart_bytes = phishing_chart.to_image(format="png")
        st.download_button(
            label="💾 Descargar Gráfico",
            data=phishing_chart_bytes,
            file_name="resumen_phishing.png",
            mime="image/png",
            key="download_phishing"
        )
    
    with col2:
        st.markdown("### Uso de Fuentes")
        sources_chart = chart_gen.create_sources_usage_chart(
            statistics.get('sources_usage', {})
        )
        st.plotly_chart(sources_chart, use_container_width=True, key="sources_usage")
        
        sources_chart_bytes = sources_chart.to_image(format="png")
        st.download_button(
            label="💾 Descargar Gráfico",
            data=sources_chart_bytes,
            file_name="uso_fuentes.png",
            mime="image/png",
            key="download_sources"
        )
    
    # Row 3: Daily Trend
    if daily_counts and daily_counts.get('data'):
        st.markdown("### Tendencia Diaria de Análisis")
        daily_chart = chart_gen.create_daily_trend_chart(daily_counts['data'])
        st.plotly_chart(daily_chart, use_container_width=True, key="daily_trend")
        
        daily_chart_bytes = daily_chart.to_image(format="png")
        st.download_button(
            label="💾 Descargar Gráfico",
            data=daily_chart_bytes,
            file_name="tendencia_diaria.png",
            mime="image/png",
            key="download_daily"
        )
    
    # Row 4: Risk Score Histogram
    if analyses and analyses.get('data'):
        st.markdown("### Distribución de Puntuación de Riesgo (Histograma)")
        hist_chart = chart_gen.create_risk_score_histogram(analyses['data'])
        st.plotly_chart(hist_chart, use_container_width=True, key="risk_hist")
        
        hist_chart_bytes = hist_chart.to_image(format="png")
        st.download_button(
            label="💾 Descargar Gráfico",
            data=hist_chart_bytes,
            file_name="histograma_riesgo.png",
            mime="image/png",
            key="download_hist"
        )
    
    st.markdown("---")
    
    # PDF Report Generation
    st.subheader("📄 Generar Informe PDF")
    
    if st.button("🔄 Generar Informe PDF", use_container_width=True):
        with st.spinner("Generando informe PDF..."):
            try:
                charts = {
                    'risk_distribution': chart_gen.create_risk_distribution_chart(
                        statistics.get('risk_distribution', {})
                    ),
                    'confidence_distribution': chart_gen.create_confidence_distribution_chart(
                        statistics.get('confidence_distribution', {})
                    ),
                    'phishing_pie': chart_gen.create_phishing_detection_pie(statistics),
                    'sources_usage': chart_gen.create_sources_usage_chart(
                        statistics.get('sources_usage', {})
                    )
                }
                
                pdf_gen = PDFReportGenerator()
                output_path = os.path.join(tempfile.gettempdir(), "phishing_report.pdf")
                
                pdf_gen.generate_report(
                    statistics=statistics,
                    charts=charts,
                    date_range={
                        'start': start_date_iso,
                        'end': end_date_iso
                    },
                    output_path=output_path
                )
                
                with open(output_path, "rb") as pdf_file:
                    st.download_button(
                        label="📥 Descargar Informe PDF",
                        data=pdf_file,
                        file_name=f"informe_phishing_{start_date_iso}_a_{end_date_iso}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                
                st.success("✅ ¡Informe PDF generado exitosamente!")
                
            except Exception as e:
                st.error(f"Error al generar el PDF: {e}")
    
    # Data Table
    if analyses and analyses.get('data'):
        st.markdown("---")
        st.subheader("📋 Análisis Recientes")
        
        df = pd.DataFrame(analyses['data'])
        
        display_columns = [
            'analysis_date', 'is_phishing', 'risk_score', 
            'confidence_level', 'sources_checked'
        ]
        
        display_columns = [col for col in display_columns if col in df.columns]
        
        st.dataframe(
            df[display_columns].head(50),
            use_container_width=True,
            height=400
        )


if __name__ == "__main__":
    main()