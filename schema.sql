-- Tabla de URLs
CREATE TABLE IF NOT EXISTS public.urls (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  url text NOT NULL UNIQUE,
  domain text NOT NULL,
  submitted_at timestamp with time zone DEFAULT now(),
  source text DEFAULT 'manual'::text,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  url_hash text DEFAULT md5(url),
  CONSTRAINT urls_pkey PRIMARY KEY (id)
);

-- Índices básicos para urls
CREATE INDEX IF NOT EXISTS idx_urls_domain ON public.urls(domain);
CREATE INDEX IF NOT EXISTS idx_urls_submitted_at ON public.urls(submitted_at DESC);


-- Tabla de resultados de análisis
CREATE TABLE IF NOT EXISTS public.analysis_results (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  url_id uuid NOT NULL,
  analysis_date timestamp with time zone DEFAULT now(),
  is_phishing boolean NOT NULL,
  risk_score integer NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
  confidence_level text NOT NULL CHECK (confidence_level = ANY (ARRAY['high'::text, 'medium'::text, 'low'::text])),
  virustotal_result jsonb,
  heuristic_result jsonb,
  analysis_duration_ms integer,
  sources_checked text[],
  error_log text,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT analysis_results_pkey PRIMARY KEY (id),
  CONSTRAINT analysis_results_url_id_fkey FOREIGN KEY (url_id) 
    REFERENCES public.urls(id) ON DELETE CASCADE
);

-- Índices básicos para analysis_results
CREATE INDEX IF NOT EXISTS idx_analysis_results_url_id ON public.analysis_results(url_id);
CREATE INDEX IF NOT EXISTS idx_analysis_results_analysis_date ON public.analysis_results(analysis_date DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_results_is_phishing ON public.analysis_results(is_phishing);