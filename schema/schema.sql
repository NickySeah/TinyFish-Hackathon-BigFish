-- Create the Scans table to store the results from Tinyfish and VirusTotal
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    expiry_date TIMESTAMPTZ NOT NULL,
    openai_raw JSONB,
    vt_raw JSONB,
    scanned_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create a table to store URL sources
CREATE TABLE url_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    url TEXT NOT NULL,
    source_type TEXT NOT NULL, -- e.g. 'EMAIL', 'SMS', 'WEB', etc.
    source TEXT, -- Nullable field (no NOT NULL constraint)

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Optional: Indexes for performance
CREATE INDEX idx_url_sources_url ON url_sources(url);
CREATE INDEX idx_url_sources_source_type ON url_sources(source_type);

-- Indexes for performance optimization
CREATE INDEX idx_scans_url ON scans(url);
CREATE INDEX idx_scans_scanned_at ON scans(scanned_at DESC);

