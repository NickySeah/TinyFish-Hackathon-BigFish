-- Create the URLs table to store unique links
CREATE TABLE urls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_url TEXT UNIQUE NOT NULL,
    domain TEXT, -- Helpful for analyzing if a specific domain is frequently malicious
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create the Scans table to store the results from Tinyfish and VirusTotal
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id UUID NOT NULL REFERENCES urls(id) ON DELETE CASCADE,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL, -- Optional: Links the scan to a logged-in user
    
    -- Tinyfish Results
    tinyfish_verdict TEXT, 
    tinyfish_raw JSONB, -- Stores the full API JSON response for future reference
    
    -- VirusTotal Results
    vt_verdict TEXT,
    vt_malicious_votes INT DEFAULT 0,
    vt_total_votes INT DEFAULT 0,
    vt_raw JSONB, -- Stores the full VirusTotal API JSON response
    
    -- Collated Final Result
    final_verdict TEXT NOT NULL DEFAULT 'PENDING' CHECK (final_verdict IN ('SAFE', 'SUSPICIOUS', 'MALICIOUS', 'PENDING', 'ERROR')),
    risk_score INT CHECK (risk_score >= 0 AND risk_score <= 100), -- Optional: A calculated score from 0-100
    
    scanned_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance optimization
CREATE INDEX idx_urls_original_url ON urls(original_url);
CREATE INDEX idx_scans_url_id ON scans(url_id);
CREATE INDEX idx_scans_scanned_at ON scans(scanned_at DESC);