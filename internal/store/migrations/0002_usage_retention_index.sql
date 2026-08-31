-- 0002_usage_retention_index.sql — index supporting the fixed usage retention
-- cleanup that purges old usage_counters rows by hour_bucket.

CREATE INDEX IF NOT EXISTS idx_usage_counters_hour ON usage_counters(hour_bucket);
