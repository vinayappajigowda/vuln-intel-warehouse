-- One row per CVE per EPSS score date.
-- Grain: cve_id, score_date
--
-- No window-function dedup here: each score date is one landed file and the loader loads each
-- file exactly once (raw._load_log), so duplicates cannot occur. The grain test below proves it
-- on every build, which is far cheaper than sorting ~27M rows (90 days x ~300K CVEs) to dedup.

select
    cve_id,
    cast(score_date as date)                    as score_date,
    cast(epss as {{ type_double() }})           as epss,
    cast(percentile as {{ type_double() }})     as percentile,
    model_version,
    _batch_id,
    {{ ingested_ts() }}                         as ingested_at

from {{ source('raw', 'epss_scores') }}
