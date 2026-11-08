-- One row per CVE: the latest version seen across all NVD batches.
-- Grain: cve_id
--
-- Dedup is done on narrow key columns first, then joined back to the raw rows, so the
-- multi-KB JSON payloads are never sorted (sorting 420K+ payloads is what blows up memory).

with ranked as (

    select
        cve_id,
        _source_file,
        row_number() over (
            partition by cve_id
            order by cast(last_modified as timestamp) desc, _ingested_at desc, _source_file desc
        ) as rn
    from {{ source('raw', 'nvd_cves') }}

),

latest as (

    select src.*
    from {{ source('raw', 'nvd_cves') }} as src
    inner join ranked
        on  ranked.cve_id = src.cve_id
        and ranked._source_file = src._source_file
    where ranked.rn = 1

)

select
    cve_id,
    cast(published as timestamp)                                  as published_at,
    cast(last_modified as timestamp)                              as last_modified_at,
    vuln_status,
    vuln_status = 'Rejected'                                      as is_rejected,
    {{ json_str('payload', '$.sourceIdentifier') }}               as source_identifier,

    case
        when {{ json_str('payload', '$.descriptions[0].lang') }} = 'en'
            then {{ json_str('payload', '$.descriptions[0].value') }}
        else {{ json_str('payload', '$.descriptions[1].value') }}
    end                                                           as description,

    -- CVSS v3.1 (NVD "Primary" score preferred over the CNA's "Secondary")
    cast({{ cvss31('cvssData.baseScore') }} as {{ type_double() }}) as cvss3_base_score,
    {{ cvss31('cvssData.baseSeverity') }}                         as cvss3_severity,
    {{ cvss31('cvssData.vectorString') }}                         as cvss3_vector,
    {{ cvss31('cvssData.attackVector') }}                         as cvss3_attack_vector,
    {{ cvss31('type') }}                                          as cvss3_score_type,
    {{ cvss31('source') }}                                        as cvss3_score_source,
    cast({{ cvss31('exploitabilityScore') }} as {{ type_double() }}) as cvss3_exploitability_score,
    cast({{ cvss31('impactScore') }} as {{ type_double() }})      as cvss3_impact_score,

    {{ json_str('payload', '$.weaknesses[0].description[0].value') }} as primary_cwe,

    _batch_id,
    {{ ingested_ts() }}                                           as ingested_at

from latest
