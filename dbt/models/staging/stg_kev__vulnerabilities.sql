-- One row per KEV entry per daily snapshot.
-- Grain: snapshot_date, cve_id
-- Keeping every snapshot lets week 2 detect additions, edits and removals over time.

with source as (

    select * from {{ source('raw', 'kev_snapshots') }}

),

deduped as (

    select *
    from source
    where true
    qualify row_number() over (
        partition by snapshot_date, cve_id
        order by _ingested_at desc
    ) = 1

)

select
    cast(snapshot_date as {{ dbt.type_string() }}) || '|' || cve_id as kev_snapshot_id,
    cast(snapshot_date as date)                                     as snapshot_date,
    cve_id,
    {{ json_str('payload', '$.vendorProject') }}                    as vendor_project,
    {{ json_str('payload', '$.product') }}                          as product,
    {{ json_str('payload', '$.vulnerabilityName') }}                as vulnerability_name,
    cast({{ json_str('payload', '$.dateAdded') }} as date)          as date_added,
    cast({{ json_str('payload', '$.dueDate') }} as date)            as due_date,
    {{ json_str('payload', '$.knownRansomwareCampaignUse') }}       as known_ransomware_campaign_use,
    {{ json_str('payload', '$.knownRansomwareCampaignUse') }} = 'Known' as is_ransomware_linked,
    {{ json_str('payload', '$.requiredAction') }}                   as required_action,
    catalog_version,
    _batch_id,
    {{ ingested_ts() }}                                             as ingested_at

from deduped
