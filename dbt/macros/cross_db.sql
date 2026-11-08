{#
  The same models run on DuckDB (local/CI) and BigQuery (cloud).
  Only the few functions that differ between the two engines are wrapped here.
#}

{# Use "staging" as-is on DuckDB; prefix with the dataset on BigQuery (vulnintel_staging). #}
{% macro generate_schema_name(custom_schema_name, node) -%}
  {%- if custom_schema_name is none -%}
    {{ target.schema }}
  {%- elif target.type == 'bigquery' -%}
    {{ target.schema }}_{{ custom_schema_name | trim }}
  {%- else -%}
    {{ custom_schema_name | trim }}
  {%- endif -%}
{%- endmacro %}


{# Extract a scalar from a JSON string as text. #}
{% macro json_str(column, path) -%}
  {{ return(adapter.dispatch('json_str', 'vulnintel')(column, path)) }}
{%- endmacro %}

{% macro default__json_str(column, path) -%}
  json_extract_string({{ column }}, '{{ path }}')
{%- endmacro %}

{% macro bigquery__json_str(column, path) -%}
  json_value({{ column }}, '{{ path }}')
{%- endmacro %}


{# Regex match, returns boolean. #}
{% macro regex_match(expr, pattern) -%}
  {{ return(adapter.dispatch('regex_match', 'vulnintel')(expr, pattern)) }}
{%- endmacro %}

{% macro default__regex_match(expr, pattern) -%}
  regexp_full_match({{ expr }}, '{{ pattern }}')
{%- endmacro %}

{% macro bigquery__regex_match(expr, pattern) -%}
  regexp_contains({{ expr }}, r'^(?:{{ pattern }})$')
{%- endmacro %}


{# Source freshness: _ingested_at is an ISO-8601 string with a UTC offset. #}
{% macro ingested_ts(column='_ingested_at') -%}
  {{ return(adapter.dispatch('ingested_ts', 'vulnintel')(column)) }}
{%- endmacro %}

{% macro default__ingested_ts(column) -%}
  cast(cast({{ column }} as timestamptz) as timestamp)
{%- endmacro %}

{% macro bigquery__ingested_ts(column) -%}
  cast({{ column }} as timestamp)
{%- endmacro %}


{#
  NVD can list several CVSS v3.1 scores: NVD's own ("Primary") and the CNA's ("Secondary"),
  in either order. Prefer Primary; fall back to whatever is first.
  Handles the first two entries, which covers NVD in practice; week 2 replaces this with
  a proper unnest into an int_ model.
#}
{% macro cvss31(field) -%}
  case
    when {{ json_str('payload', '$.metrics.cvssMetricV31[1].type') }} = 'Primary'
     and coalesce({{ json_str('payload', '$.metrics.cvssMetricV31[0].type') }}, '') <> 'Primary'
    then {{ json_str('payload', '$.metrics.cvssMetricV31[1].' ~ field) }}
    else {{ json_str('payload', '$.metrics.cvssMetricV31[0].' ~ field) }}
  end
{%- endmacro %}


{# 64-bit float. dbt.type_float() is 32-bit on DuckDB and turns 9.8 into 9.800000190734863. #}
{% macro type_double() -%}
  {{ return(adapter.dispatch('type_double', 'vulnintel')()) }}
{%- endmacro %}

{% macro default__type_double() -%}double{%- endmacro %}

{% macro bigquery__type_double() -%}float64{%- endmacro %}
