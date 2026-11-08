{% test between(model, column_name, min_value, max_value) %}
select {{ column_name }}
from {{ model }}
where {{ column_name }} is not null
  and ({{ column_name }} < {{ min_value }} or {{ column_name }} > {{ max_value }})
{% endtest %}


{% test matches_pattern(model, column_name, pattern) %}
select {{ column_name }}
from {{ model }}
where {{ column_name }} is not null
  and not {{ regex_match(column_name, pattern) }}
{% endtest %}


{# Grain test without building a string key: cheap even on tens of millions of rows. #}
{% test unique_combination(model, combination_of_columns) %}
select {{ combination_of_columns | join(', ') }}
from {{ model }}
group by {{ combination_of_columns | join(', ') }}
having count(*) > 1
{% endtest %}
