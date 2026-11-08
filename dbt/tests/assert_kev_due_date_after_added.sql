-- CISA sets a remediation due date after the date an entry is added. Anything else is bad data.
select *
from {{ ref('stg_kev__vulnerabilities') }}
where due_date < date_added
