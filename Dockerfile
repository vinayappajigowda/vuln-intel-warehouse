FROM apache/airflow:3.4.0-python3.12

# project code lives at /opt/project (mounted in docker-compose for live editing)
COPY --chown=airflow:root pyproject.toml /opt/project/
COPY --chown=airflow:root src /opt/project/src

USER airflow
RUN pip install --no-cache-dir -e "/opt/project[dbt]"
