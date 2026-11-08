.PHONY: setup test lint demo ingest load dbt freshness run airflow clean

setup:            ## create venv and install everything
	python -m venv .venv && . .venv/bin/activate && pip install -e ".[dbt,dev]"
	[ -f .env ] || cp .env.example .env

test:             ## unit tests (offline)
	pytest -q

lint:
	ruff check src tests airflow

demo:             ## offline end-to-end run on fixtures
	vulnintel demo && vulnintel dbt build

ingest:           ## pull NVD, EPSS and KEV into data/landing
	vulnintel ingest all

load:             ## load new landed files into the warehouse
	vulnintel load

dbt:
	vulnintel dbt build

freshness:
	vulnintel dbt source freshness

run:              ## the whole daily pipeline, without Airflow
	vulnintel run

airflow:          ## local Airflow at http://localhost:8080
	docker compose up --build

clean:
	rm -rf data/landing data/state data/warehouse.duckdb dbt/target
