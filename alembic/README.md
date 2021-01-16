Generic single-database configuration.

export PYTHONPATH=$PYTHONPATH:/full_path/to/alembic_sample

Generate migration:
`alembic revision --autogenerate -m "Add a column"`

Run migrations:
`alembic upgrade head`

Run specific migration:
`alembic upgrade 3acb47b42db5`

Revert last migration:
`alembic -n client downgrade -1`
