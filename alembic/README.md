Generic single-database configuration.

`export PYTHONPATH=$PYTHONPATH:$(pwd)`

Generate migration:
`alembic revision --autogenerate -m "Add a column"`

Run migrations:
`alembic upgrade head`

Run specific migration:
`alembic upgrade 3acb47b42db5`

Revert last migration:
`alembic downgrade -1`
