from models import User

# Create User table.
if not User.table_exists():
    User.create_table()
