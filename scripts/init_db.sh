#!/usr/bin/env bash
# set -x
set -eo pipefail

if ! [ -x "$(command -v psql)" ]; then
  echo >&2 "Error: psql is not installed."
  exit 1
fi

if ! [ -x "$(command -v sqlx)" ]; then
  echo >&2 "Error: sqlx is not installed."
  echo >&2 "Use: "
  # echo >&2 "cargo install --version=0.5.7 sqlx-cli --no-default-features --features postgres"
  echo >&2 "cargo binstall sqlx-cli --no-default-features --features postgres"
  echo >&2 "to install it."
  exit 1
fi

ENV_FILE="$1"
CMD=${@:2}

# Check if a custom user has been set, otherwise default to 'postgres'
DB_USER=${POSTGRES_USER:=postgres}
# Check if a custom password has been set, otherwise default to 'password'
DB_PASSWORD="${POSTGRES_PASSWORD:=welcome}"
# Check if a custom database name has been set, otherwise default to 'newsletter'
DB_NAME="${POSTGRES_DB:=example_db}"
# Check if a custom port has been set, otherwise default to '5432'
DB_PORT="${POSTGRES_PORT:=5432}"
DB_HOST="${POSTGRES_HOST:=127.0.0.1}"

echo $DB_PASSWORD > ./db/password.txt

if [[ $DOCKER == true ]]; then
  # docker compose up -d --force-recreate --remove-orphans
  docker compose up -d
fi

# Keep pinging Postgres until it's ready to accept commands
export PGPASSWORD="${DB_PASSWORD}"
until psql -h "localhost" -U "${DB_USER}" -p "${DB_PORT}" -d "postgres" -c '\q'; do
>&2 echo "Postgres is still unavailable - sleeping"
sleep 1
done
>&2 echo "Postgres is up and running on port ${DB_PORT}!"

export DATABASE_URL=postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}

sqlx database create
sqlx migrate run --source ./db/migrations

>&2 echo "Postgres has been migrated, ready to go!"


if [[ $SEED == true ]]; then
#   psql -v ON_ERROR_STOP=1 -h "localhost" -U "${DB_USER}" -p "${DB_PORT}" --dbname "$DB_NAME" <<-EOSQL
# 	CREATE USER docker;
# 	CREATE DATABASE docker;
# 	GRANT ALL PRIVILEGES ON DATABASE docker TO docker;
# EOSQL
  psql \
    -v ON_ERROR_STOP=1 \
    -h "localhost" \
    -U "${DB_USER}" \
    -p "${DB_PORT}" \
    --dbname "$DB_NAME" \
    -f ./db/fixtures/dev-seed-user.sql
    
  >&2 echo "Database seeded"
fi

if [[ $LOG == true ]]; then
  docker logs --follow example_service_example_db
fi
