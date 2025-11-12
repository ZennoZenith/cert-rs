# systems

## Starting the DB

```sh
# Start postgresql server docker image:
docker run --rm --name pg -p 5432:5432 \
   -e POSTGRES_PASSWORD=welcome \
   postgres:18

# (optional) To have a psql terminal on pg. 
# In another terminal (tab) run psql:
docker exec -it -u postgres pg psql

# (optional) For pg to print all sql statements.
# In psql command line started above.
ALTER DATABASE postgres SET log_statement = 'all';
```

## Dev (watch)

> NOTE: Install cargo watch with `cargo install cargo-watch`.

```sh
# Terminal 1 - To run the server.
cargo watch -q -c -w crates/services/web-server/src/ -w crates/libs/ -w .cargo/ -x "run -p web-server"

# Terminal 2 - To run the quick_dev.
cargo watch -q -c -w crates/services/web-server/examples/ -x "run -p web-server --example quick_dev"
```

## Dev

```sh
# Terminal 1 - To run the server.
cargo run -p web-server

# Terminal 2 - To run the tests.
cargo run -p web-server --example quick_dev
```

## Unit Test (watch)

```sh
cargo watch -q -c -x "test -- --nocapture"

# Specific test with filter.
cargo watch -q -c -x "test -p lib-core test_create -- --nocapture"
```

## Unit Test

```sh
cargo test -- --nocapture

cargo watch -q -c -x "test -p lib-core model::task::tests::test_create -- --nocapture"
```

## Tools

```sh
cargo run -p gen-key
```

<br />
