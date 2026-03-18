set dotenv-load

# alias r := run-server

default:
    @just --choose

all:
    cargo fmt --check
    cargo clippy -- -D warnings
    cargo test
    cargo audit

clippy:
    cargo clippy-all
    
fmt: 
    echo "Formatting"
    cargo fmt

doc: 
    # cargo doc --no-deps --document-private-items -p cert-rs
    cargo doc --no-deps --document-private-items

# integration-test:
#     DOCKER=true LOG=true ./tests/test.sh

test:
    cargo test -- --nocapture
    
watch-test:
    watchexec -q "cargo test -- --nocapture"

watch-test-specific:
    # Specific test with filter.
    watchexec -q -c -x "cargo test utils::tests::test_create -- --nocapture"

run-example:
    cargo run --example playground

pebble:
    ## Pebble will sleep a random number of seconds, Set to 1 to test at full speed
    ## (https://github.com/letsencrypt/pebble?tab=readme-ov-file#testing-at-full-speed)
    # PEBBLE_VA_NOSLEEP: 1

    ## The maximal number of seconds to sleep
    # PEBBLE_VA_SLEEPTIME: 2 

    ## [Skip validation](https://github.com/letsencrypt/pebble?tab=readme-ov-file#skipping-validation )
    # PEBBLE_VA_ALWAYS_VALID: 1

    ## https://github.com/letsencrypt/pebble?tab=readme-ov-file#invalid-anti-replay-nonce-errors
    ## to reject 10% of good nonces, To never reject a valid nonce set it to 0
    # PEBBLE_WFE_NONCEREJECT: 10 

    ## [Listing orders](https://github.com/letsencrypt/pebble?tab=readme-ov-file#listing-orders)
    # PEBBLE_WFE_ORDERS_PER_PAGE: 15
    
    # pebble -config ./pebble/config.json -strict -dnsserver 10.30.50.3:8053
    # PEBBLE_WFE_NONCEREJECT=0 PEBBLE_VA_NOSLEEP=1 pebble -config ./pebble/config.json -dnsserver 127.0.0.1:8053
    PEBBLE_WFE_NONCEREJECT=50 PEBBLE_VA_NOSLEEP=1 pebble -config ./pebble/config.json -dnsserver 127.0.0.1:8053

pebble-challtestsrv:
    pebble-challtestsrv -defaultIPv6 "" -defaultIPv4 127.0.0.1
