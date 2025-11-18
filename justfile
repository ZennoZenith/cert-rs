set dotenv-load

# alias r := run-server

default:
    @just --choose

fmt: 
    echo "Formatting"
    cargo fmt


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
