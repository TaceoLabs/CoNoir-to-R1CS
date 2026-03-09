[private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

lint:
    cargo clippy --all-targets -q -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc -q --no-deps

test:
    cargo test --all-features

check-pr: lint test
