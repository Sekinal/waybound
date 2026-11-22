.PHONY: setup check fix test fmt-check lint-rust lint-python

setup:
	cd python && uv sync --dev
	cd python && uv run pre-commit install

check: fmt-check lint-rust lint-python test

fix:
	cargo fmt --all
	cd python && uv run ruff check --fix .
	cd python && uv run ruff format .

fmt-check:
	cargo fmt --all -- --check
	cd python && uv run ruff format --check .

lint-rust:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

lint-python:
	cd python && uv run ruff check .
	cd python && uv run mypy src tests

test:
	cargo test --workspace --all-features
	cd python && uv run pytest
