.PHONY: install test docker

install:
	uv sync
	uv run playwright install chromium

test:
	uv run pytest

docker:
	docker compose build
