.PHONY: install test docker demo watch

install:
	uv sync
	uv run playwright install chromium

test:
	uv run pytest

docker:
	docker compose build

demo:
	uv run shaheen demo

watch:
	uv run shaheen watch
