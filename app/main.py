"""WSGI entrypoint for local development."""
from __future__ import annotations

from app import create_app


app = create_app()


def main() -> None:
    app.run(debug=True, port=5001)


if __name__ == "__main__":
    main()
