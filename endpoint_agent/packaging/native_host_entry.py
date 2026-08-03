"""PyInstaller entry point for the stdio-only Native Messaging Host."""

from shielddome_endpoint.native_host import main


if __name__ == "__main__":
    raise SystemExit(main())
