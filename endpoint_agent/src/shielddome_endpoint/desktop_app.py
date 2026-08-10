import sys


def main() -> int:
    try:
        from .desktop_qt import create_desktop_application
    except ImportError:
        sys.stderr.write(
            "ShieldDome desktop UI requires the approved offline "
            "PySide6-Essentials==6.8.3 runtime.\n"
        )
        return 2
    bundle = create_desktop_application()
    return bundle.application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
