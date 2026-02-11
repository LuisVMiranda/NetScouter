"""GUI bootstrap and application startup for NetScouter."""

from __future__ import annotations

from netscouter.gui.bootstrap import launch_dashboard


def main() -> None:
    """Application entrypoint."""
    launch_dashboard()


if __name__ == "__main__":
    main()
