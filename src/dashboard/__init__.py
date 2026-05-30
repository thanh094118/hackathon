from src.dashboard.query_adapter import DashboardQueryAdapter

__all__ = ["main", "DashboardQueryAdapter"]


def main():
    from src.dashboard.app import main as _main

    return _main()
