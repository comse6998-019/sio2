"""sio2: a bounded agent that scans a pinned Python repository with Bandit and labels each alert."""


def main() -> int:
    from sio2.cli import main as cli_main
    return cli_main()
