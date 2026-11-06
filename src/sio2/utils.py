from pathlib import Path
import subprocess

def target_commit(root: Path) -> str:
    """The pinned commit of --input, read by the runtime (the model never sees .git).

    Args:
        root: The path to the Git repository.
    Returns:
        The commit SHA as a 40-character string, or "0" * 40 if it cannot be determined.
    """
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
        sha = out.stdout.strip()
        if len(sha) == 40:
            return sha
    except (OSError, subprocess.SubprocessError):
        pass
    return "0" * 40