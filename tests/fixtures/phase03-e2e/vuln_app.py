import subprocess


def run_command(user_input: str) -> None:
    """Command injection — CWE-78."""
    subprocess.call(user_input, shell=True)


def read_config(path: str) -> str:
    """Path traversal — CWE-22."""
    return open(path).read()  # noqa: SIM115
