from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

def get_scenario_path(module_dir: str, scenario_dir: str, variant: str) -> Path:
    """Returns the absolute path to a specific scenario variant."""
    return PROJECT_ROOT / "modules" / module_dir / scenario_dir / variant
