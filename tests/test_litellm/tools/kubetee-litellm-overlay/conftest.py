"""Import the measured overlay from the worktree, not the production submodule."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] /
                     "tools/kubetee-litellm-overlay"))
