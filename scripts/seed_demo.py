"""Create DEMO users with random passwords (written to data/demo_credentials.txt, git-ignored).
Roles are fixed server-side. Run:  python scripts/seed_demo.py"""
import os
import secrets
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agentguard.api import AgentGuard  # noqa: E402
from agentguard.config import Settings  # noqa: E402

USERS = [("student1", "student"), ("employee1", "employee"), ("employee2", "employee"), ("manager1", "manager"),
         ("manager2", "manager"), ("admin1", "admin"), ("admin2", "admin"), ("reviewer1", "reviewer")]

if __name__ == "__main__":
    s = Settings.from_env()
    ag = AgentGuard(s)
    lines = []
    for name, role in USERS:
        pw = secrets.token_urlsafe(14)
        try:
            ag.provision_user(name, pw, role)
            lines.append(f"{name}\t{role}\t{pw}")
        except Exception as e:  # already exists
            lines.append(f"{name}\t{role}\t(already exists: {type(e).__name__})")
    p = s.data_dir / "demo_credentials.txt"
    p.write_text("\n".join(lines) + "\n")
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
    print(f"Wrote {p} (demo only; random passwords; do not commit)")
