import json
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path


class BackupManager:
    def __init__(self, db_path: str | Path, backup_dir: str | Path | None = None):
        self.db_path = Path(db_path)
        self.backup_dir = Path(backup_dir) if backup_dir else self.db_path.parent / 'backups'

    def create_backup(self) -> Path:
        """Create a backup of the database. Returns backup file path."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        backup_path = self.backup_dir / f'migate_backup_{ts}.db'
        # Use SQLite backup API for consistent snapshot
        src = sqlite3.connect(str(self.db_path))
        dst = sqlite3.connect(str(backup_path))
        src.backup(dst)
        src.close()
        dst.close()
        return backup_path

    def list_backups(self) -> list[dict]:
        """List available backups."""
        if not self.backup_dir.exists():
            return []
        backups = []
        for f in sorted(self.backup_dir.glob('*.db'), reverse=True):
            backups.append({
                'name': f.name,
                'size': f.stat().st_size,
                'created': datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
        return backups

    def restore_backup(self, backup_name: str) -> bool:
        """Restore from a backup file."""
        backup_path = self.backup_dir / backup_name
        if not backup_path.exists():
            return False
        # Create a safety backup first
        self.create_backup()
        # Remove existing DB and its WAL/journal to ensure clean restore
        for suffix in ("", "-wal", "-shm", "-journal"):
            p = self.db_path.with_name(self.db_path.name + suffix) if suffix else self.db_path
            if p.exists():
                p.unlink()
        # Use shutil to copy the backup file
        shutil.copy2(backup_path, self.db_path)
        return True

    def delete_backup(self, backup_name: str) -> bool:
        backup_path = self.backup_dir / backup_name
        if not backup_path.exists():
            return False
        backup_path.unlink()
        return True
