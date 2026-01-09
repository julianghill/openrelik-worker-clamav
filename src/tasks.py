import json
import subprocess
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, Dict, List, Optional, Tuple

from celery import signals
from celery.utils.log import get_task_logger

# API docs - https://openrelik.github.io/openrelik-worker-common/openrelik_worker_common/index.html
from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.logging import Logger
from openrelik_worker_common.task_utils import create_task_result, get_input_files

from .app import celery

TASK_NAME = "openrelik-worker-clamav.tasks.scan_velociraptor_collection"

TASK_METADATA = {
    "display_name": "ClamAV Velociraptor Scan",
    "description": "Scan Velociraptor collection archives with ClamAV.",
    "task_config": [
        {
            "name": "update_signatures",
            "label": "Update signatures before scan",
            "description": "Fetch the latest ClamAV signatures before running the scan.",
            "type": "checkbox",
            "required": False,
        },
        {
            "name": "include_clean",
            "label": "Include clean files in report",
            "description": "When enabled, the report will list clean files in addition to infected ones.",
            "type": "checkbox",
            "required": False,
        },
    ],
}

log_root = Logger()
logger = log_root.get_logger(__name__, get_task_logger(__name__))

CLAMAV_DB_DIRS = [Path("/var/lib/clamav")]


def _coerce_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _first_value(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _safe_extract_tar(tar: tarfile.TarFile, destination: Path) -> None:
    destination = destination.resolve()
    for member in tar.getmembers():
        member_path = (destination / member.name).resolve()
        if not str(member_path).startswith(str(destination)):
            raise ValueError(f"Tar member would escape destination: {member.name}")
    tar.extractall(destination)


def _safe_extract_zip(zip_file: zipfile.ZipFile, destination: Path) -> None:
    destination = destination.resolve()
    for member in zip_file.namelist():
        member_path = (destination / member).resolve()
        if not str(member_path).startswith(str(destination)):
            raise ValueError(f"Zip member would escape destination: {member}")
    zip_file.extractall(destination)


def _extract_archive(input_path: Path, staging_dir: Path) -> Path:
    """Extract supported archive types into staging_dir and return the extraction path."""
    destination = staging_dir / input_path.stem
    destination.mkdir(parents=True, exist_ok=True)

    if zipfile.is_zipfile(input_path):
        with zipfile.ZipFile(input_path, "r") as zf:
            _safe_extract_zip(zf, destination)
        return destination

    if tarfile.is_tarfile(input_path):
        with tarfile.open(input_path, "r:*") as tf:
            _safe_extract_tar(tf, destination)
        return destination

    return input_path


def _count_files(path: Path) -> int:
    if path.is_file():
        return 1
    return sum(1 for p in path.rglob("*") if p.is_file())


def _send_progress(
    task,
    display_name: str,
    total_files: int,
    processed: int,
    infected: int,
    current_path: Optional[str],
    signature_status: Optional[Dict[str, Optional[str]]] = None,
) -> None:
    percent = round((processed / total_files) * 100, 2) if total_files else None
    signature_status_text = _format_signature_status(signature_status or {})
    task.send_event(
        "task-progress",
        data={
            "file": display_name,
            "processed": processed,
            "total": total_files,
            "percent": percent,
            "infected": infected,
            "current_path": current_path,
            "signature_status": signature_status_text,
            "signature_updated_at": (signature_status or {}).get("updated_at"),
            "signature_files": (signature_status or {}).get("files"),
        },
    )


def _get_signature_status(db_dir: Optional[Path] = None) -> Dict[str, Optional[str]]:
    target_dir = db_dir
    if target_dir is None:
        for candidate in CLAMAV_DB_DIRS:
            if candidate.exists():
                target_dir = candidate
                break

    status: Dict[str, Optional[str]] = {
        "db_dir": str(target_dir) if target_dir else None,
        "updated_at": None,
        "files": None,
    }

    if target_dir is None:
        return status

    candidates = [
        "main.cvd",
        "main.cld",
        "daily.cvd",
        "daily.cld",
        "bytecode.cvd",
        "bytecode.cld",
    ]

    newest_mtime = None
    file_entries = []
    for name in candidates:
        path = target_dir / name
        if not path.exists():
            continue
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            continue
        file_entries.append({"name": name, "updated_at": mtime.strftime("%Y-%m-%d %H:%M:%S UTC")})
        if newest_mtime is None or mtime > newest_mtime:
            newest_mtime = mtime

    if newest_mtime:
        status["updated_at"] = newest_mtime.strftime("%Y-%m-%d %H:%M:%S UTC")
    if file_entries:
        status["files"] = ", ".join(entry["name"] for entry in file_entries)

    return status


def _format_signature_status(status: Dict[str, Optional[str]]) -> Optional[str]:
    updated_at = status.get("updated_at")
    files = status.get("files")
    parts = []
    if updated_at:
        parts.append(f"Updated: {updated_at}")
    if files:
        parts.append(f"Files: {files}")
    if not parts:
        return None
    return " | ".join(parts)


def _update_signatures(task, task_config: Optional[dict]) -> None:
    raw_update = _first_value((task_config or {}).get("update_signatures"))
    if not _coerce_bool(raw_update):
        return

    task.send_event("task-progress", data={"message": "Updating ClamAV signatures..."})
    result = subprocess.run(
        ["freshclam", "--stdout"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        logger.warning(
            "ClamAV signature update failed (code %s). STDERR: %s",
            result.returncode,
            (result.stderr or "").strip() or "<empty>",
        )
        task.send_event(
            "task-progress",
            data={"message": "Signature update failed; continuing scan."},
        )
        return

    task.send_event("task-progress", data={"message": "Signature update complete."})


def _write_infected_only_report(output_path: str, display_name: str, scan_result: Dict):
    infected_items = [item for item in scan_result.get("items", []) if item.get("result") == "FOUND"]
    if not infected_items:
        return None

    infected_file = create_output_file(
        output_path,
        display_name=f"{display_name}_clamav_infected",
        extension="json",
        data_type="clamav_scan_infected",
    )

    with open(infected_file.path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "infected_count": len(infected_items),
                "items": infected_items,
                "summary": scan_result.get("summary", {}),
            },
            fh,
            indent=2,
        )

    return infected_file


def parse_clamscan_output(output: str) -> Tuple[List[Dict[str, str]], Dict[str, str]]:
    """Parse clamscan stdout into per-file results and summary."""
    items: List[Dict[str, str]] = []
    summary: Dict[str, str] = {}
    in_summary = False

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("----------- SCAN SUMMARY"):
            in_summary = True
            continue
        if in_summary:
            if ":" in line:
                key, value = line.split(":", 1)
                summary[key.strip()] = value.strip()
            continue
        if ": " not in line:
            continue

        path, status = line.split(": ", 1)
        signature = None
        result = status

        if status.endswith("FOUND"):
            result = "FOUND"
            signature = status.rsplit(" ", 1)[0]
        elif status == "OK":
            result = "OK"

        items.append({"path": path, "result": result, "signature": signature})

    return items, summary


def run_clamscan(
    scan_target: Path,
    include_clean: bool,
    total_files: int,
    progress_cb: Optional[Callable[[int, int, int, Dict[str, str]], None]] = None,
) -> Dict:
    """Run clamscan against the target and return a structured report."""
    base_command = ["clamscan", "--recursive", "--stdout"]
    if not include_clean:
        base_command.append("--infected")

    command = base_command + [str(scan_target)]
    logger.info("Running clamscan: %s", " ".join(command))
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    stdout_lines: List[str] = []
    processed = 0
    infected_seen = 0

    if progress_cb:
        progress_cb(processed, total_files, infected_seen, {})

    in_summary = False

    for line in process.stdout:
        stdout_lines.append(line)
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("----------- SCAN SUMMARY"):
            in_summary = True
            continue
        if in_summary:
            continue
        if ": " not in stripped:
            continue
        path, status = stripped.split(": ", 1)
        processed += 1
        if status.endswith("FOUND"):
            infected_seen += 1
        if progress_cb:
            progress_cb(
                processed,
                total_files,
                infected_seen,
                {"path": path, "status": status},
            )

    process.wait()
    stderr = process.stderr.read() if process.stderr else ""

    if stderr:
        logger.warning("clamscan stderr: %s", stderr)

    stdout_text = "".join(stdout_lines)
    items, summary = parse_clamscan_output(stdout_text)

    infected_from_summary = summary.get("Infected files")
    infected_count = int(infected_from_summary) if infected_from_summary and infected_from_summary.isdigit() else 0
    infected = infected_count > 0 or any(item.get("result") == "FOUND" for item in items)

    return {
        "command": " ".join(command),
        "return_code": process.returncode,
        "infected": infected,
        "items": items,
        "summary": summary,
        "stderr": stderr,
    }


@signals.task_prerun.connect
def on_task_prerun(sender, task_id, task, args, kwargs, **_):
    log_root.bind(
        task_id=task_id,
        task_name=task.name,
        worker_name=TASK_METADATA.get("display_name"),
    )


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def command(
    self,
    pipe_result: str = None,
    input_files: list = None,
    output_path: str = None,
    workflow_id: str = None,
    task_config: dict = None,
) -> str:
    """Scan Velociraptor collections with ClamAV."""
    log_root.bind(workflow_id=workflow_id)
    logger.info(f"Starting {TASK_NAME} for workflow {workflow_id}")

    input_files = get_input_files(pipe_result, input_files or [])
    include_clean = _coerce_bool(_first_value((task_config or {}).get("include_clean")))
    output_files = []

    if not input_files:
        logger.warning("No input files supplied to ClamAV worker.")

    _update_signatures(self, task_config)
    signature_status = _get_signature_status()
    signature_status_text = _format_signature_status(signature_status)
    if signature_status_text:
        self.send_event("task-progress", data={"message": f"ClamAV signatures: {signature_status_text}"})

    with TemporaryDirectory(prefix="clamav_", dir=output_path) as staging_dir:
        staging_path = Path(staging_dir)
        for input_file in input_files:
            source_path = Path(input_file.get("path"))
            display_name = input_file.get("display_name") or source_path.name
            scan_target = _extract_archive(source_path, staging_path)
            total_files = _count_files(scan_target)
            scan_result = run_clamscan(
                scan_target,
                include_clean,
                total_files,
                progress_cb=lambda processed, total, infected, current: _send_progress(
                    self,
                    display_name,
                    total,
                    processed,
                    infected,
                    current.get("path") if current else None,
                    signature_status,
                ),
            )

            output_file = create_output_file(
                output_path,
                display_name=f"{display_name}_clamav",
                extension="json",
                data_type="clamav_scan",
            )

            with open(output_file.path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "input_file": str(source_path),
                        "scan_target": str(scan_target),
                        "signature_status": signature_status,
                        **scan_result,
                    },
                    fh,
                    indent=2,
                )

            output_files.append(output_file.to_dict())
            infected_only = _write_infected_only_report(output_path, display_name, scan_result)
            if infected_only:
                output_files.append(infected_only.to_dict())

    return create_task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        command="clamscan",
        meta={
            "include_clean": include_clean,
            "signature_updated_at": signature_status.get("updated_at"),
            "signature_files": signature_status.get("files"),
        },
    )
