# OpenRelik worker for ClamAV

This worker runs [ClamAV](https://github.com/Cisco-Talos/clamav) over evidence supplied to OpenRelik. It safely unpacks Velociraptor collection archives (zip/tar.*), scans all contained files, and writes JSON reports back into the workflow. When detections are present, a second JSON file lists only the infected items for quick triage.

## What you can run from the OpenRelik UI

- **ClamAV Velociraptor Scan (`scan_velociraptor_collection`)** – point the task at a Velociraptor collection export (zip/tar.*). The worker extracts the archive, recursively runs `clamscan`, and emits:
  - Full scan report (`*_clamav.json`): command, return code, per-file results, ClamAV scan summary, stderr (if any).
  - Infected-only report (`*_clamav_infected.json`): only files flagged as `FOUND`, plus summary totals.
  - Progress events: the UI shows `PROGRESS` updates with processed/total counts and current file paths during the scan.
- **Include clean files** – optional checkbox to include clean files in the report output (default: only infected lines in `clamscan` output).

Both reports are attached to the workflow so you can download or feed them into downstream tasks without leaving OpenRelik.

## Installation instructions

Add the worker to your OpenRelik `docker-compose` stack:

```
  openrelik-worker-clamav:
    container_name: openrelik-worker-clamav
    image: ghcr.io/julianghill/openrelik-worker-clamav:latest
    restart: always
    environment:
      - REDIS_URL=redis://openrelik-redis:6379
      - OPENRELIK_PYDEBUG=0
    volumes:
      - ./data:/usr/share/openrelik/data
    command: "celery --app=src.app worker --task-events --concurrency=4 --loglevel=INFO -Q openrelik-worker-clamav"
```

> The Docker image refreshes ClamAV signatures during build (`freshclam`). Rebuild periodically or run `freshclam` in a sidecar/cron if you need up-to-date definitions.

## Local development

```
uv sync --group test
uv run pytest -s --cov=.
```

To run the worker locally with Redis available:

```
REDIS_URL=redis://localhost:6379/0 \
uv run celery --app=src.app worker --task-events --concurrency=1 --loglevel=INFO -Q openrelik-worker-clamav
```

## Notes

- Supports Velociraptor collection archives (zip/tar.*). Files are extracted with zip/tar path traversal protection, then scanned recursively.
- Progress is emitted via Celery `task-progress` events; the UI shows a spinning/progress state while ClamAV runs.
- Two outputs when infections are found:
  - Full scan JSON (`clamav_scan` data_type)
  - Infected-only JSON (`clamav_scan_infected` data_type)
- Safe extraction runs inside a temp directory per task; staging is cleaned up after each run.
- `include_clean` toggles whether clean files are listed in the ClamAV stdout (and thus in the full report).

### Extending to disk images

The worker currently expects archives/directories. To add disk-image support later, mount the image read-only into a temp directory (e.g., `ewfmount`/`qemu-nbd`/`guestmount`) and reuse the existing scan flow against the mount path, then unmount on completion. If you want that built in, we can add an `input_type` or `mount_command` config to drive the mount and cleanup. This will be done later .. I hope :)
