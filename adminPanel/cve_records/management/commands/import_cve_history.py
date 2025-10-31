import time
import json
from typing import Any, Dict, List, Optional

from django.core.management.base import BaseCommand
from django.db import transaction

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import hashlib
from django.utils.dateparse import parse_datetime

from cve_records.models import CVEHistory, ImportCheckpoint


API_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"


def make_session(max_retries: int = 5, backoff_factor: float = 0.5) -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
    )
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"User-Agent": "cve-history-importer/1.0 (+https://example)"})
    return s


def extract_records(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Try to find the main list of history records in the response JSON.

    This function prefers known keys but will fall back to the first list found.
    """
    # Common keys that may hold records
    for key in ("vulnerabilities", "cveHistory", "result", "results", "cve_history"):
        if key in payload and isinstance(payload[key], list):
            return payload[key]

    # fallback: return any top-level list value
    for v in payload.values():
        if isinstance(v, list):
            return v

    return []


def find_cveId(rec: Dict[str, Any]) -> str:
    # Try a few common shapes
    if isinstance(rec.get("cve"), dict) and rec["cve"].get("id"):
        return rec["cve"]["id"]
    if rec.get("cveId"):
        return rec.get("cveId")
    if rec.get("cveId"):
        return rec.get("cveId")
    # some APIs embed as 'cve' -> 'CVE_data_meta' -> 'ID'
    c = rec.get("cve") or {}
    if isinstance(c, dict):
        meta = c.get("CVE_data_meta") or {}
        if isinstance(meta, dict) and meta.get("ID"):
            return meta.get("ID")
    # last resort
    return rec.get("id") or rec.get("name") or "unknown"


def find_timestamp(rec: Dict[str, Any]) -> Optional[str]:
    for k in ("timestamp", "time", "date", "modified"):
        v = rec.get(k)
        if v:
            return v
    return None


class Command(BaseCommand):
    help = "Import CVE history from NVD and store locally with checkpointing."

    def add_arguments(self, parser):
        parser.add_argument("--page-size", type=int, default=2000, help="resultsPerPage to request")
        parser.add_argument("--checkpoint", default="nvd_cve_history", help="name of checkpoint to use")
        parser.add_argument("--start-index", type=int, help="startIndex to begin from (overrides checkpoint)")
        parser.add_argument("--batch-size", type=int, default=1000, help="DB bulk_create batch size")
        parser.add_argument("--max-pages", type=int, default=0, help="limit number of pages (0 = all)")

    def handle(self, *args, **options):
        page_size = options["page_size"]
        batch_size = options["batch_size"]
        cp_name = options["checkpoint"]
        max_pages = options["max_pages"]

        session = make_session()

        # load or create checkpoint
        checkpoint, _ = ImportCheckpoint.objects.get_or_create(name=cp_name)
        start = int(options["start_index"]) if options.get("start_index") is not None else int(checkpoint.next_index or 0)

        # first request to detect total
        params = {"startIndex": start, "resultsPerPage": page_size}
        self.stdout.write(f"Starting import from index {start} (page_size={page_size})")

        page_count = 0
        total_results = None

        while True:
            if max_pages and page_count >= max_pages:
                self.stdout.write("Reached max-pages limit, stopping.")
                break

            params["startIndex"] = start
            params["resultsPerPage"] = page_size

            try:
                resp = session.get(API_URL, params=params, timeout=30)
                if resp.status_code == 429:
                    # backoff then retry
                    wait = 60
                    self.stdout.write(f"Rate limited (429). Sleeping {wait}s")
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
            except Exception as e:
                self.stderr.write(f"Request failed at index {start}: {e}")
                # don't crash; wait and retry a few times
                time.sleep(5)
                continue

            data = resp.json()

            # determine total and resultsPerPage if available
            if total_results is None:
                for k in ("totalResults", "total", "count"):
                    if isinstance(data.get(k), int):
                        total_results = data.get(k)
                        break

            # extract records list
            records = extract_records(data)

            if total_results is None:
                # try to derive from headers or data
                total_results = data.get("totalResults") or data.get("total")

            if not records:
                self.stdout.write(f"No records found at startIndex={start}. Stopping.")
                break

            # prepare model instances matching our CVEHistory model (records often come as {"change": {...}})
            objs = []
            for rec in records:
                # the API returns items like {"change": {...}} — support that shape and fall back to the record itself
                change = rec.get("change") if isinstance(rec, dict) and rec.get("change") else rec
                if not isinstance(change, dict):
                    continue

                cveId = change.get("cveId") or change.get("cveId") or find_cveId(change)
                eventName = change.get("eventName") or change.get("eventName")
                cveChangeId = change.get("cveChangeId") or change.get("cveChangeId") or change.get("id")
                sourceIdentifier = change.get("sourceIdentifier") or change.get("sourceIdentifier")

                created_raw = change.get("created") or change.get("date") or change.get("time")
                created_dt = None
                if created_raw:
                    created_dt = parse_datetime(created_raw)
                    if created_dt is None:
                        # try removing fractional seconds
                        try:
                            created_dt = parse_datetime(created_raw.split(".")[0])
                        except Exception:
                            created_dt = None

                details = change.get("details") if isinstance(change.get("details"), (list, dict)) else None

                # ensure we have a stable cveChangeId (unique). If missing, derive a sha1 from the raw change
                if not cveChangeId:
                    # use JSON canonical representation
                    try:
                        raw_str = json.dumps(change, sort_keys=True)
                    except Exception:
                        raw_str = str(change)
                    cveChangeId = hashlib.sha1(raw_str.encode("utf-8")).hexdigest()

                objs.append(
                    CVEHistory(
                        cveId=cveId or "unknown",
                        eventName=eventName,
                        cveChangeId=cveChangeId,
                        sourceIdentifier=sourceIdentifier,
                        created=created_dt,
                        details=details,
                    )
                )

            # bulk insert in chunks while avoiding duplicates by cveChangeId
            created = 0
            try:
                with transaction.atomic():
                    for i in range(0, len(objs), batch_size):
                        chunk = objs[i : i + batch_size]
                        # get cveChangeIds in this chunk
                        chunk_ids = [o.cveChangeId for o in chunk if o.cveChangeId]
                        # query existing ids to avoid unique constraint failures
                        existing = set()
                        if chunk_ids:
                            existing = set(
                                CVEHistory.objects.filter(cveChangeId__in=chunk_ids).values_list(
                                    "cveChangeId", flat=True
                                )
                            )

                        to_create = [o for o in chunk if o.cveChangeId not in existing]
                        if to_create:
                            CVEHistory.objects.bulk_create(to_create, batch_size=batch_size)
                            created += len(to_create)
                        else:
                            # nothing new in this chunk
                            pass
            except Exception as e:
                self.stderr.write(f"DB insert failed at start {start}: {e}")
                # Do not advance checkpoint; allow rerun after fix
                raise

            start += len(records)
            checkpoint.next_index = start
            if isinstance(total_results, int):
                checkpoint.total = total_results
            checkpoint.save()

            page_count += 1
            self.stdout.write(f"Imported {created} records (progress: {start}/{total_results or 'unknown'})")

            # stop when we've reached total
            if isinstance(total_results, int) and start >= total_results:
                self.stdout.write("All records imported.")
                break

            # small sleep to be polite and avoid rate limits
            time.sleep(0.2)

        self.stdout.write("Import finished. Checkpoint saved: %s" % checkpoint.next_index)
