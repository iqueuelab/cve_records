# CVE History API

REST API for querying CVE (Common Vulnerabilities and Exposures) history records with comprehensive filtering, sorting, and pagination capabilities.

## API Endpoints

### List/Search CVE History Records

```
GET /api/cve-history/
```

## Features

1. **Pagination**

   - Page number: `?page=2`
   - Page size: `?page_size=50` (default: 100, max: 1000)
   - Example: `/api/cve-history/?page=2&page_size=50`

2. **Sorting**

   - Sort by any field using `sort` parameter
   - Prefix with `-` for descending order
   - Multiple sort fields supported (comma-separated)
   - Example: `/api/cve-history/?sort=-created,cve_id`

3. **Filtering**

   a. **Basic Filters (Exact Match)**

   - cve_id
   - event_name
   - cve_change_id
   - source_identifier

   ```
   /api/cve-history/?cve_id=CVE-2021-1234
   ```

   b. **Contains Filters (Case-insensitive)**

   - cve_id_contains
   - event_name_contains
   - source_identifier_contains

   ```
   /api/cve-history/?cve_id_contains=2021
   ```

   c. **Date Range Filters**

   - created_after
   - created_before
   - ingested_after
   - ingested_before

   ```
   /api/cve-history/?created_after=2021-01-01T00:00:00Z&created_before=2021-12-31T23:59:59Z
   ```

   d. **Multiple Values (comma-separated)**

   - Add `_in` suffix to field name

   ```
   /api/cve-history/?event_name_in=Added,Modified,Rejected
   ```

   e. **JSON Field Search**

   - details_contains
   - raw_contains

   ```
   /api/cve-history/?details_contains={"severity":"high"}
   ```

4. **Full-Text Search**
   - Use `q` parameter to search across multiple fields
   - Searches in: cve_id, event_name, source_identifier
   ```
   /api/cve-history/?q=security
   ```

## Example Queries

1. Get latest CVEs:

```
/api/cve-history/?sort=-created
```

2. Search for specific CVE with partial match:

```
/api/cve-history/?cve_id_contains=2021
```

3. Get rejected CVEs from specific date range:

```
/api/cve-history/?event_name=CVE%20Rejected&created_after=2021-01-01
```

4. Complex query combining multiple filters:

```
/api/cve-history/?source_identifier_contains=mitre&created_after=2021-01-01&sort=-created&page_size=50
```

5. Search in JSON fields:

```
/api/cve-history/?details_contains={"impact":"high"}&event_name=Modified
```

## Response Format

```json
{
    "count": 1234,
    "next": "http://example.com/api/cve-history/?page=2",
    "previous": null,
    "results": [
        {
            "id": 1,
            "cve_id": "CVE-2021-1234",
            "event_name": "CVE Added",
            "cve_change_id": "UUID-HERE",
            "source_identifier": "cve@mitre.org",
            "created": "2021-01-01T00:00:00Z",
            "details": [...],
            "raw": {...},
            "ingested_at": "2021-01-02T00:00:00Z"
        },
        ...
    ]
}
```

## Setup

1. Install required packages:

```bash
pip install djangorestframework django-filter
```

2. Add to INSTALLED_APPS in settings.py:

```python
INSTALLED_APPS = [
    ...
    'rest_framework',
    'django_filters',
    'cve_records',
]
```

3. Configure Django REST Framework settings:

```python
REST_FRAMEWORK = {
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 100,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
}
```
