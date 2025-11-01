from rest_framework import viewsets, filters
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q
from .models import CVEHistory
from .serializers import CVEHistorySerializer
from .filters import CVEHistoryFilter

class StandardResultsSetPagination(PageNumberPagination):
    """Custom pagination with smaller default page size to prevent memory issues.

    This pagination accepts both `page` and `page_number` query params so
    clients can use whichever they prefer.
    """
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 1000
    page_query_param = 'page'

    def get_page_number(self, request, paginator):
        """Allow either `page` or `page_number` query params.

        Falls back to the default behavior when neither is provided.
        """
        # prefer explicit page param then page_number
        page_number = request.query_params.get(self.page_query_param) or request.query_params.get('page_number')
        if page_number is None:
            return super().get_page_number(request, paginator)
        return page_number

class CVEHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for querying CVE History records.
    
    Features:
    - Pagination: Use page and page_size parameters
    - Sorting: Use sort parameter (prefix with - for descending)
    - Filtering: Multiple filter options available
    - Search: Full text search across multiple fields
    
    Filter parameters:
    - cve_id: Exact match (e.g., ?cve_id=CVE-2021-1234)
    - cve_id_contains: Case-insensitive partial match
    - event_name: Exact match
    - event_name_contains: Case-insensitive partial match
    - cve_change_id: Exact match
    - source_identifier: Exact match
    - source_identifier_contains: Case-insensitive partial match
    
    Date filters:
    - created_after: ISO format (e.g., ?created_after=2021-01-01T00:00:00Z)
    - created_before: ISO format
    - ingested_after: ISO format
    - ingested_before: ISO format
    
    JSON field filters:
    - details_contains: Search in details JSON
    - raw_contains: Search in raw JSON
    
    Multiple values:
    - Add _in suffix for multiple values (comma-separated)
    - Example: ?event_name_in=Added,Modified,Rejected
    
    Sorting:
    - Use sort parameter with field names
    - Prefix with - for descending order
    - Multiple fields supported (comma-separated)
    - Example: ?sort=-created,cve_id
    
    Search:
    - Use q parameter for full-text search across multiple fields
    - Example: ?q=searchterm
    
    Example queries:
    - /api/cve-history/?cve_id=CVE-2021-1234
    - /api/cve-history/?event_name_contains=rejected&created_after=2021-01-01
    - /api/cve-history/?sort=-created&page_size=50
    - /api/cve-history/?source_identifier=mitre&details_contains={"severity":"high"}
    """
    queryset = CVEHistory.objects.all().only(
        'id', 'cveId', 'eventName', 'cveChangeId',
        'sourceIdentifier', 'created'
    ).defer('details')  # Defer large JSON fields unless specifically requested
    
    serializer_class = CVEHistorySerializer
    pagination_class = StandardResultsSetPagination
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_class = CVEHistoryFilter
    search_fields = [
        'cveId', 
        'eventName', 
        'cveChangeId', 
        'sourceIdentifier'
    ]
    ordering_fields = [
        'cveId', 
        'eventName', 
        'cveChangeId', 
        'sourceIdentifier',
        'created',
    ]
    ordering = ['created']  # default sorting
    
    def get_queryset(self):
        """
        Optimize queryset based on requested fields and sorting.
        - Defers JSON fields by default
        - Only loads fields that will be used
        - Adds specific optimizations for sorting
        """
        queryset = super().get_queryset()
        
        # If JSON fields are needed (check request parameters)
        request = self.request
        if request and any(param in request.query_params for param in ['details_contains']):
            queryset = CVEHistory.objects.all()  # Don't defer JSON fields
        
        # Get the sort fields
        ordering = self.request.query_params.get('sort', 'created').split(',')
        
        # If sorting by a specific field, optimize the query
        if len(ordering) == 1:
            sort_field = ordering[0].lstrip('-')
            if sort_field in ['created']:
                # For date sorting, we can use an indexed field directly
                queryset = queryset.order_by(ordering[0], 'id')
            elif sort_field in ['cveId', 'eventName']:
                # For string sorting, add id as secondary sort to ensure stability
                queryset = queryset.order_by(ordering[0], 'id')
        
        return queryset
