import json
from django_filters import rest_framework as filters
from django.db.models import Q
from .models import CVEHistory

class CVEHistoryFilter(filters.FilterSet):
    # Exact matches
    cveId = filters.CharFilter(lookup_expr='exact')
    eventName = filters.CharFilter(lookup_expr='exact')
    cveChangeId = filters.CharFilter(lookup_expr='exact')
    sourceIdentifier = filters.CharFilter(lookup_expr='exact')
    
    # Contains/icontains filters for text fields
    cveId_contains = filters.CharFilter(field_name='cveId', lookup_expr='icontains')
    eventName_contains = filters.CharFilter(field_name='eventName', lookup_expr='icontains')
    sourceIdentifier_contains = filters.CharFilter(field_name='sourceIdentifier', lookup_expr='icontains')
    
    # JSON field contains (for both details and raw)
    details_contains = filters.CharFilter(method='filter_json_contains')
    raw_contains = filters.CharFilter(method='filter_json_contains')
    
    # Multiple value filters (comma-separated)
    cveId_in = filters.CharFilter(method='filter_list')
    eventName_in = filters.CharFilter(method='filter_list')
    sourceIdentifier_in = filters.CharFilter(method='filter_list')
    
    # Search across multiple fields
    search = filters.CharFilter(method='filter_search')
    
    def filter_list(self, queryset, name, value):
        field_name = name.replace('_in', '')
        values = [v.strip() for v in value.split(',') if v.strip()]
        if values:
            return queryset.filter(**{f"{field_name}__in": values})
        return queryset
    
    def filter_json_contains(self, queryset, name, value):
        field_name = name.replace('_contains', '')
        try:
            # Try to parse as JSON if it looks like JSON
            if value.startswith('{') or value.startswith('['):
                return queryset.filter(**{f"{field_name}__contains": json.loads(value)})
            # Otherwise treat as string
            return queryset.filter(**{f"{field_name}__contains": value})
        except Exception:
            return queryset.filter(**{f"{field_name}__contains": value})
    
    def filter_search(self, queryset, name, value):
        return queryset.filter(
            Q(cveId__icontains=value) |
            Q(eventName__icontains=value) |
            Q(sourceIdentifier__icontains=value)
        )
    
    class Meta:
        model = CVEHistory
        fields = {
            'cveId': ['exact', 'in', 'startswith'],
            'eventName': ['exact', 'in'],
            'cveChangeId': ['exact', 'in'],
            'sourceIdentifier': ['exact', 'in'],
            'created': ['exact', 'lt', 'lte', 'gt', 'gte'],
        }