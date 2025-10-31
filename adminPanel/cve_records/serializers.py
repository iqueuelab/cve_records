from rest_framework import serializers
from .models import CVEHistory

class CVEHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = CVEHistory
        fields = [
            'id', 'cveId', 'eventName', 'cveChangeId', 
            'sourceIdentifier', 'created', 'details'
        ]