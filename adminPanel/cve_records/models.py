from django.db import models


# Stores a single CVE history "change" as returned by the NVD endpoint.
# Matches the sample shape where each record is { "change": { ... } }
class CVEHistory(models.Model):
	# maps to change.cveId
	cveId = models.CharField(max_length=200, db_index=True)

	# maps to change.eventName (e.g., "CVE Rejected")
	eventName = models.CharField(max_length=200, null=True, blank=True)

	# maps to change.cveChangeId (useful as a unique change identifier)
	cveChangeId = models.CharField(max_length=200, unique=True, db_index=True)

	# maps to change.sourceIdentifier
	sourceIdentifier = models.CharField(max_length=200, null=True, blank=True)

	# maps to change.created (datetime string in source)
	created = models.DateTimeField(null=True, blank=True)

	# store the details array (often empty) as JSON
	details = models.JSONField(null=True, blank=True)

	class Meta:
		indexes = [
			models.Index(fields=["cveId"]),
			models.Index(fields=["cveChangeId"]),
			models.Index(fields=["created", "id"]),  # Compound index for sorted pagination
			models.Index(fields=["eventName", "id"]),  # Common sort field
			models.Index(fields=["sourceIdentifier", "id"]),  # Common filter/sort field
		]

	def __str__(self) -> str:
		return f"{self.cveId} ({self.cveChangeId}) @ {self.created} [{self.eventName}]"


class ImportCheckpoint(models.Model):
	"""Simple checkpoint to allow resuming long-running imports.

	Use a named checkpoint so multiple imports can be tracked if needed.
	"""
	name = models.CharField(max_length=100, unique=True)
	next_index = models.BigIntegerField(default=0)
	total = models.BigIntegerField(null=True, blank=True)
	updated_at = models.DateTimeField(auto_now=True)

	def __str__(self) -> str:
		return f"{self.name}: next_index={self.next_index} total={self.total}"
