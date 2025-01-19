from django.db.models import QuerySet


class SerializerOptimizeMixin:
    prefetch_related: list[str] = []
    select_related: list[str] = []
    only_fields: list[str] = []
    exclude_fields: list[str] = []

    def optimize_qs(self, _: QuerySet) -> QuerySet:
        if self.prefetch_related:
            _ = _.prefetch_related(self.prefetch_related)
        if self.select_related:
            _ = _.select_related(self.select_related)
        if self.only_fields:
            _ = _.only(self.only_fields)
        if self.exclude_fields:
            _ = _.defer(self.exclude_fields)
        return _