import sys

from django.test.runner import DiscoverRunner


class CustomTestRunner(DiscoverRunner):
    def __init__(self, *args, **kwargs):
        kwargs = self.migration_test_config(kwargs)
        super().__init__(*args, **kwargs)

    def migration_test_config(self, kwargs):
        "Detects if migration tests are requested and updates exclude_tags."
        migration_requested = "--tag=migration" in sys.argv or any("test_migrations" in arg for arg in sys.argv)

        if migration_requested:
            print("\nRunning migration tests\n")
        else:
            current_exclude_tags = kwargs.get("exclude_tags") or set()
            if not isinstance(current_exclude_tags, set):
                current_exclude_tags = set(current_exclude_tags)
            current_exclude_tags.add("migration")
            kwargs["exclude_tags"] = current_exclude_tags
            print("\nAuto-excluding migration tests (use --tag=migration to run them)\n")

        return kwargs
