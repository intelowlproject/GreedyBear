# Tor Exit Nodes Feature

## Overview

The Tor Exit Nodes feature automatically extracts and monitors Tor exit node IP addresses from the official Tor Project source. This helps identify traffic originating from Tor exit nodes, which is useful for threat intelligence and network security analysis.

## Purpose

- **Automatic Extraction**: Downloads the official Tor exit address list periodically
- **IOC Enrichment**: Tags known IOCs with `ip_reputation = "tor exit node"`
- **Feed Exclusion**: Tor exit nodes are excluded from generated threat feeds (by default)
- **Attack Attribution**: Helps identify attacks coming through Tor networks

## How It Works

### Components

#### 1. **TorExitNodes Model** (`greedybear/models.py`)
```python
class TorExitNodes(models.Model):
    ip_address: IP address of the Tor exit node
    added: Timestamp when the IP was first added to the database
```

#### 2. **TorExitNodesCron Job** (`greedybear/cronjobs/tor_exit_nodes.py`)
- Fetches data from: `https://check.torproject.org/exit-addresses`
- Extracts IP addresses using regex pattern matching
- Deduplicates entries to avoid redundant storage
- Updates existing IOC records with `ip_reputation = "tor exit node"`

#### 3. **Celery Task** (`greedybear/tasks.py`)
- `get_tor_exit_nodes()`: Scheduled periodic task that triggers the cronjob
- Can be configured to run at desired intervals (e.g., every 6 hours)

### Data Flow

```
Tor Project Website
    ↓ (download)
TorExitNodesCron.run()
    ↓ (extract & deduplicate)
TorExitNodes Database Table
    ↓ (tag existing)
IOC Records (ip_reputation updated)
    ↓ (exclude)
Generated Threat Feeds
```

## Configuration

### Scheduling
The cronjob is executed by a Celery periodic task. To configure the execution schedule, update the Celery beat schedule in `settings.py`:

```python
CELERY_BEAT_SCHEDULE = {
    'get_tor_exit_nodes': {
        'task': 'greedybear.tasks.get_tor_exit_nodes',
        'schedule': crontab(hour='*/6'),  # Run every 6 hours
    },
}
```

## Database

### Table Structure
- **ip_address**: CharField(max_length=256) - The Tor exit node IP
- **added**: DateTimeField - When the entry was first recorded
- **Index**: On `ip_address` field for fast lookups

### Migration
- Migration file: `greedybear/migrations/0026_torexitnodes.py`

## Testing

Comprehensive test coverage is provided in `tests/greedybear/cronjobs/test_tor_exit_nodes.py`:

1. **test_run**: Basic functionality test - verifies IPs are extracted and stored
2. **test_run_with_duplicate_ips**: Ensures deduplication works correctly
3. **test_ioc_updated_on_new_tor_node**: Verifies IOC records are tagged appropriately
4. **test_run_empty_response**: Handles edge case of empty response gracefully

### Running Tests
```bash
python manage.py test tests.greedybear.cronjobs.test_tor_exit_nodes
```

## Implementation Details

### Data Source
- **Official Tor Project**: `https://check.torproject.org/exit-addresses`
- **Format**: Plain text with structured data about exit nodes
- **Reliability**: Maintained by The Tor Project, updated regularly

### Extraction Pattern
Uses regex pattern to extract IPv4 addresses:
```
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
```

### Error Handling
- Network timeouts: 10-second timeout on HTTP requests
- HTTP errors: Raises exception if download fails (logged and handled by Celery)
- Missing IOC records: Gracefully skips updating non-existent IOCs

## Related Issues
- Closes #547: Add automatic Tor Exit Nodes extraction

## Future Enhancements
- IPv6 support for Tor exit nodes
- Additional metadata from Tor Project API (exit policies, flags)
- Configurable feed exclusion rules
- Webhook notifications for new Tor exit nodes
