from datetime import date, datetime, timedelta
from functools import cache

import numpy as np
import pandas as pd
from django.contrib.postgres.aggregates import ArrayAgg
from django.db.models import F, Q

from api.views.utils import FeedRequestParams, feeds_response
from greedybear.models import IOC


@cache
def date_delta(earlier_date: str, later_date: str) -> int:
    """
     Calculate number of days between two dates in ISO format.

    Args:
        earlier_date: ISO format date string (YYYY-MM-DD)
        later_date: ISO format date string (YYYY-MM-DD)

    Returns:
        Number of days between dates (positive if later_date is after earlier_date)

    Raises:
       ValueError: If dates are not in ISO format (YYYY-MM-DD)
    """
    try:
        d1 = date.fromisoformat(earlier_date)
        d2 = date.fromisoformat(later_date)
    except ValueError as exc:
        raise ValueError("Dates must be in ISO format (YYYY-MM-DD)") from exc
    return (d2 - d1).days


def correlated_features(df: pd.DataFrame, threshold: float = 0.7) -> list[tuple]:
    """
    Identify highly correlated feature pairs in a DataFrame.

    Args:
        df: Input DataFrame containing the features
        threshold: Minimum absolute correlation value to consider features as highly correlated

    Returns:
        Correlated pairs with correlation > threshold
    """
    corr_matrix = df.corr()
    high_corr_pairs = []
    features = list(df.columns)
    for idx, f1 in enumerate(features):
        for f2 in features[idx + 1 :]:
            if abs(corr_matrix.loc[f1, f2]) > threshold:
                high_corr_pairs.append((f1, f2, corr_matrix.loc[f1, f2]))
    return high_corr_pairs


def get_features(iocs: list[dict], reference_day: str) -> pd.DataFrame:
    """
    Extract and calculate features from IOC data.

    Args:
        iocs: List of IOC dictionaries with required fields
        reference_day: Reference date for time-based calculations

    Returns:
       DataFrame containing metadata and calculated features for each IOC
    """
    result = []
    for ioc in iocs:
        days_seen_count = len(ioc["days_seen"])
        time_diffs = [date_delta(str(a), str(b)) for a, b in zip(ioc["days_seen"], ioc["days_seen"][1:], strict=False)]
        active_timespan = sum(time_diffs) + 1
        result.append(
            {
                # METADATA
                "value": ioc.get("name", ioc["value"]),
                "attack_count": ioc["attack_count"],
                "last_seen": ioc["last_seen"],
                "first_seen": ioc["first_seen"],
                "days_seen": ioc["days_seen"],
                # CATEGORICAL FEATURES
                "asn": str(ioc["asn"]),
                "ip_reputation": ioc["ip_reputation"],
                # MULTI VALUE FEATURES
                "honeypots": ioc["feed_type"],
                # NUMERICAL FEATURES
                "honeypot_count": len(ioc["feed_type"]),
                "destination_port_count": ioc["destination_port_count"],
                "days_seen_count": days_seen_count,
                "active_timespan": active_timespan,
                "active_days_ratio": days_seen_count / active_timespan,
                "login_attempts": ioc["login_attempts"],
                "login_attempts_per_day": ioc["login_attempts"] / days_seen_count,
                "interaction_count": ioc["interaction_count"],
                "interactions_per_day": ioc["interaction_count"] / days_seen_count,
                "avg_days_between": np.mean(time_diffs) if len(time_diffs) > 0 else 1,
                "std_days_between": np.std(time_diffs) if len(time_diffs) > 0 else 0,
                "days_since_last_seen": date_delta(ioc["last_seen"], reference_day),
                "days_since_first_seen": date_delta(ioc["first_seen"], reference_day),
            }
        )
    df = pd.DataFrame(result)
    return df


def multi_label_encode(df: pd.DataFrame, column_name: str) -> pd.DataFrame:
    """
    Convert a column containing lists of values into multiple binary columns.

    For each unique value found across all lists in the specified column, creates a new
    column prefixed with 'has_' containing 1 if the value is present in the list and 0
    if it is not. The original column is dropped.

    Args:
        df: A pandas DataFrame containing the column to encode
        column_name: Name of the column containing lists of values to encode

    Returns:
        DataFrame with the original column replaced by binary columns for each unique value
    """
    result_df = df.copy()
    unique_values = set()
    for value_list in df[column_name]:
        unique_values.update(value_list)
    for value in sorted(unique_values):
        result_df[f"has_{value}"] = df[column_name].apply(lambda x: 1 if value in x else 0)
    return result_df.drop(column_name, axis=1)


def serialize_iocs(iocs: list[dict]) -> list[dict]:
    """
    Serialize IOC values using an API method.

    Args:
        iocs: List of IOC values.

    Returns:
        list: Serialized IOC data including associated honeypot names.
              Processed through feeds_response API method.
    """
    return feeds_response(
        iocs=iocs,
        feed_params=FeedRequestParams({}),  # using defaults from FeedRequestParams
        valid_feed_types={},  # not required as check is skipped due to the verbose argument
        dict_only=True,
        verbose=True,
    )["iocs"]


def get_data_by_pks(primary_keys: set) -> list[dict]:
    """
    Retrieve and serialize IOC data for a collection of primary keys.

    Args:
        primary_keys: A set of IOC primary keys to retrieve from the database.

    Returns:
        list: Serialized IOC data including associated honeypot names.
              Processed through feeds_response API method.
    """
    iocs = (
        IOC.objects.filter(pk__in=primary_keys)
        .prefetch_related("general_honeypot")
        .annotate(value=F("name"))
        .annotate(honeypots=ArrayAgg("general_honeypot__name"))
        .values()
    )
    return serialize_iocs(iocs)


def get_current_data(days_lookback: int = 30) -> list[dict]:
    """
    Get current IOC data for scanners seen in the last N days.

    Retrieves IOCs that:
    - Are scanners
    - Were seen in the specified lookback period
    - Are associated with either Cowrie, Log4j, or active general honeypots

    Args:
        days_lookback: Number of days to look back for last_seen timestamp.
            Defaults to 30 days.

    Returns:
        list: Serialized IOC data including associated honeypot names.
              Processed through feeds_response API method.
    """
    cutoff_date = datetime.now() - timedelta(days=days_lookback)
    query_dict = {
        "last_seen__gte": cutoff_date,
        "scanner": True,
    }
    iocs = (
        IOC.objects.filter(Q(cowrie=True) | Q(log4j=True) | Q(general_honeypot__active=True))
        .filter(**query_dict)
        .prefetch_related("general_honeypot")
        .annotate(value=F("name"))
        .annotate(honeypots=ArrayAgg("general_honeypot__name"))
        .values()
    )
    return serialize_iocs(iocs)
