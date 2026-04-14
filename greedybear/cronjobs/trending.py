from collections.abc import Mapping

AttackerCounts = Mapping[str, int]
AttackerRank = int | None
RankedAttacker = dict[str, str | int | float | None]

UNRANKED_ATTACKER_SORT_ORDER = 10**9


def _rank_map(sorted_counts: list[tuple[str, int]]) -> dict[str, int]:
    return {attacker_ip: rank for rank, (attacker_ip, _) in enumerate(sorted_counts, start=1)}


def growth_score(current_count: int, previous_count: int) -> float:
    if previous_count == 0:
        return round(float(current_count), 4)
    return round((current_count - previous_count) / previous_count, 4)


def rank_delta(current_rank: int | None, previous_rank: int | None) -> int | None:
    if current_rank is not None and previous_rank is not None:
        return previous_rank - current_rank
    if current_rank is None and previous_rank is not None:
        return -previous_rank
    return None


def attacker_sort_tuple(
    attacker_ip: str,
    current_rank: AttackerRank,
    current_count: int,
    previous_count: int,
) -> tuple[bool, int, int, int, str]:
    return (
        current_rank is None,
        current_rank or UNRANKED_ATTACKER_SORT_ORDER,
        -(current_count - previous_count),
        -previous_count,
        attacker_ip,
    )


def _ranked_attacker(
    attacker_ip: str,
    current_rank: AttackerRank,
    previous_rank: AttackerRank,
    current_count: int,
    previous_count: int,
) -> RankedAttacker:
    return {
        "attacker_ip": attacker_ip,
        "current_interactions": current_count,
        "previous_interactions": previous_count,
        "interaction_delta": current_count - previous_count,
        "growth_score": growth_score(current_count, previous_count),
        "current_rank": current_rank,
        "previous_rank": previous_rank,
        "rank_delta": rank_delta(current_rank, previous_rank),
    }


def build_ranked_attackers(current_counts: AttackerCounts, previous_counts: AttackerCounts, limit: int) -> list[RankedAttacker]:
    sorted_current = sorted(current_counts.items(), key=lambda item: (-item[1], item[0]))
    sorted_previous = sorted(previous_counts.items(), key=lambda item: (-item[1], item[0]))

    current_ranks = _rank_map(sorted_current)
    previous_ranks = _rank_map(sorted_previous)

    candidate_ips = {ip for ip, _ in sorted_current[:limit]}
    candidate_ips |= {ip for ip, _ in sorted_previous[:limit]}

    previous_rank_offset = 1

    def _effective_rank(attacker_ip: str) -> int:
        current_rank = current_ranks.get(attacker_ip)
        if current_rank is not None:
            return current_rank

        previous_rank = previous_ranks.get(attacker_ip)
        if previous_rank is not None:
            return previous_rank + previous_rank_offset

        return UNRANKED_ATTACKER_SORT_ORDER

    sorted_ips = sorted(
        candidate_ips,
        key=lambda attacker_ip: (
            _effective_rank(attacker_ip),
            -(current_counts.get(attacker_ip, 0) - previous_counts.get(attacker_ip, 0)),
            -previous_counts.get(attacker_ip, 0),
            attacker_ip,
        ),
    )[:limit]

    return [
        _ranked_attacker(
            attacker_ip,
            current_ranks.get(attacker_ip),
            previous_ranks.get(attacker_ip),
            current_counts.get(attacker_ip, 0),
            previous_counts.get(attacker_ip, 0),
        )
        for attacker_ip in sorted_ips
    ]


def validate_window_minutes(window_minutes: int, max_window_minutes: int) -> int:
    if window_minutes > max_window_minutes:
        raise ValueError(f"window_minutes cannot be greater than {max_window_minutes}")
    if window_minutes % 60 != 0:
        raise ValueError("window_minutes must be a multiple of 60")
    return window_minutes
