from collections.abc import Mapping


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


def attacker_sort_tuple(attacker_ip: str, current_rank: int | None, current_count: int, previous_count: int):
    return (current_rank is None, current_rank or 10**9, -(current_count - previous_count), -previous_count, attacker_ip)


def build_ranked_attackers(current_counts: Mapping[str, int], previous_counts: Mapping[str, int], limit: int) -> list[dict]:
    sorted_current = sorted(current_counts.items(), key=lambda item: (-item[1], item[0]))
    sorted_previous = sorted(previous_counts.items(), key=lambda item: (-item[1], item[0]))

    current_ranks = _rank_map(sorted_current)
    previous_ranks = _rank_map(sorted_previous)

    candidate_ips = {ip for ip, _ in sorted_current[:limit]}
    candidate_ips |= {ip for ip, _ in sorted_previous[:limit]}

    sorted_ips = sorted(
        candidate_ips,
        key=lambda attacker_ip: attacker_sort_tuple(
            attacker_ip,
            current_ranks.get(attacker_ip),
            current_counts.get(attacker_ip, 0),
            previous_counts.get(attacker_ip, 0),
        ),
    )[:limit]

    attackers = []
    for attacker_ip in sorted_ips:
        current_rank = current_ranks.get(attacker_ip)
        previous_rank = previous_ranks.get(attacker_ip)
        current_count = current_counts.get(attacker_ip, 0)
        previous_count = previous_counts.get(attacker_ip, 0)

        attackers.append(
            {
                "attacker_ip": attacker_ip,
                "current_interactions": current_count,
                "previous_interactions": previous_count,
                "interaction_delta": current_count - previous_count,
                "growth_score": growth_score(current_count, previous_count),
                "current_rank": current_rank,
                "previous_rank": previous_rank,
                "rank_delta": rank_delta(current_rank, previous_rank),
            }
        )

    return attackers
