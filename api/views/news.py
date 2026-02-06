from rest_framework.decorators import api_view
from rest_framework.response import Response

from api.views.utils import get_greedybear_news


@api_view(["GET"])
def news_view(request):
    """
    Fetch and return a list of GreedyBear-related blog posts.

    This endpoint retrieves blog entries from the intelowlproject.github.io repository
    via the GitHub API. It filters for GreedyBear-specific content based on titles
    to ensure the news widget remains relevant.

    Caching Strategy:
        To mitigate GitHub's rate limits and optimize performance, responses are
        cached for one hour. This reduces average latency from ~7 seconds to
        approximately 162ms.

    Returns:
        Response: A JSON list of dictionaries containing title, date, link, and subtext.
    """
    news_list = get_greedybear_news()
    return Response(news_list)
