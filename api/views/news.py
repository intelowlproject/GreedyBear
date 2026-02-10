from rest_framework.decorators import api_view
from rest_framework.response import Response

from api.views.utils import get_greedybear_news


@api_view(["GET"])
def news_view(request):
    """
    Fetch GreedyBear blog posts from an RSS feed.

    Filters for posts with "GreedyBear" in the title, truncates long summaries,
    sorts by newest first, and caches results to improve performance.

    Returns:
        List[dict]: Each dict contains title, date, link, and subtext.
        Returns an empty list if no relevant posts are found or feed fails.
    """
    news_list = get_greedybear_news()
    return Response(news_list)
