"""
Web Search Agent

Uses Tavily API for advanced web search with full content extraction.
Returns complete article content (not just snippets) via include_raw_content,
giving downstream agents real source material to ground their analysis in.
"""

import time
import logging
from dataclasses import dataclass, field
from tavily import TavilyClient
from typing import List
from config import settings

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """Web search result with full content."""
    title: str
    url: str
    content: str       # Tavily snippet (always available)
    raw_content: str   # Full page content (from include_raw_content)
    score: float = 0.0


@dataclass
class WebSearcher:
    """
    Agent for web search using Tavily API.

    Fetches full page content via include_raw_content="markdown" so
    downstream analysis is grounded in actual source material rather
    than brief snippets.
    """
    client: TavilyClient = field(
        default_factory=lambda: TavilyClient(api_key=settings.tavily_api_key)
    )
    max_retries: int = 3

    def search(self, query: str, max_results: int = 5) -> List[SearchResult]:
        """
        Search the web and return results with full content.

        Retries on failure with exponential backoff.
        """
        for attempt in range(self.max_retries):
            try:
                response = self.client.search(
                    query=query,
                    search_depth="advanced",
                    max_results=max_results,
                    include_raw_content=True,
                )

                return [
                    SearchResult(
                        title=result.get("title", ""),
                        url=result.get("url", ""),
                        content=result.get("content", ""),
                        raw_content=result.get("raw_content", "") or "",
                        score=result.get("score", 0.0),
                    )
                    for result in response.get("results", [])
                ]
            except Exception as e:
                wait = 2 ** attempt
                logger.warning(
                    f"Search failed (attempt {attempt + 1}/{self.max_retries}): {e}. "
                    f"Retrying in {wait}s..."
                )
                if attempt < self.max_retries - 1:
                    time.sleep(wait)

        logger.error(f"Search failed after {self.max_retries} attempts for: {query}")
        return []
