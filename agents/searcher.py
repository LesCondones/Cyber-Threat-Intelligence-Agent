"""
Web Search Agent

Uses Tavily API for advanced web search with full content extraction.
Returns complete article content (not just snippets) via include_raw_content,
giving downstream agents real source material to ground their analysis in.

Results are cached locally (SQLite, 7-day TTL) keyed by (query, max_results)
so repeat investigations don't re-hit Tavily and re-feed the LLM the same
content.
"""

import time
import logging
from dataclasses import dataclass, field
from tavily import TavilyClient
from typing import List
from config import settings
from database.search_cache import SearchCache

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

    Fetches full page content via include_raw_content=True so downstream
    analysis is grounded in actual source material rather than brief
    snippets. Results are cached locally to avoid re-querying Tavily for
    the same query within the cache TTL.
    """
    client: TavilyClient = field(
        default_factory=lambda: TavilyClient(api_key=settings.tavily_api_key)
    )
    cache: SearchCache = field(default_factory=SearchCache)
    max_retries: int = 3

    @staticmethod
    def _to_search_result(raw: dict) -> SearchResult:
        return SearchResult(
            title=raw.get("title", ""),
            url=raw.get("url", ""),
            content=raw.get("content", ""),
            raw_content=raw.get("raw_content", "") or "",
            score=raw.get("score", 0.0),
        )

    def search(self, query: str, max_results: int = 5) -> List[SearchResult]:
        """
        Search the web and return results with full content.

        Hits the local cache first. On miss, calls Tavily with exponential
        backoff retry and persists the response.
        """
        cached = self.cache.get(query, max_results)
        if cached is not None:
            logger.info(f"Search cache hit: '{query}'")
            return [self._to_search_result(r) for r in cached]

        for attempt in range(self.max_retries):
            try:
                response = self.client.search(
                    query=query,
                    search_depth="advanced",
                    max_results=max_results,
                    include_raw_content=True,
                )

                raw_results = response.get("results", [])
                self.cache.set(query, max_results, raw_results)
                return [self._to_search_result(r) for r in raw_results]
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
