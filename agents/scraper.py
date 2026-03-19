"""
Web Scraper Agent

Uses LangChain's WebBaseLoader for fetching and extracting content from
specific URLs (threat reports, vendor advisories, CVE pages, etc.).

This supplements the Tavily search — Tavily finds relevant pages, the scraper
can fetch additional URLs discovered during analysis.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List

from langchain_community.document_loaders import WebBaseLoader

logger = logging.getLogger(__name__)


@dataclass
class ScrapedPage:
    """Result of scraping a web page."""
    url: str
    title: str
    content: str
    success: bool
    error: str = ""


@dataclass
class WebScraper:
    """
    Fetches and extracts clean text from web pages using LangChain's WebBaseLoader.

    WebBaseLoader uses BeautifulSoup under the hood for HTML parsing and
    text extraction. Results are cached within a session.
    """
    max_content_length: int = 50000
    _cache: Dict[str, ScrapedPage] = field(default_factory=dict)

    def scrape(self, url: str) -> ScrapedPage:
        """Fetch and extract text from a single URL."""
        if url in self._cache:
            return self._cache[url]

        try:
            loader = WebBaseLoader(
                web_paths=[url],
                requests_kwargs={"timeout": 20},
            )
            docs = loader.load()

            if docs and docs[0].page_content:
                content = docs[0].page_content.strip()
                if len(content) > self.max_content_length:
                    content = content[:self.max_content_length] + "\n\n[Content truncated]"

                title = docs[0].metadata.get("title", url)
                result = ScrapedPage(
                    url=url, title=title, content=content, success=True
                )
            else:
                result = ScrapedPage(
                    url=url, title="", content="",
                    success=False, error="No content extracted"
                )

        except Exception as e:
            result = ScrapedPage(
                url=url, title="", content="",
                success=False, error=str(e)[:200]
            )

        self._cache[url] = result
        return result

    def scrape_many(self, urls: List[str], max_pages: int = 10) -> List[ScrapedPage]:
        """Scrape multiple URLs, returning results for all that succeed."""
        results = []
        for url in urls[:max_pages]:
            page = self.scrape(url)
            if page.success:
                results.append(page)
            else:
                logger.debug(f"Scrape failed for {url}: {page.error}")
        return results
