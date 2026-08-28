<!-- llm-wiki:start -->
## LLM Wiki Routing Policy

This repository has an optional LLM wiki, not a mandatory pre-read. Use the wiki only when it is
likely to reduce exploration cost or provide durable context that is not obvious from code.

Before reading wiki pages:

1. Inspect only `wiki/context-router.json` when it exists.
2. If the router has a high- or medium-confidence route matching the task, read only the wiki pages
   listed in that route.
3. If the router is missing, use `wiki/map.md` only for onboarding, architecture, design, contract,
   operations, or broad repo-understanding tasks.
4. For localized code changes, exact file/function requests, stack traces, cosmetic edits, and
   test-only fixes, skip wiki unless the router has a high-confidence match.
5. For partial routes, skim only the routed page and then inspect source code.
6. Always verify important wiki claims against the source files before editing.
7. If code contradicts the wiki, trust the code for implementation and flag the wiki drift.
8. If code changes make the wiki stale, run or recommend the relevant llm-wiki refresh or update
   workflow for the current host before the work is considered complete.

Do not read `wiki/index.md`, `wiki/map.md`, or wiki content pages by default. If no router route
matches the task, go directly to the smallest relevant source files.
<!-- llm-wiki:end -->
