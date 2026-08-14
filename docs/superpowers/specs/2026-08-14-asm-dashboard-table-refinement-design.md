# ASM Dashboard Table Refinement Design

## Goal

Refine the Streamlit dashboard list and trend interactions based on product review feedback.

## Requirements

- Exposure trend x-axis must render at day granularity.
- Page selector must be displayed below the list, not above it.
- The list must not use an internal vertical scroll container for the 200 rows on a page.
- Each finding row must have an expander-style control.
- Expanded row content must show the full scan/finding detail payload.
- Expanded current-status rows must include a whitelist action and reason/operator confirmation form.
- Endpoint Name must display as plain URL text while remaining clickable. It must not display markdown syntax such as `[url](url)`.
- Add a Wiz Link column. The visible text must be `Wiz Link`, linked to the row's `wiz_link` value.
- Historical Results should use the same row display style but without whitelist actions.

## Design

Replace the `st.dataframe` row-selection table with a Streamlit-native list made from lightweight row summaries and `st.expander` detail sections. Keep pagination at 200 rows per page and render the complete page directly without dataframe height scrolling. Use markdown links in row summaries with plain visible labels: endpoint URL as its own visible text and `Wiz Link` as the fixed Wiz label.

Add pure helper functions for link formatting and row view-model creation so formatting can be tested without Streamlit. Trend chart rendering will explicitly set the x-axis type and daily tick interval.

## Testing

Add unit tests for:

- Endpoint link markdown uses the URL as visible text.
- Wiz link markdown uses `Wiz Link` as visible text.
- Table row view models include endpoint and Wiz links.
- App module still imports and path-startup behavior still works.

Run the full unit suite before committing.
