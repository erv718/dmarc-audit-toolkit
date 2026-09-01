-- Genuine DMARC failures, deduplicated (Gmail logs in BigQuery).
-- A message counts as failing only if NO log row for the same
-- (rfc2822_message_id, recipient) pair passed DMARC. Counting raw rows
-- overstates failures: forwarding, Google Groups redistribution, and
-- multi-event logging all produce extra rows for mail that already
-- authenticated on another leg.
--
-- Table: the unified Workspace logs export (`<dataset>.activity`).
-- Legacy Gmail-only export: swap the table for your daily tables and
-- verify the field prefix against your schema.

WITH legs AS (
  SELECT
    gmail.message_info.rfc2822_message_id                              AS msg_id,
    d.address                                                          AS recipient,
    SPLIT(gmail.message_info.source.address, '@')[SAFE_OFFSET(1)]      AS envelope_domain,
    gmail.message_info.source.from_header_address                      AS header_from,
    gmail.message_info.connection_info.dmarc_pass                      AS dmarc_pass
  FROM `YOUR_PROJECT.YOUR_DATASET.activity`,
       UNNEST(gmail.message_info.destination) AS d
  WHERE TIMESTAMP_MICROS(time_usec) >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
    AND ENDS_WITH(gmail.message_info.source.from_header_address, '@example.com')
    AND gmail.message_info.rfc2822_message_id IS NOT NULL
)
SELECT
  msg_id,
  recipient,
  ANY_VALUE(envelope_domain)               AS envelope_domain,
  ANY_VALUE(header_from)                   AS header_from,
  COUNT(*)                                 AS legs,
  LOGICAL_OR(IFNULL(dmarc_pass, FALSE))    AS any_leg_passed
FROM legs
GROUP BY msg_id, recipient
HAVING NOT any_leg_passed
ORDER BY msg_id
