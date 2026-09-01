-- Sender census: every envelope domain sending as your header-from domain,
-- with authentication pass rates. This is the inventory that decides which
-- vendors need DKIM before you ratchet policy.

SELECT
  SPLIT(gmail.message_info.source.address, '@')[SAFE_OFFSET(1)]        AS envelope_domain,
  COUNT(DISTINCT gmail.message_info.rfc2822_message_id)                AS messages,
  COUNTIF(gmail.message_info.connection_info.spf_pass)                 AS spf_pass_rows,
  COUNTIF(gmail.message_info.connection_info.dkim_pass)                AS dkim_pass_rows,
  COUNTIF(gmail.message_info.connection_info.dmarc_pass)               AS dmarc_pass_rows,
  COUNT(*)                                                             AS total_rows,
  ANY_VALUE(gmail.message_info.subject)                                AS sample_subject
FROM `YOUR_PROJECT.YOUR_DATASET.activity`
WHERE TIMESTAMP_MICROS(time_usec) >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
  AND ENDS_WITH(gmail.message_info.source.from_header_address, '@example.com')
GROUP BY envelope_domain
ORDER BY messages DESC
