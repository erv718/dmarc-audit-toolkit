-- Subdomain health: authentication posture for every subdomain seen in the
-- header-from, apex included. Subdomains you forgot about are the ones
-- attackers use once the apex is enforced.

SELECT
  SPLIT(gmail.message_info.source.from_header_address, '@')[SAFE_OFFSET(1)] AS from_domain,
  COUNT(DISTINCT gmail.message_info.rfc2822_message_id)                     AS messages,
  COUNTIF(gmail.message_info.connection_info.dmarc_pass)                    AS dmarc_pass_rows,
  COUNTIF(IFNULL(gmail.message_info.connection_info.dmarc_pass, FALSE) = FALSE) AS dmarc_fail_rows,
  COUNTIF(gmail.message_info.is_spam)                                       AS marked_spam_rows
FROM `YOUR_PROJECT.YOUR_DATASET.activity`
WHERE TIMESTAMP_MICROS(time_usec) >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
  AND REGEXP_CONTAINS(gmail.message_info.source.from_header_address,
                      r'@([a-z0-9-]+\.)*example\.com$')
GROUP BY from_domain
ORDER BY messages DESC
