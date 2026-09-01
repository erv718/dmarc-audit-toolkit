-- Mail that failed DMARC but was NOT classified as spam: your local
-- overrides (approved sender lists, routing rules, allowlists) masking
-- failures that every outside receiver still sees. These senders break
-- silently for the rest of the world when you move to quarantine or reject.
--
-- disposition: 1 = not spam, 2 = spam, 3 = phishing, 4 = suspicious, 5 = malware

SELECT
  gmail.message_info.source.from_header_address                        AS header_from,
  SPLIT(gmail.message_info.source.address, '@')[SAFE_OFFSET(1)]        AS envelope_domain,
  gmail.message_info.subject                                           AS subject,
  gmail.message_info.spam_info.disposition                             AS disposition,
  ARRAY_TO_STRING(
    ARRAY(SELECT r.rule_name
          FROM UNNEST(gmail.message_info.triggered_rule_info) AS r
          WHERE r.rule_name IS NOT NULL), '; ')                        AS triggered_rules
FROM `YOUR_PROJECT.YOUR_DATASET.activity`
WHERE TIMESTAMP_MICROS(time_usec) >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
  AND ENDS_WITH(gmail.message_info.source.from_header_address, '@example.com')
  AND IFNULL(gmail.message_info.connection_info.dmarc_pass, FALSE) = FALSE
  AND IFNULL(gmail.message_info.spam_info.disposition, 1) = 1
ORDER BY header_from, subject
