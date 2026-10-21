CREATE TABLE issuers (
    issuer_code TEXT PRIMARY KEY,
    issuer_name TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    exempt_org INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE rule_thresholds (
    jurisdiction TEXT NOT NULL,
    txn_type TEXT NOT NULL,
    threshold_cents INTEGER NOT NULL,
    cross_border_rate_num INTEGER NOT NULL DEFAULT 1,
    cross_border_rate_den INTEGER NOT NULL DEFAULT 1,
    retail_rate_num INTEGER NOT NULL DEFAULT 1,
    retail_rate_den INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (jurisdiction, txn_type)
);

CREATE TABLE issuer_rule_overrides (
    issuer_code TEXT NOT NULL,
    jurisdiction TEXT NOT NULL,
    txn_type TEXT NOT NULL,
    threshold_cents INTEGER NOT NULL,
    cross_border_rate_num INTEGER NOT NULL DEFAULT 1,
    cross_border_rate_den INTEGER NOT NULL DEFAULT 1,
    retail_rate_num INTEGER NOT NULL DEFAULT 1,
    retail_rate_den INTEGER NOT NULL DEFAULT 1,
    effective_from TEXT NOT NULL DEFAULT '00000000',
    PRIMARY KEY (issuer_code, jurisdiction, txn_type, effective_from)
);

CREATE TABLE sample_filings (
    id INTEGER PRIMARY KEY,
    encoded_payload TEXT NOT NULL,
    note TEXT
);

CREATE TABLE accepted_fragments (
    sample_id INTEGER NOT NULL,
    json_key TEXT NOT NULL,
    json_value TEXT NOT NULL,
    FOREIGN KEY (sample_id) REFERENCES sample_filings(id)
);

INSERT INTO issuers (issuer_code, issuer_name, entity_type, exempt_org) VALUES
    ('ACME', 'Acme Capital Markets', 'BROKER_DEALER', 0),
    ('GLBL', 'Global Reserve Trust', 'CENTRAL_BANK', 1),
    ('NDEX', 'Nordic Exchange Clearing', 'CLEARINGHOUSE', 0),
    ('TORQ', 'Torque Asset Management', 'ASSET_MANAGER', 0),
    ('VESTA', 'Vesta Pension Holdings', 'PENSION_FUND', 1),
    ('QURO', 'Quorum Reserve Corp', 'ASSET_MANAGER', 0);

INSERT INTO rule_thresholds (jurisdiction, txn_type, threshold_cents,
                             cross_border_rate_num, cross_border_rate_den,
                             retail_rate_num, retail_rate_den) VALUES
    ('US', 'S',    1000000,  1,  2,  3, 4),
    ('US', 'P',    1000000,  1,  2,  3, 4),
    ('US', 'T',     500000,  2,  5,  1, 2),
    ('US', 'D',    2500000,  1,  2,  5, 8),
    ('EU', 'S',    1500000,  3,  5,  3, 4),
    ('EU', 'P',    1500000,  3,  5,  3, 4),
    ('EU', 'T',     750000,  1,  2,  1, 2),
    ('EU', 'D',    3000000,  3,  5,  5, 8),
    ('UK', 'S',    1200000,  1,  2,  3, 4),
    ('UK', 'P',    1200000,  1,  2,  3, 4),
    ('UK', 'T',     600000,  1,  2,  1, 2),
    ('UK', 'D',    2800000, 11, 20,  5, 8),
    ('SG', 'S',     800000,  3,  4,  7, 8),
    ('SG', 'P',     800000,  3,  4,  7, 8),
    ('SG', 'T',     400000,  3,  4,  1, 2),
    ('SG', 'D',    2000000,  3,  4,  5, 8),
    ('JP', 'S',    1000001,  1,  2,  3, 4),
    ('JP', 'P',    1000001,  3,  4,  2, 3),
    ('JP', 'D', 5201290650, 69,100,  1, 2);

INSERT INTO issuer_rule_overrides (issuer_code, jurisdiction, txn_type, threshold_cents,
                                   cross_border_rate_num, cross_border_rate_den,
                                   retail_rate_num, retail_rate_den) VALUES
    ('TORQ', 'US', 'D', 1200000, 9, 20, 7, 8);

INSERT INTO issuer_rule_overrides (issuer_code, jurisdiction, txn_type, threshold_cents,
                                   cross_border_rate_num, cross_border_rate_den,
                                   retail_rate_num, retail_rate_den, effective_from) VALUES
    ('QURO', 'US', 'D',  900000,  1,  4,  3,  8, '20250101'),
    ('QURO', 'US', 'D',  950001, 11, 20,  7, 16, '20260301'),
    ('QURO', 'US', 'D', 1000000,  3,  8,  9, 16, '20260901');

INSERT INTO sample_filings (id, encoded_payload, note) VALUES
    (1, 'RPT7,ACME,US,S,1000000,20260115,00,31', 'ACME sale in US/S at 1000000, flags 00'),
    (2, 'RPT7,ACME,US,S,999999,20260115,00,36', 'ACME sale in US/S at 999999, flags 00'),
    (3, 'RPT7,GLBL,US,S,5000000,20260115,00,46', 'GLBL sale in US/S at 5000000, flags 00'),
    (4, 'RPT7,NDEX,EU,T,375000,20260201,04,09', 'NDEX transfer in EU/T at 375000, flags 04'),
    (5, 'RPT7,TORQ,SG,D,100,20260305,08,61', 'TORQ deposit in SG/D at 100, flags 08'),
    (6, 'RPT7,TORQ,US,D,1500000,20260410,00,67', 'TORQ deposit in US/D at 1500000, flags 00'),
    (7, 'RPT7,TORQ,US,D,1199999,20260410,00,11', 'TORQ deposit in US/D at 1199999, flags 00'),
    (8, 'RPT7,ACME,US,S,5000000,20260512,01,37', 'ACME sale in US/S at 5000000, flags 01'),
    (9, 'RPT7,GLBL,US,S,1,20260512,09,55', 'GLBL sale in US/S at 1, flags 09'),
    (10, 'RPT7,ACME,US,S,-2000000,20260601,00,77', 'ACME sale in US/S, amount written with a leading minus sign'),
    (11, 'RPT7,ACME,US,S,(2000000),20260601,00,77', 'ACME sale in US/S, same amount written in parentheses'),
    (12, 'RPT7,NDEX,UK,D,1540000,20260615,04,51', 'NDEX deposit in UK/D at 1540000, flags 04'),
    (13, 'RPT7,TORQ,US,P,1000000,20260701,02,79', 'TORQ purchase in US/P at 1000000, flags 02'),
    (14, 'RPT7,NDEX,SG,T,400000,20260715,00,04', 'NDEX transfer in SG/T at 400000, flags 00'),
    (15, 'RPT7,ACME,EU,P,1499999,20260801,00,65', 'ACME purchase in EU/P at 1499999, flags 00'),
    (16, 'RPT7,VESTA,UK,S,5000000,20260815,02,48', 'VESTA sale in UK/S at 5000000, flags 02'),
    (17, 'RPT7,ACME,JP,S,375001,20260901,06,90', 'ACME sale in JP/S at 375001, flags 06'),
    (18, 'RPT7,ACME,JP,S,375000,20260901,06,89', 'ACME sale in JP/S at 375000, flags 06'),
    (19, 'RPT7,ACME,JP,S,750000,20260901,02,82', 'ACME sale in JP/S at 750000, flags 02'),
    (20, 'RPT7,TORQ,US,D,1050000,20260901,02,74', 'TORQ deposit in US/D at 1050000, flags 02'),
    (21, 'RPT7,ACME,US,D,1500000,20260901,00,24', 'ACME deposit in US/D at 1500000, flags 00'),
    (22, 'RPT7,ACME,JP,D,3588890549,20261001,04,09', 'ACME deposit in JP/D at 3588890549, flags 04'),
    (23, 'RPT7,ACME,JP,D,3588890548,20261001,04,08', 'ACME deposit in JP/D at 3588890548, flags 04'),
    (24, 'RPT7,QURO,US,D,2500000,20241231,00,69', 'QURO deposit in US/D at 2500000, before any QURO override has started'),
    (25, 'RPT7,QURO,US,D,2499999,20241231,00,16', 'QURO deposit in US/D at 2499999, before any QURO override has started'),
    (26, 'RPT7,QURO,US,D,900000,20250101,00,19', 'QURO deposit in US/D at 900000, exactly on the first override version start date'),
    (27, 'RPT7,QURO,US,D,899999,20250615,00,73', 'QURO deposit in US/D at 899999, midway through the first override version'),
    (28, 'RPT7,QURO,US,D,950001,20260301,00,28', 'QURO deposit in US/D at 950001, exactly on the second override version start date'),
    (29, 'RPT7,QURO,US,D,950000,20260601,00,30', 'QURO deposit in US/D at 950000, midway through the second override version'),
    (30, 'RPT7,QURO,US,D,1000000,20260901,00,68', 'QURO deposit in US/D at 1000000, exactly on the third override version start date'),
    (31, 'RPT7,QURO,US,D,999999,20261231,00,70', 'QURO deposit in US/D at 999999, well after the third override version started');

INSERT INTO accepted_fragments (sample_id, json_key, json_value) VALUES
    (1, 'filing_date', '2026-01-15'),
    (12, 'filing_date', '2026-06-15'),
    (1, 'reportable', 'true'),
    (2, 'reportable', 'false'),
    (3, 'reportable', 'false'),
    (3, 'exempt', 'true'),
    (4, 'reportable', 'true'),
    (4, 'cross_border', 'true'),
    (5, 'reportable', 'true'),
    (5, 'manual_review', 'true'),
    (5, 'threshold_cents', '2000000'),
    (6, 'reportable', 'true'),
    (6, 'threshold_cents', '1200000'),
    (7, 'reportable', 'false'),
    (7, 'threshold_cents', '1200000'),
    (8, 'reportable', 'false'),
    (8, 'exempt', 'true'),
    (9, 'reportable', 'true'),
    (9, 'exempt', 'true'),
    (9, 'manual_review', 'true'),
    (10, 'reportable', 'true'),
    (10, 'amount_cents', '-2000000'),
    (11, 'reportable', 'true'),
    (11, 'amount_cents', '-2000000'),
    (12, 'reportable', 'true'),
    (12, 'cross_border', 'true'),
    (12, 'threshold_cents', '1540000'),
    (13, 'reportable', 'true'),
    (13, 'retail', 'true'),
    (13, 'threshold_cents', '750000'),
    (14, 'reportable', 'true'),
    (15, 'reportable', 'false'),
    (16, 'reportable', 'false'),
    (16, 'exempt', 'true'),
    (16, 'retail', 'true'),
    (16, 'threshold_cents', '900000'),
    (17, 'threshold_cents', '375001'),
    (17, 'reportable', 'true'),
    (18, 'threshold_cents', '375001'),
    (18, 'reportable', 'false'),
    (19, 'threshold_cents', '750001'),
    (19, 'reportable', 'false'),
    (20, 'threshold_cents', '1050000'),
    (20, 'reportable', 'true'),
    (21, 'threshold_cents', '2500000'),
    (21, 'reportable', 'false'),
    (22, 'threshold_cents', '3588890549'),
    (22, 'reportable', 'true'),
    (23, 'threshold_cents', '3588890549'),
    (23, 'reportable', 'false'),
    (24, 'threshold_cents', '2500000'),
    (24, 'reportable', 'true'),
    (25, 'threshold_cents', '2500000'),
    (25, 'reportable', 'false'),
    (26, 'threshold_cents', '900000'),
    (26, 'reportable', 'true'),
    (27, 'threshold_cents', '900000'),
    (27, 'reportable', 'false'),
    (28, 'threshold_cents', '950001'),
    (28, 'reportable', 'true'),
    (29, 'threshold_cents', '950001'),
    (29, 'reportable', 'false'),
    (30, 'threshold_cents', '1000000'),
    (30, 'reportable', 'true'),
    (31, 'threshold_cents', '1000000'),
    (31, 'reportable', 'false');

INSERT INTO issuers (issuer_code, issuer_name, entity_type, exempt_org)
WITH RECURSIVE seq(n) AS (
    SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 300000
)
SELECT 'IS' || printf('%06d', n),
       'Registered Filer ' || n,
       CASE n % 4
           WHEN 0 THEN 'BROKER_DEALER'
           WHEN 1 THEN 'CLEARINGHOUSE'
           WHEN 2 THEN 'ASSET_MANAGER'
           ELSE 'PENSION_FUND'
       END,
       CASE WHEN n % 9 = 0 THEN 1 ELSE 0 END
FROM seq;

INSERT INTO issuer_rule_overrides (issuer_code, jurisdiction, txn_type, threshold_cents,
                                   cross_border_rate_num, cross_border_rate_den,
                                   retail_rate_num, retail_rate_den)
WITH RECURSIVE seq(n) AS (
    SELECT 0 UNION ALL SELECT n + 1 FROM seq WHERE n < 299999
)
SELECT 'IS' || printf('%06d', (n / 4) + 1),
       CASE n % 4 WHEN 0 THEN 'US' WHEN 1 THEN 'US' WHEN 2 THEN 'EU' ELSE 'EU' END,
       CASE n % 4 WHEN 0 THEN 'S'  WHEN 1 THEN 'D'  WHEN 2 THEN 'S'  ELSE 'D'  END,
       5000000 + n,
       CASE n % 4 WHEN 0 THEN 1 WHEN 1 THEN 1 WHEN 2 THEN 3 ELSE 1 END,
       CASE n % 4 WHEN 0 THEN 2 WHEN 1 THEN 4 WHEN 2 THEN 4 ELSE 2 END,
       CASE n % 4 WHEN 0 THEN 3 WHEN 1 THEN 1 WHEN 2 THEN 7 ELSE 5 END,
       CASE n % 4 WHEN 0 THEN 4 WHEN 1 THEN 2 WHEN 2 THEN 8 ELSE 8 END
FROM seq;

INSERT INTO issuer_rule_overrides (issuer_code, jurisdiction, txn_type, threshold_cents,
                                   cross_border_rate_num, cross_border_rate_den,
                                   retail_rate_num, retail_rate_den) VALUES
    ('IS200000', 'SG', 'T', 5201290650, 69, 100, 1, 2);

INSERT INTO issuer_rule_overrides (issuer_code, jurisdiction, txn_type, threshold_cents,
                                   cross_border_rate_num, cross_border_rate_den,
                                   retail_rate_num, retail_rate_den, effective_from) VALUES
    ('IS050000', 'US', 'S', 5500000, 3, 5, 2, 3, '20260601');
