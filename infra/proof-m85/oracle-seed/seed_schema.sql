-- proof-m85 — first-boot Oracle seed for the M8 governed-agent-loop proof
-- (DEV-ONLY data; deterministic fixtures the bars assert on).
--
-- gvenzl runs every *.sql in /container-entrypoint-initdb.d once, on the first
-- boot of a fresh volume, AFTER the database and the APP_USER (cognic) are set
-- up. These init scripts run as an admin in the root container — NOT as the
-- APP_USER — so we ALTER SESSION INTO XEPDB1 and create everything explicitly
-- (the proof-m6 pattern).
--
-- What this seed builds (spec §6 / plan Task C1):
--
--   1. THREE analytics schemas as NO AUTHENTICATION owners (not directly
--      connectable): RETAIL_ANALYTICS, FIN, CARDS.
--   2. BASE (raw) tables per schema — the objects the governed layer wraps.
--      Raw tables are NEVER granted to any proxy identity: a statement that
--      references one refuses at the tool's object allow-set arm
--      (agent_sql_object_out_of_scope) AND, if it ever reached the engine,
--      at the DB grant layer (ORA-00942 for the proxy session) — BAR 4/4b.
--   3. The EIGHT governed views — the EXACT view names + column sets the four
--      instruction skills teach (each SKILL.md is the authoritative contract):
--        RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS   (scope retail_analytics)
--        RETAIL_ANALYTICS.V_CUSTOMER_PROFILE    (scope retail_analytics)
--        FIN.V_GL_BALANCES                      (scope financials)
--        FIN.V_BRANCH_PNL                       (scope financials)
--        CARDS.V_CARD_ACCOUNTS                  (scope cards_analytics)
--        CARDS.V_CARD_SPEND                     (scope cards_analytics)
--        CARDS.V_ATM_SETTLEMENTS                (scope atm_recon — seeded,
--        CARDS.V_ATM_DISPUTES                    NEVER entitled/granted)
--   4. Deterministic demo rows, including the BAR-1 top-10-depositors fixture
--      (12 depositors with strictly-distinct SUM(BALANCE) totals so "top 10
--      customers by deposit balance this quarter" has ONE right answer; the
--      rank-11 customer must NOT appear).
--   5. PROXY USERS — the data-scope DB identities (ADR-027 §c: the kernel
--      stamps proxy_db_identity from the SCOPE row; the tool opens a DEDICATED
--      Oracle proxy-authenticated connection user="cognic[<identity>]"):
--        AN_AMIR — the retail_analytics + financials scope identity
--        AN_SARA — the cards_analytics scope identity
--      Both are NO AUTHENTICATION (no direct logon; proxy-only through the
--      APP_USER) + GRANT CONNECT THROUGH cognic + CREATE SESSION.
--   6. VIEW-ONLY grants per identity, matching the entitlement matrix:
--        AN_AMIR -> SELECT on the retail + fin views ONLY
--        AN_SARA -> SELECT on the cards + retail views ONLY
--        NOBODY  -> any grant on V_ATM_SETTLEMENTS / V_ATM_DISPUTES or on any
--                   raw table (the atm_recon scope is seeded kernel-side but
--                   never entitled; the DB backstop must refuse too — BAR 4b).
--      The scope row atm_recon carries proxy_db_identity AN_ATM_RECON, which
--      is DELIBERATELY NOT provisioned here: never entitled -> never minted;
--      even a hypothetical token could not open a session (fail-closed).
--
-- SET DEFINE OFF so stray '&' is never treated as a substitution variable;
-- WHENEVER SQLERROR EXIT so any failure aborts loud (never a half-seeded DB).

SET DEFINE OFF
WHENEVER SQLERROR EXIT SQL.SQLCODE

ALTER SESSION SET CONTAINER = XEPDB1;

-- ---------------------------------------------------------------------------
-- 1. Schema owners (NO AUTHENTICATION = schema-only; not directly connectable)
-- ---------------------------------------------------------------------------

CREATE USER retail_analytics NO AUTHENTICATION
    DEFAULT TABLESPACE users QUOTA UNLIMITED ON users;
CREATE USER fin NO AUTHENTICATION
    DEFAULT TABLESPACE users QUOTA UNLIMITED ON users;
CREATE USER cards NO AUTHENTICATION
    DEFAULT TABLESPACE users QUOTA UNLIMITED ON users;

-- ---------------------------------------------------------------------------
-- 2. Base (raw) tables — never granted; the governed views wrap these
-- ---------------------------------------------------------------------------

CREATE TABLE retail_analytics.customers_raw (
    customer_id    NUMBER          NOT NULL,
    customer_name  VARCHAR2(120)   NOT NULL,
    segment        VARCHAR2(20)    NOT NULL,
    branch_code    VARCHAR2(10)    NOT NULL,
    status         VARCHAR2(10)    NOT NULL,
    joined_date    DATE            NOT NULL,
    internal_risk_note VARCHAR2(400),  -- deliberately ungoverned column: raw-only
    CONSTRAINT pk_customers_raw PRIMARY KEY (customer_id),
    CONSTRAINT ck_customers_raw_segment CHECK (segment IN ('RETAIL', 'PREMIER', 'PRIVATE')),
    CONSTRAINT ck_customers_raw_status CHECK (status IN ('ACTIVE', 'DORMANT', 'CLOSED'))
);

CREATE TABLE retail_analytics.deposit_accounts_raw (
    account_id     NUMBER          NOT NULL,
    customer_id    NUMBER          NOT NULL,
    account_type   VARCHAR2(20)    NOT NULL,
    branch_code    VARCHAR2(10)    NOT NULL,
    currency       CHAR(3)         NOT NULL,
    balance        NUMBER(18, 2)   NOT NULL,
    as_of_date     DATE            NOT NULL,
    opened_date    DATE            NOT NULL,
    CONSTRAINT pk_deposit_accounts_raw PRIMARY KEY (account_id),
    CONSTRAINT fk_deposit_accounts_customer
        FOREIGN KEY (customer_id) REFERENCES retail_analytics.customers_raw (customer_id),
    CONSTRAINT ck_deposit_accounts_type CHECK (account_type IN ('SAVINGS', 'CURRENT', 'TERM_DEPOSIT'))
);

CREATE TABLE fin.gl_balances_raw (
    gl_account       VARCHAR2(10)  NOT NULL,
    gl_account_name  VARCHAR2(80)  NOT NULL,
    cost_center      VARCHAR2(10)  NOT NULL,
    period           VARCHAR2(7)   NOT NULL,
    currency         CHAR(3)       NOT NULL,
    opening_balance  NUMBER(18, 2) NOT NULL,
    debits           NUMBER(18, 2) NOT NULL,
    credits          NUMBER(18, 2) NOT NULL,
    closing_balance  NUMBER(18, 2) NOT NULL,
    CONSTRAINT pk_gl_balances_raw PRIMARY KEY (gl_account, cost_center, period)
);

CREATE TABLE fin.branch_pnl_raw (
    branch_code        VARCHAR2(10)  NOT NULL,
    branch_name        VARCHAR2(80)  NOT NULL,
    period             VARCHAR2(7)   NOT NULL,
    interest_income    NUMBER(18, 2) NOT NULL,
    fee_income         NUMBER(18, 2) NOT NULL,
    operating_expense  NUMBER(18, 2) NOT NULL,
    net_income         NUMBER(18, 2) NOT NULL,
    CONSTRAINT pk_branch_pnl_raw PRIMARY KEY (branch_code, period)
);

CREATE TABLE cards.card_accounts_raw (
    card_id       NUMBER         NOT NULL,
    customer_id   NUMBER         NOT NULL,
    product       VARCHAR2(10)   NOT NULL,
    status        VARCHAR2(10)   NOT NULL,
    open_date     DATE           NOT NULL,
    credit_limit  NUMBER(18, 2),
    currency      CHAR(3)        NOT NULL,
    CONSTRAINT pk_card_accounts_raw PRIMARY KEY (card_id),
    CONSTRAINT ck_card_accounts_product CHECK (product IN ('DEBIT', 'CREDIT', 'PREPAID')),
    CONSTRAINT ck_card_accounts_status CHECK (status IN ('ACTIVE', 'BLOCKED', 'CLOSED'))
);

CREATE TABLE cards.card_spend_raw (
    card_id            NUMBER         NOT NULL,
    spend_month        VARCHAR2(7)    NOT NULL,
    merchant_category  VARCHAR2(30)   NOT NULL,
    txn_count          NUMBER         NOT NULL,
    spend_amount       NUMBER(18, 2)  NOT NULL,
    currency           CHAR(3)        NOT NULL,
    CONSTRAINT pk_card_spend_raw PRIMARY KEY (card_id, spend_month, merchant_category),
    CONSTRAINT fk_card_spend_card
        FOREIGN KEY (card_id) REFERENCES cards.card_accounts_raw (card_id)
);

CREATE TABLE cards.atm_settlements_raw (
    atm_id         VARCHAR2(10)   NOT NULL,
    atm_location   VARCHAR2(80)   NOT NULL,
    business_date  DATE           NOT NULL,
    switch_total   NUMBER(18, 2)  NOT NULL,
    gl_total       NUMBER(18, 2)  NOT NULL,
    txn_count      NUMBER         NOT NULL,
    status         VARCHAR2(10)   NOT NULL,
    CONSTRAINT pk_atm_settlements_raw PRIMARY KEY (atm_id, business_date),
    CONSTRAINT ck_atm_settlements_status CHECK (status IN ('MATCHED', 'UNMATCHED'))
);

CREATE TABLE cards.atm_disputes_raw (
    dispute_id     NUMBER         NOT NULL,
    atm_id         VARCHAR2(10)   NOT NULL,
    business_date  DATE           NOT NULL,
    amount         NUMBER(18, 2)  NOT NULL,
    reason_code    VARCHAR2(10)   NOT NULL,
    status         VARCHAR2(10)   NOT NULL,
    opened_date    DATE           NOT NULL,
    resolved_date  DATE,
    CONSTRAINT pk_atm_disputes_raw PRIMARY KEY (dispute_id),
    CONSTRAINT ck_atm_disputes_status CHECK (status IN ('OPEN', 'RESOLVED'))
);

-- ---------------------------------------------------------------------------
-- 3. Governed views — the EXACT SKILL.md column contracts
-- ---------------------------------------------------------------------------

-- cognic-skill-customer-data SKILL.md: one row per deposit account,
-- customer-attributed, at the current quarter's position (AS_OF_DATE).
-- Columns (exact order): CUSTOMER_ID, CUSTOMER_NAME, SEGMENT, ACCOUNT_ID,
-- ACCOUNT_TYPE, BRANCH_CODE, CURRENCY, BALANCE, AS_OF_DATE, OPENED_DATE.
CREATE VIEW retail_analytics.v_customer_deposits AS
SELECT c.customer_id,
       c.customer_name,
       c.segment,
       a.account_id,
       a.account_type,
       a.branch_code,
       a.currency,
       a.balance,
       a.as_of_date,
       a.opened_date
  FROM retail_analytics.customers_raw c
  JOIN retail_analytics.deposit_accounts_raw a
    ON a.customer_id = c.customer_id;

-- cognic-skill-customer-data SKILL.md: one row per customer.
-- Columns: CUSTOMER_ID, CUSTOMER_NAME, SEGMENT, BRANCH_CODE, STATUS, JOINED_DATE.
CREATE VIEW retail_analytics.v_customer_profile AS
SELECT customer_id,
       customer_name,
       segment,
       branch_code,
       status,
       joined_date
  FROM retail_analytics.customers_raw;

-- cognic-skill-financial-data SKILL.md: one row per GL account x cost center
-- x fiscal period. Columns: GL_ACCOUNT, GL_ACCOUNT_NAME, COST_CENTER, PERIOD,
-- CURRENCY, OPENING_BALANCE, DEBITS, CREDITS, CLOSING_BALANCE.
CREATE VIEW fin.v_gl_balances AS
SELECT gl_account,
       gl_account_name,
       cost_center,
       period,
       currency,
       opening_balance,
       debits,
       credits,
       closing_balance
  FROM fin.gl_balances_raw;

-- cognic-skill-financial-data SKILL.md: one row per branch x fiscal period.
-- Columns: BRANCH_CODE, BRANCH_NAME, PERIOD, INTEREST_INCOME, FEE_INCOME,
-- OPERATING_EXPENSE, NET_INCOME.
CREATE VIEW fin.v_branch_pnl AS
SELECT branch_code,
       branch_name,
       period,
       interest_income,
       fee_income,
       operating_expense,
       net_income
  FROM fin.branch_pnl_raw;

-- cognic-skill-cards-data SKILL.md: one row per card in the portfolio.
-- Columns: CARD_ID, CUSTOMER_ID, PRODUCT, STATUS, OPEN_DATE, CREDIT_LIMIT,
-- CURRENCY.
CREATE VIEW cards.v_card_accounts AS
SELECT card_id,
       customer_id,
       product,
       status,
       open_date,
       credit_limit,
       currency
  FROM cards.card_accounts_raw;

-- cognic-skill-cards-data SKILL.md: one row per card x spend month x merchant
-- category. Columns: CARD_ID, SPEND_MONTH, MERCHANT_CATEGORY, TXN_COUNT,
-- SPEND_AMOUNT, CURRENCY.
CREATE VIEW cards.v_card_spend AS
SELECT card_id,
       spend_month,
       merchant_category,
       txn_count,
       spend_amount,
       currency
  FROM cards.card_spend_raw;

-- cognic-skill-atm-recon SKILL.md: one row per ATM x business date; the
-- switch total reconciled against the GL feed. Columns: ATM_ID, ATM_LOCATION,
-- BUSINESS_DATE, SWITCH_TOTAL, GL_TOTAL, VARIANCE (= SWITCH_TOTAL - GL_TOTAL),
-- TXN_COUNT, STATUS. Seeded but NEVER granted (BAR-2/BAR-4b negative).
CREATE VIEW cards.v_atm_settlements AS
SELECT atm_id,
       atm_location,
       business_date,
       switch_total,
       gl_total,
       switch_total - gl_total AS variance,
       txn_count,
       status
  FROM cards.atm_settlements_raw;

-- cognic-skill-atm-recon SKILL.md: one row per customer dispute raised
-- against an ATM day. Columns: DISPUTE_ID, ATM_ID, BUSINESS_DATE, AMOUNT,
-- REASON_CODE, STATUS, OPENED_DATE, RESOLVED_DATE. Seeded but NEVER granted.
CREATE VIEW cards.v_atm_disputes AS
SELECT dispute_id,
       atm_id,
       business_date,
       amount,
       reason_code,
       status,
       opened_date,
       resolved_date
  FROM cards.atm_disputes_raw;

-- ---------------------------------------------------------------------------
-- 4. Deterministic demo rows
-- ---------------------------------------------------------------------------

-- 4a. RETAIL_ANALYTICS — the BAR-1 top-10-depositors fixture. 12 depositors
-- with STRICTLY DISTINCT SUM(BALANCE) totals + 1 closed non-depositor. The
-- deterministic expected answer for "top 10 customers by deposit balance this
-- quarter" (SUM per customer, descending) is:
--   rank  1  1001 Ayesha Khan       92500000.00   (60000000 + 32500000)
--   rank  2  1002 Bilal Sheikh      84000000.00   (48000000 + 36000000)
--   rank  3  1003 Chandni Malik     71250000.00
--   rank  4  1004 Daniyal Raza      65500000.00   (40000000 + 25500000)
--   rank  5  1005 Erum Siddiqui     58750000.00
--   rank  6  1006 Farhan Qureshi    52000000.00   (30000000 + 22000000)
--   rank  7  1007 Gul Nawaz         45600000.00
--   rank  8  1008 Hina Aslam        39300000.00
--   rank  9  1009 Imran Baig        33100000.00   (20000000 + 13100000)
--   rank 10  1010 Javeria Tariq     27800000.00
--   --- top-10 cut ---
--   rank 11  1011 Kamran Zafar      21400000.00   (must NOT appear in top 10)
--   rank 12  1012 Lubna Mirza       15000000.00   (DORMANT — the dormant-
--                                                  holdings worked example)
-- All balances PKR at the current quarter position AS_OF_DATE 2026-06-30.

INSERT INTO retail_analytics.customers_raw VALUES (1001, 'Ayesha Khan',    'PREMIER', 'KHI-01', 'ACTIVE',  DATE '2015-03-12', NULL);
INSERT INTO retail_analytics.customers_raw VALUES (1002, 'Bilal Sheikh',   'PRIVATE', 'LHR-02', 'ACTIVE',  DATE '2012-07-01', NULL);
INSERT INTO retail_analytics.customers_raw VALUES (1003, 'Chandni Malik',  'PREMIER', 'KHI-01', 'ACTIVE',  DATE '2018-01-20', NULL);
INSERT INTO retail_analytics.customers_raw VALUES (1004, 'Daniyal Raza',   'RETAIL',  'ISB-03', 'ACTIVE',  DATE '2019-11-05', NULL);
INSERT INTO retail_analytics.customers_raw VALUES (1005, 'Erum Siddiqui',  'PRIVATE', 'LHR-02', 'ACTIVE',  DATE '2014-06-30', NULL);
INSERT INTO retail_analytics.customers_raw VALUES (1006, 'Farhan Qureshi', 'PREMIER', 'ISB-03', 'ACTIVE',  DATE '2016-09-14', NULL);
INSERT INTO retail_analytics.customers_raw VALUES (1007, 'Gul Nawaz',      'RETAIL',  'KHI-01', 'ACTIVE',  DATE '2020-02-02', NULL);
INSERT INTO retail_analytics.customers_raw VALUES (1008, 'Hina Aslam',     'PREMIER', 'LHR-02', 'ACTIVE',  DATE '2017-04-18', NULL);
INSERT INTO retail_analytics.customers_raw VALUES (1009, 'Imran Baig',     'RETAIL',  'ISB-03', 'ACTIVE',  DATE '2021-08-09', NULL);
INSERT INTO retail_analytics.customers_raw VALUES (1010, 'Javeria Tariq',  'PREMIER', 'KHI-01', 'ACTIVE',  DATE '2013-12-25', NULL);
INSERT INTO retail_analytics.customers_raw VALUES (1011, 'Kamran Zafar',   'RETAIL',  'LHR-02', 'ACTIVE',  DATE '2022-05-11', NULL);
INSERT INTO retail_analytics.customers_raw VALUES (1012, 'Lubna Mirza',    'RETAIL',  'ISB-03', 'DORMANT', DATE '2011-10-03', NULL);
INSERT INTO retail_analytics.customers_raw VALUES (1013, 'Maheen Abbasi',  'RETAIL',  'KHI-01', 'CLOSED',  DATE '2010-01-15', NULL);

INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2001, 1001, 'SAVINGS',      'KHI-01', 'PKR', 60000000.00, DATE '2026-06-30', DATE '2015-03-12');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2002, 1001, 'TERM_DEPOSIT', 'KHI-01', 'PKR', 32500000.00, DATE '2026-06-30', DATE '2019-06-01');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2003, 1002, 'CURRENT',      'LHR-02', 'PKR', 48000000.00, DATE '2026-06-30', DATE '2012-07-01');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2004, 1002, 'TERM_DEPOSIT', 'LHR-02', 'PKR', 36000000.00, DATE '2026-06-30', DATE '2020-01-15');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2005, 1003, 'SAVINGS',      'KHI-01', 'PKR', 71250000.00, DATE '2026-06-30', DATE '2018-01-20');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2006, 1004, 'SAVINGS',      'ISB-03', 'PKR', 40000000.00, DATE '2026-06-30', DATE '2019-11-05');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2007, 1004, 'CURRENT',      'ISB-03', 'PKR', 25500000.00, DATE '2026-06-30', DATE '2021-03-22');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2008, 1005, 'TERM_DEPOSIT', 'LHR-02', 'PKR', 58750000.00, DATE '2026-06-30', DATE '2014-06-30');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2009, 1006, 'SAVINGS',      'ISB-03', 'PKR', 30000000.00, DATE '2026-06-30', DATE '2016-09-14');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2010, 1006, 'TERM_DEPOSIT', 'ISB-03', 'PKR', 22000000.00, DATE '2026-06-30', DATE '2022-11-30');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2011, 1007, 'CURRENT',      'KHI-01', 'PKR', 45600000.00, DATE '2026-06-30', DATE '2020-02-02');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2012, 1008, 'SAVINGS',      'LHR-02', 'PKR', 39300000.00, DATE '2026-06-30', DATE '2017-04-18');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2013, 1009, 'SAVINGS',      'ISB-03', 'PKR', 20000000.00, DATE '2026-06-30', DATE '2021-08-09');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2014, 1009, 'CURRENT',      'ISB-03', 'PKR', 13100000.00, DATE '2026-06-30', DATE '2023-01-10');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2015, 1010, 'TERM_DEPOSIT', 'KHI-01', 'PKR', 27800000.00, DATE '2026-06-30', DATE '2013-12-25');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2016, 1011, 'SAVINGS',      'LHR-02', 'PKR', 21400000.00, DATE '2026-06-30', DATE '2022-05-11');
INSERT INTO retail_analytics.deposit_accounts_raw VALUES (2017, 1012, 'SAVINGS',      'ISB-03', 'PKR', 15000000.00, DATE '2026-06-30', DATE '2011-10-03');

-- 4b. FIN — GL balances + branch P&L, periods 2026-05 / 2026-06 (PKR).
-- Deterministic orderings: largest 2026-06 |closing| = 110100 DEPOSITS-PAYABLE;
-- top 2026-06 net income = LHR-02 (Lahore Mall) > KHI-01 > ISB-03.
INSERT INTO fin.gl_balances_raw VALUES ('110100', 'DEPOSITS PAYABLE',    'CC-100', '2026-06', 'PKR', -448600000.00, 12000000.00, 72500000.00, -509100000.00);
INSERT INTO fin.gl_balances_raw VALUES ('110100', 'DEPOSITS PAYABLE',    'CC-200', '2026-06', 'PKR', -95000000.00,  4000000.00,  9500000.00,  -100500000.00);
INSERT INTO fin.gl_balances_raw VALUES ('120200', 'LOANS RECEIVABLE',    'CC-100', '2026-06', 'PKR', 310000000.00, 42000000.00, 18000000.00, 334000000.00);
INSERT INTO fin.gl_balances_raw VALUES ('400100', 'INTEREST INCOME',     'CC-100', '2026-06', 'PKR', -52000000.00, 1500000.00,  14200000.00, -64700000.00);
INSERT INTO fin.gl_balances_raw VALUES ('500300', 'OPERATING EXPENSE',   'CC-300', '2026-06', 'PKR', 21800000.00,  9600000.00,  400000.00,   31000000.00);
INSERT INTO fin.gl_balances_raw VALUES ('110100', 'DEPOSITS PAYABLE',    'CC-100', '2026-05', 'PKR', -401800000.00, 9800000.00, 56600000.00, -448600000.00);
INSERT INTO fin.gl_balances_raw VALUES ('120200', 'LOANS RECEIVABLE',    'CC-100', '2026-05', 'PKR', 291500000.00, 33500000.00, 15000000.00, 310000000.00);

INSERT INTO fin.branch_pnl_raw VALUES ('KHI-01', 'Karachi Clifton',  '2026-06', 25400000.00, 6100000.00, 12800000.00, 18700000.00);
INSERT INTO fin.branch_pnl_raw VALUES ('LHR-02', 'Lahore Mall Road', '2026-06', 28900000.00, 7400000.00, 14100000.00, 22200000.00);
INSERT INTO fin.branch_pnl_raw VALUES ('ISB-03', 'Islamabad Blue',   '2026-06', 17600000.00, 4200000.00, 10900000.00, 10900000.00);
INSERT INTO fin.branch_pnl_raw VALUES ('KHI-01', 'Karachi Clifton',  '2026-05', 24100000.00, 5800000.00, 12500000.00, 17400000.00);
INSERT INTO fin.branch_pnl_raw VALUES ('LHR-02', 'Lahore Mall Road', '2026-05', 27300000.00, 7000000.00, 13900000.00, 20400000.00);
INSERT INTO fin.branch_pnl_raw VALUES ('ISB-03', 'Islamabad Blue',   '2026-05', 16900000.00, 4000000.00, 10700000.00, 10200000.00);

-- 4c. CARDS — portfolio + spend (PKR). Deterministic: top 2026-06 spender by
-- SUM(SPEND_AMOUNT) joined to accounts = customer 1002 (2740000.00 across
-- cards 3002); CREDIT_LIMIT only on PRODUCT='CREDIT' rows.
INSERT INTO cards.card_accounts_raw VALUES (3001, 1001, 'CREDIT',  'ACTIVE',  DATE '2019-02-14', 5000000.00, 'PKR');
INSERT INTO cards.card_accounts_raw VALUES (3002, 1002, 'CREDIT',  'ACTIVE',  DATE '2017-09-30', 8000000.00, 'PKR');
INSERT INTO cards.card_accounts_raw VALUES (3003, 1004, 'DEBIT',   'ACTIVE',  DATE '2020-01-05', NULL,       'PKR');
INSERT INTO cards.card_accounts_raw VALUES (3004, 1007, 'PREPAID', 'ACTIVE',  DATE '2023-06-21', NULL,       'PKR');
INSERT INTO cards.card_accounts_raw VALUES (3005, 1009, 'CREDIT',  'BLOCKED', DATE '2021-04-08', 2500000.00, 'PKR');
INSERT INTO cards.card_accounts_raw VALUES (3006, 1011, 'DEBIT',   'CLOSED',  DATE '2018-12-01', NULL,       'PKR');

INSERT INTO cards.card_spend_raw VALUES (3001, '2026-06', 'GROCERY', 42, 610000.00,  'PKR');
INSERT INTO cards.card_spend_raw VALUES (3001, '2026-06', 'TRAVEL',   6, 890000.00,  'PKR');
INSERT INTO cards.card_spend_raw VALUES (3002, '2026-06', 'TRAVEL',  11, 1750000.00, 'PKR');
INSERT INTO cards.card_spend_raw VALUES (3002, '2026-06', 'DINING',  28, 990000.00,  'PKR');
INSERT INTO cards.card_spend_raw VALUES (3003, '2026-06', 'GROCERY', 51, 480000.00,  'PKR');
INSERT INTO cards.card_spend_raw VALUES (3004, '2026-06', 'FUEL',    19, 260000.00,  'PKR');
INSERT INTO cards.card_spend_raw VALUES (3001, '2026-05', 'GROCERY', 38, 570000.00,  'PKR');
INSERT INTO cards.card_spend_raw VALUES (3002, '2026-05', 'TRAVEL',   9, 1420000.00, 'PKR');
INSERT INTO cards.card_spend_raw VALUES (3003, '2026-05', 'FUEL',    22, 310000.00,  'PKR');

-- 4d. CARDS ATM reconciliation — seeded so the atm_recon scope is REAL data
-- behind a fully-refused boundary (BAR 2 refuses at the dispatch gate; BAR 4b
-- proves the DB backstop refuses too). Variances: ATM-KHI-001 on 2026-07-05
-- UNMATCHED +125000.00; ATM-ISB-003 on 2026-07-05 UNMATCHED -40000.00.
INSERT INTO cards.atm_settlements_raw VALUES ('ATM-KHI-01', 'Karachi Clifton Lobby',  DATE '2026-07-05', 9425000.00, 9300000.00, 412, 'UNMATCHED');
INSERT INTO cards.atm_settlements_raw VALUES ('ATM-LHR-07', 'Lahore Mall Road Drive', DATE '2026-07-05', 7810000.00, 7810000.00, 351, 'MATCHED');
INSERT INTO cards.atm_settlements_raw VALUES ('ATM-ISB-03', 'Islamabad Blue Area',    DATE '2026-07-05', 5260000.00, 5300000.00, 240, 'UNMATCHED');
INSERT INTO cards.atm_settlements_raw VALUES ('ATM-KHI-01', 'Karachi Clifton Lobby',  DATE '2026-07-04', 8930000.00, 8930000.00, 397, 'MATCHED');
INSERT INTO cards.atm_settlements_raw VALUES ('ATM-LHR-07', 'Lahore Mall Road Drive', DATE '2026-07-04', 8115000.00, 8115000.00, 365, 'MATCHED');

INSERT INTO cards.atm_disputes_raw VALUES (7001, 'ATM-KHI-01', DATE '2026-07-05', 25000.00, 'SHORT-DISP', 'OPEN',     DATE '2026-07-06', NULL);
INSERT INTO cards.atm_disputes_raw VALUES (7002, 'ATM-LHR-07', DATE '2026-07-04', 10000.00, 'DOUBLE-DEB', 'RESOLVED', DATE '2026-07-05', DATE '2026-07-06');

COMMIT;

-- ---------------------------------------------------------------------------
-- 5. Proxy users — the data-scope DB identities (proxy-only; no direct logon)
-- ---------------------------------------------------------------------------
-- The tool opens user="cognic[AN_AMIR]" / user="cognic[AN_SARA]" (Oracle
-- proxy authentication through the APP_USER). NO AUTHENTICATION = the proxy
-- identities cannot log in directly with any password; the ONLY path in is
-- CONNECT THROUGH the app user. The atm_recon scope's identity (AN_ATM_RECON)
-- is DELIBERATELY NOT created: never entitled -> never minted -> and even a
-- hypothetically-forged token could not open a session.

CREATE USER an_amir NO AUTHENTICATION;
CREATE USER an_sara NO AUTHENTICATION;
GRANT CREATE SESSION TO an_amir;
GRANT CREATE SESSION TO an_sara;
ALTER USER an_amir GRANT CONNECT THROUGH cognic;
ALTER USER an_sara GRANT CONNECT THROUGH cognic;

-- ---------------------------------------------------------------------------
-- 6. View-only grants per identity — the DB backstop of the entitlement matrix
-- ---------------------------------------------------------------------------
-- AN_AMIR (analyst.amir's scopes: retail_analytics + financials):
GRANT SELECT ON retail_analytics.v_customer_deposits TO an_amir;
GRANT SELECT ON retail_analytics.v_customer_profile TO an_amir;
GRANT SELECT ON fin.v_gl_balances TO an_amir;
GRANT SELECT ON fin.v_branch_pnl TO an_amir;
-- AN_SARA (analyst.sara's scopes: cards_analytics + retail_analytics):
GRANT SELECT ON cards.v_card_accounts TO an_sara;
GRANT SELECT ON cards.v_card_spend TO an_sara;
GRANT SELECT ON retail_analytics.v_customer_deposits TO an_sara;
GRANT SELECT ON retail_analytics.v_customer_profile TO an_sara;
-- NO grant on cards.v_atm_settlements or cards.v_atm_disputes to ANY proxy
-- identity, and NO grant on ANY *_raw base table to anyone: a cross-scope or
-- raw-table statement that somehow survived the kernel + tool gates dies at
-- the engine with ORA-00942 (table or view does not exist) — BAR 4b.

EXIT
