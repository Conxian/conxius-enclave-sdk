;; Risk Manager - Canonical Health-Factor and Liquidation Thresholds
;; Aligned with CON-499 and CON-495 (Mainnet Readiness)

;; Errors
(define-constant ERR-NOT-AUTHORIZED (err u401))
(define-constant ERR-UNHEALTHY-ACCOUNT (err u412))

;; Constants
(define-constant LIQUIDATION-THRESHOLD u8000) ;; 80% LTV
(define-constant HEALTH-FACTOR-MIN u10000)    ;; 1.0

;; Administrative
(define-data-var contract-owner principal tx-sender)

;; Public Functions
(define-read-only (check-health (collateral-value uint) (debt-value uint))
    (let (
        (hf (if (is-eq debt-value u0)
            u999999
            (/ (* collateral-value LIQUIDATION-THRESHOLD) debt-value)))
    )
        (if (>= hf HEALTH-FACTOR-MIN)
            (ok hf)
            (err ERR-UNHEALTHY-ACCOUNT))
    )
)

(define-read-only (is-liquidatable (collateral-value uint) (debt-value uint))
    (match (check-health collateral-value debt-value)
        hf (ok false)
        err (ok true)
    )
)
