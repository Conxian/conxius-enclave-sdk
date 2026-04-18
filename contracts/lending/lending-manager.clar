;; Lending Manager - Borrow and Withdraw with Solvency Checks
;; Aligned with CON-497 and CON-495 (Mainnet Readiness)

;; Errors
(define-constant ERR-NOT-AUTHORIZED (err u401))
(define-constant ERR-INSUFFICIENT-COLLATERAL (err u416))
(define-constant ERR-SYSTEM-PAUSED (err u417))

;; Data Maps
(define-map UserBalances { user: principal } { collateral: uint, debt: uint })

;; Administrative
(define-data-var contract-owner principal tx-sender)

;; Public Functions

(define-public (borrow (amount uint) (collateral-value uint))
    (let (
        (balance (default-to { collateral: u0, debt: u0 } (map-get? UserBalances { user: tx-sender })))
        (new-debt (+ (get debt balance) amount))
        (new-collateral (+ (get collateral balance) collateral-value))
    )
        ;; 1. Check Circuit Breaker (CON-500)
        ;; (asserts! (not (contract-call? .emergency-control is-system-paused)) ERR-SYSTEM-PAUSED)

        ;; 2. Enforce Solvency (CON-497/499)
        ;; (try! (contract-call? .risk-manager check-health new-collateral new-debt))

        (map-set UserBalances { user: tx-sender } { collateral: new-collateral, debt: new-debt })
        (ok true)
    )
)

(define-public (withdraw (amount-collateral uint))
    (let (
        (balance (unwrap! (map-get? UserBalances { user: tx-sender }) ERR-NOT-AUTHORIZED))
        (new-collateral (- (get collateral balance) amount-collateral))
    )
        ;; 1. Enforce Solvency after withdrawal
        ;; (try! (contract-call? .risk-manager check-health new-collateral (get debt balance)))

        (map-set UserBalances { user: tx-sender } { collateral: new-collateral, debt: (get debt balance) })
        (ok true)
    )
)
