;; Emergency Control - Centralized Circuit Breaker
;; Aligned with CON-500 and CON-495 (Mainnet Readiness)

;; Errors
(define-constant ERR-NOT-AUTHORIZED (err u401))
(define-constant ERR-ALREADY-PAUSED (err u414))
(define-constant ERR-NOT-PAUSED (err u415))

;; Data Vars
(define-data-var contract-owner principal tx-sender)
(define-data-var is-paused bool false)

;; Read-only Functions

(define-read-only (is-system-paused)
    (var-get is-paused)
)

;; Public Functions

(define-public (pause-system)
    (begin
        ;; In production, this would check RBAC from admin-facade
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (not (var-get is-paused)) ERR-ALREADY-PAUSED)
        (var-set is-paused true)
        (print { event: "system-paused", triggered-by: tx-sender })
        (ok true)
    )
)

(define-public (unpause-system)
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (var-get is-paused) ERR-NOT-PAUSED)
        (var-set is-paused false)
        (print { event: "system-unpaused", triggered-by: tx-sender })
        (ok true)
    )
)
