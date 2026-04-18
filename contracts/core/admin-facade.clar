;; Admin Facade - Explicit RBAC for Privileged Paths
;; Aligned with CON-498 and CON-495 (Mainnet Readiness)

;; Errors
(define-constant ERR-NOT-AUTHORIZED (err u401))

;; Data Maps
(define-map Roles { principal: principal, role: (string-ascii 16) } { active: bool })

;; Administrative
(define-data-var contract-owner principal tx-sender)

;; Access Control
(define-read-only (has-role (account principal) (role (string-ascii 16)))
    (default-to false (get active (map-get? Roles { principal: account, role: role })))
)

(define-public (grant-role (account principal) (role (string-ascii 16)))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-set Roles { principal: account, role: role } { active: true }))
    )
)

(define-public (revoke-role (account principal) (role (string-ascii 16)))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-set Roles { principal: account, role: role } { active: false }))
    )
)
