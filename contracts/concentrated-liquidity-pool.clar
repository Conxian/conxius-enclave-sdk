;; Concentrated Liquidity Pool - Secure Implementation
;; Aligned with CON-15 Audit findings

;; Traits
(use-trait ft-trait 'SP3FBR2AGK5H9QBDH3EEN6DF8EK8JY7RX8QJ5SVTE.sip-010-trait-ft-standard.sip-010-trait)

;; Errors
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-AMOUNT (err u101))
(define-constant ERR-INSUFFICIENT-BALANCE (err u102))
(define-constant ERR-POOL-ALREADY-EXISTS (err u103))
(define-constant ERR-POOL-NOT-FOUND (err u104))
(define-constant ERR-INVALID-TOKEN (err u105))
(define-constant ERR-SLIPPAGE (err u106))
(define-constant ERR-INVALID-TICKS (err u107))

;; Data Maps
(define-map Pools
    { pool-id: uint }
    {
        token-x: principal,
        token-y: principal,
        reserve-x: uint,
        reserve-y: uint,
        fee: uint,
        liquidity: uint,
        sqrt-price: uint,
        tick: int,
        fee-growth-global-x: uint,
        fee-growth-global-y: uint
    }
)

(define-map Positions
    { pool-id: uint, owner: principal, tick-lower: int, tick-upper: int }
    {
        liquidity: uint,
        fee-growth-inside-x: uint,
        fee-growth-inside-y: uint
    }
)

;; Administrative
(define-data-var contract-owner principal tx-sender)
(define-data-var pool-count uint u0)

;; Internal Functions

;; Calculate output based on constant-product formula: (x + delta_x)(y - delta_y) = xy
;; delta_y = y - (xy / (x + delta_x))
(define-read-only (calculate-output (amount-in uint) (reserve-in uint) (reserve-out uint))
    (let (
        (k (* reserve-in reserve-out))
        (new-reserve-in (+ reserve-in amount-in))
        (new-reserve-out (/ k new-reserve-in))
    )
        (- reserve-out new-reserve-out)
    )
)

;; Public Functions

(define-public (create-pool (token-x principal) (token-y principal) (fee uint) (sqrt-price uint))
    (let (
        (pool-id (+ (var-get pool-count) u1))
    )
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (map-insert Pools { pool-id: pool-id }
            {
                token-x: token-x,
                token-y: token-y,
                reserve-x: u0,
                reserve-y: u0,
                fee: fee,
                liquidity: u0,
                sqrt-price: sqrt-price,
                tick: i0,
                fee-growth-global-x: u0,
                fee-growth-global-y: u0
            }
        )
        (var-set pool-count pool-id)
        (print { event: "pool-created", pool-id: pool-id, token-x: token-x, token-y: token-y })
        (ok pool-id)
    )
)

(define-public (set-pool-fee (pool-id uint) (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (let ((pool (unwrap! (map-get? Pools { pool-id: pool-id }) ERR-POOL-NOT-FOUND)))
            (map-set Pools { pool-id: pool-id } (merge pool { fee: new-fee }))
            (print { event: "set-pool-fee", pool-id: pool-id, new-fee: new-fee })
            (ok true)
        )
    )
)

(define-public (mint (pool-id uint) (tick-lower int) (tick-upper int) (amount-x uint) (amount-y uint) (token-x-trait <ft-trait>) (token-y-trait <ft-trait>))
    (let (
        (pool (unwrap! (map-get? Pools { pool-id: pool-id }) ERR-POOL-NOT-FOUND))
        (position-key { pool-id: pool-id, owner: tx-sender, tick-lower: tick-lower, tick-upper: tick-upper })
        (position (default-to { liquidity: u0, fee-growth-inside-x: u0, fee-growth-inside-y: u0 } (map-get? Positions position-key)))
    )
        (asserts! (< tick-lower tick-upper) ERR-INVALID-TICKS)
        (asserts! (or (> amount-x u0) (> amount-y u0)) ERR-INVALID-AMOUNT)
        (asserts! (is-eq (contract-of token-x-trait) (get token-x pool)) ERR-INVALID-TOKEN)
        (asserts! (is-eq (contract-of token-y-trait) (get token-y pool)) ERR-INVALID-TOKEN)

        (if (> amount-x u0)
            (try! (contract-call? token-x-trait transfer amount-x tx-sender (as-contract tx-sender) none))
            u0
        )
        (if (> amount-y u0)
            (try! (contract-call? token-y-trait transfer amount-y tx-sender (as-contract tx-sender) none))
            u0
        )

        (map-set Positions position-key
            (merge position {
                liquidity: (+ (get liquidity position) amount-x),
                fee-growth-inside-x: (get fee-growth-global-x pool),
                fee-growth-inside-y: (get fee-growth-global-y pool)
            })
        )

        (map-set Pools { pool-id: pool-id }
            (merge pool {
                liquidity: (+ (get liquidity pool) amount-x),
                reserve-x: (+ (get reserve-x pool) amount-x),
                reserve-y: (+ (get reserve-y pool) amount-y)
            }))

        (print { event: "mint", pool-id: pool-id, owner: tx-sender, amount-x: amount-x, amount-y: amount-y })
        (ok true)
    )
)

(define-public (swap (pool-id uint) (amount-in uint) (min-amount-out uint) (zero-for-one bool) (token-in <ft-trait>) (token-out <ft-trait>))
    (let (
        (pool (unwrap! (map-get? Pools { pool-id: pool-id }) ERR-POOL-NOT-FOUND))
        (fee-amount (/ (* amount-in (get fee pool)) u10000))
        (amount-after-fee (- amount-in fee-amount))
        (reserve-in (if zero-for-one (get reserve-x pool) (get reserve-y pool)))
        (reserve-out (if zero-for-one (get reserve-y pool) (get reserve-x pool)))
    )
        (asserts! (> amount-in u0) ERR-INVALID-AMOUNT)
        (if zero-for-one
            (begin
                (asserts! (is-eq (contract-of token-in) (get token-x pool)) ERR-INVALID-TOKEN)
                (asserts! (is-eq (contract-of token-out) (get token-y pool)) ERR-INVALID-TOKEN)
            )
            (begin
                (asserts! (is-eq (contract-of token-in) (get token-y pool)) ERR-INVALID-TOKEN)
                (asserts! (is-eq (contract-of token-out) (get token-x pool)) ERR-INVALID-TOKEN)
            )
        )

        (try! (contract-call? token-in transfer amount-in tx-sender (as-contract tx-sender) none))

        (let ((amount-out (calculate-output amount-after-fee reserve-in reserve-out)))
            (asserts! (>= amount-out min-amount-out) ERR-SLIPPAGE)
            (if zero-for-one
                (map-set Pools { pool-id: pool-id }
                    (merge pool {
                        reserve-x: (+ (get reserve-x pool) amount-in),
                        reserve-y: (- (get reserve-y pool) amount-out),
                        fee-growth-global-x: (+ (get fee-growth-global-x pool) fee-amount)
                    }))
                (map-set Pools { pool-id: pool-id }
                    (merge pool {
                        reserve-y: (+ (get reserve-y pool) amount-in),
                        reserve-x: (- (get reserve-x pool) amount-out),
                        fee-growth-global-y: (+ (get fee-growth-global-y pool) fee-amount)
                    }))
            )

            (try! (as-contract (contract-call? token-out transfer amount-out (as-contract tx-sender) tx-sender none)))

            (print { event: "swap", pool-id: pool-id, swapper: tx-sender, amount-in: amount-in, amount-out: amount-out })
            (ok amount-out)
        )
    )
)

(define-public (burn (pool-id uint) (tick-lower int) (tick-upper int) (liquidity-amount uint) (token-x-trait <ft-trait>) (token-y-trait <ft-trait>))
    (let (
        (pool (unwrap! (map-get? Pools { pool-id: pool-id }) ERR-POOL-NOT-FOUND))
        (position-key { pool-id: pool-id, owner: tx-sender, tick-lower: tick-lower, tick-upper: tick-upper })
        (position (unwrap! (map-get? Positions position-key) ERR-INSUFFICIENT-BALANCE))
        ;; Simplified share calculation
        (share-x (/ (* (get reserve-x pool) liquidity-amount) (get liquidity pool)))
        (share-y (/ (* (get reserve-y pool) liquidity-amount) (get liquidity pool)))
    )
        (asserts! (< tick-lower tick-upper) ERR-INVALID-TICKS)
        (asserts! (is-eq (contract-of token-x-trait) (get token-x pool)) ERR-INVALID-TOKEN)
        (asserts! (is-eq (contract-of token-y-trait) (get token-y pool)) ERR-INVALID-TOKEN)
        (asserts! (>= (get liquidity position) liquidity-amount) ERR-INSUFFICIENT-BALANCE)

        (try! (as-contract (contract-call? token-x-trait transfer share-x (as-contract tx-sender) tx-sender none)))
        (try! (as-contract (contract-call? token-y-trait transfer share-y (as-contract tx-sender) tx-sender none)))

        (map-set Positions position-key
            (merge position { liquidity: (- (get liquidity position) liquidity-amount) }))

        (map-set Pools { pool-id: pool-id }
            (merge pool {
                liquidity: (- (get liquidity pool) liquidity-amount),
                reserve-x: (- (get reserve-x pool) share-x),
                reserve-y: (- (get reserve-y pool) share-y)
            }))

        (print { event: "burn", pool-id: pool-id, owner: tx-sender, liquidity: liquidity-amount })
        (ok { amount-x: share-x, amount-y: share-y })
    )
)

(define-public (collect (pool-id uint) (tick-lower int) (tick-upper int) (token-x-trait <ft-trait>) (token-y-trait <ft-trait>))
    (let (
        (pool (unwrap! (map-get? Pools { pool-id: pool-id }) ERR-POOL-NOT-FOUND))
        (position-key { pool-id: pool-id, owner: tx-sender, tick-lower: tick-lower, tick-upper: tick-upper })
        (position (unwrap! (map-get? Positions position-key) ERR-INSUFFICIENT-BALANCE))
        (owed-x (- (get fee-growth-global-x pool) (get fee-growth-inside-x position)))
        (owed-y (- (get fee-growth-global-y pool) (get fee-growth-inside-y position)))
    )
        (asserts! (is-eq (contract-of token-x-trait) (get token-x pool)) ERR-INVALID-TOKEN)
        (asserts! (is-eq (contract-of token-y-trait) (get token-y pool)) ERR-INVALID-TOKEN)

        (if (> owed-x u0)
            (try! (as-contract (contract-call? token-x-trait transfer owed-x (as-contract tx-sender) tx-sender none)))
            u0
        )
        (if (> owed-y u0)
            (try! (as-contract (contract-call? token-y-trait transfer owed-y (as-contract tx-sender) tx-sender none)))
            u0
        )

        (map-set Positions position-key
            (merge position {
                fee-growth-inside-x: (get fee-growth-global-x pool),
                fee-growth-inside-y: (get fee-growth-global-y pool)
            })
        )

        (print { event: "collect", pool-id: pool-id, owner: tx-sender, owed-x: owed-x, owed-y: owed-y })
        (ok { owed-x: owed-x, owed-y: owed-y })
    )
)
