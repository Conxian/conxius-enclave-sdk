;; Dimensional Oracle - Fail-Closed Liquidity & Volatility Data
;; Aligned with CON-496 and CON-495 (Mainnet Readiness)

;; Errors
(define-constant ERR-NOT-AUTHORIZED (err u401))
(define-constant ERR-NOT-FOUND (err u404))
(define-constant ERR-STALE-DATA (err u405))
(define-constant ERR-INVALID-DIMENSION (err u411))

;; Data Maps
(define-map MarketDimensions
    { asset: (string-ascii 16), dimension: (string-ascii 24) }
    {
        value: uint,
        last-block: uint,
        confidence: uint ;; 0-10000 (0% to 100%)
    }
)

;; Administrative
(define-data-var contract-owner principal tx-sender)

;; Read-only Functions
(define-read-only (get-dimension (asset (string-ascii 16)) (dimension (string-ascii 24)))
    (let (
        (data (unwrap! (map-get? MarketDimensions { asset: asset, dimension: dimension }) ERR-NOT-FOUND))
    )
        (asserts! (<= (+ (get last-block data) u72) block-height) ERR-STALE-DATA)
        (asserts! (>= (get confidence data) u8000) ERR-STALE-DATA)
        (ok (get value data))
    )
)

;; Public Functions
(define-public (update-dimension (asset (string-ascii 16)) (dimension (string-ascii 24)) (value uint) (confidence uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (map-set MarketDimensions { asset: asset, dimension: dimension }
            {
                value: value,
                last-block: block-height,
                confidence: confidence
            }
        )
        (ok true)
    )
)
