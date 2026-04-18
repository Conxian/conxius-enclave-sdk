;; Oracle Aggregator - Fail-Closed Implementation
;; Aligned with CON-496 and CON-495 (Mainnet Readiness)

;; Errors
(define-constant ERR-NOT-AUTHORIZED (err u401))
(define-constant ERR-NOT-FOUND (err u404))
(define-constant ERR-STALE-PRICE (err u405))
(define-constant ERR-QUORUM-NOT-MET (err u406))
(define-constant ERR-OUTLIER-REJECTED (err u407))
(define-constant ERR-INVALID-PRICE (err u410))

;; Constants
(define-constant STALE-THRESHOLD u144) ;; ~24 hours
(define-constant MAX-DEVIATION u500)   ;; 5%

;; Data Maps
(define-map AuthorizedOracles principal { name: (string-ascii 32), active: bool })
(define-map PriceFeeds { asset: (string-ascii 16) } { price: uint, last-block: uint, quorum-reached: bool })
(define-map OracleSubmissions { asset: (string-ascii 16), oracle: principal } { price: uint, timestamp: uint })
(define-map EmergencyOverrides { asset: (string-ascii 16) } { price: uint, expiry: uint, authorized-by: principal })

;; Administrative
(define-data-var contract-owner principal tx-sender)
(define-data-var required-quorum uint u3)

;; Read-only Functions
(define-read-only (get-price (asset (string-ascii 16)))
    (let (
        (override (map-get? EmergencyOverrides { asset: asset }))
        (feed (map-get? PriceFeeds { asset: asset }))
    )
        (match override
            override-data (if (< block-height (get expiry override-data))
                (ok (get price override-data))
                (get-canonical-price asset feed))
            (get-canonical-price asset feed)
        )
    )
)

(define-private (get-canonical-price (asset (string-ascii 16)) (feed (option { price: uint, last-block: uint, quorum-reached: bool })))
    (match feed
        feed-data (if (< (+ (get last-block feed-data) STALE-THRESHOLD) block-height)
            ERR-STALE-PRICE
            (if (not (get quorum-reached feed-data))
                ERR-QUORUM-NOT-MET
                (if (is-eq (get price feed-data) u0)
                    ERR-INVALID-PRICE
                    (ok (get price feed-data)))))
        ERR-NOT-FOUND
    )
)

;; Public Functions
(define-public (submit-price (asset (string-ascii 16)) (price uint))
    (let (
        (oracle-info (unwrap! (map-get? AuthorizedOracles tx-sender) ERR-NOT-AUTHORIZED))
    )
        (asserts! (get active oracle-info) ERR-NOT-AUTHORIZED)
        (asserts! (> price u0) ERR-INVALID-PRICE)

        (map-set OracleSubmissions { asset: asset, oracle: tx-sender }
            { price: price, timestamp: block-height })

        (print { event: "price-submitted", asset: asset, oracle: tx-sender, price: price })
        (ok true)
    )
)

(define-public (update-canonical-price (asset (string-ascii 16)) (median-price uint) (reached-quorum bool))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (map-set PriceFeeds { asset: asset }
            {
                price: median-price,
                last-block: block-height,
                quorum-reached: reached-quorum
            }
        )
        (ok true)
    )
)

(define-public (set-emergency-override (asset (string-ascii 16)) (price uint) (duration uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (map-set EmergencyOverrides { asset: asset }
            { price: price, expiry: (+ block-height duration), authorized-by: tx-sender })
        (ok true)
    )
)

(define-public (add-oracle (oracle principal) (name (string-ascii 32)))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-set AuthorizedOracles oracle { name: name, active: true }))
    )
)
