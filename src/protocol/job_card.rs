use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkIntent {
    pub sender_address: String,
    pub receiver_address: String,
    #[serde(rename = "amount_sBTC")]
    pub amount_sbtc: String,
    pub town_name: Option<String>,
    pub country_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConxianJobCard {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@type")]
    pub r#type: String,
    pub work_intent: WorkIntent,
}

impl ConxianJobCard {
    pub fn new(
        sender: &str,
        receiver: &str,
        amount_sbtc: impl Into<String>,
        town: Option<String>,
        country: Option<String>,
    ) -> Self {
        Self {
            context: "https://conxian.com/contexts/job-card/v2.0".to_string(),
            r#type: "ConxianJobCard".to_string(),
            work_intent: WorkIntent {
                sender_address: sender.to_string(),
                receiver_address: receiver.to_string(),
                amount_sbtc: amount_sbtc.into(),
                town_name: town,
                country_code: country,
            },
        }
    }

    fn validate_amount_sbtc(&self) -> ConclaveResult<()> {
        let amount = self.work_intent.amount_sbtc.as_str();
        if amount.is_empty() {
            return Err(ConclaveError::IsoError(
                "ISO-422: Missing amount_sBTC".to_string(),
            ));
        }

        if amount.starts_with('+') || amount.starts_with('-') {
            return Err(ConclaveError::IsoError(
                "ISO-422: Invalid amount_sBTC sign".to_string(),
            ));
        }

        let mut iter = amount.split('.');
        let whole = iter.next().unwrap_or_default();
        let frac = iter.next();
        if iter.next().is_some() {
            return Err(ConclaveError::IsoError(
                "ISO-422: Invalid amount_sBTC format".to_string(),
            ));
        }

        if whole.is_empty() || !whole.chars().all(|c| c.is_ascii_digit()) {
            return Err(ConclaveError::IsoError(
                "ISO-422: Invalid amount_sBTC whole part".to_string(),
            ));
        }

        if let Some(frac) = frac {
            if frac.is_empty() || !frac.chars().all(|c| c.is_ascii_digit()) {
                return Err(ConclaveError::IsoError(
                    "ISO-422: Invalid amount_sBTC fractional part".to_string(),
                ));
            }
            if frac.len() > 8 {
                return Err(ConclaveError::IsoError(
                    "ISO-422: amount_sBTC exceeds 8 decimal places".to_string(),
                ));
            }
        }

        let whole_all_zero = whole.chars().all(|c| c == '0');
        let frac_all_zero = match frac {
            None => true,
            Some(f) => f.chars().all(|c| c == '0'),
        };
        if whole_all_zero && frac_all_zero {
            return Err(ConclaveError::IsoError(
                "ISO-422: amount_sBTC must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate(&self) -> ConclaveResult<()> {
        self.validate_amount_sbtc()?;
        if self.work_intent.town_name.is_none() || self.work_intent.country_code.is_none() {
            return Err(ConclaveError::IsoError(
                "ISO-404: Missing mandatory fields (town_name or country_code)".to_string(),
            ));
        }
        Ok(())
    }
}

pub struct Iso20022Wrapper;

impl Iso20022Wrapper {
    pub fn wrap_pacs008(card: &ConxianJobCard) -> ConclaveResult<String> {
        card.validate()?;

        let town = card.work_intent.town_name.as_deref().unwrap_or("Unknown");
        let country = card.work_intent.country_code.as_deref().unwrap_or("ZZ");

        // For pacs.008.001.08 XML generation
        // This is a simplified representation for the bounty requirement
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">
    <FIToFICstmrCdtTrf>
        <GrpHdr>
            <MsgId>CONXIAN-{}</MsgId>
            <CreDtTm>2026-03-26T12:00:00Z</CreDtTm>
            <NbOfTxs>1</NbOfTxs>
            <SttlmInf>
                <SttlmMtd>CLRG</SttlmMtd>
            </SttlmInf>
        </GrpHdr>
        <CdtTrfTxInf>
            <PmtId>
                <EndToEndId>{}</EndToEndId>
            </PmtId>
            <IntrBkSttlmAmt Ccy="sBTC">{}</IntrBkSttlmAmt>
            <Dbtr>
                <Nm>{}</Nm>
                <PstlAdr>
                    <TwnNm>{}</TwnNm>
                    <Ctry>{}</Ctry>
                </PstlAdr>
            </Dbtr>
            <Cdtr>
                <Nm>{}</Nm>
            </Cdtr>
        </CdtTrfTxInf>
    </FIToFICstmrCdtTrf>
</Document>"#,
            card.work_intent.sender_address,
            card.work_intent.receiver_address,
            card.work_intent.amount_sbtc,
            card.work_intent.sender_address,
            town,
            country,
            card.work_intent.receiver_address
        );

        Ok(xml)
    }

    pub fn wrap_json_ld(card: &ConxianJobCard) -> ConclaveResult<String> {
        card.validate()?;
        serde_json::to_string_pretty(card).map_err(|_| ConclaveError::InvalidPayload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_job_card_validation() {
        let mut card = ConxianJobCard::new(
            "SP1...",
            "SP2...",
            "0.05".to_string(),
            Some("Johannesburg".to_string()),
            Some("ZA".to_string()),
        );
        assert!(card.validate().is_ok());

        card.work_intent.town_name = None;
        let res = card.validate();
        assert!(res.is_err());
        match res {
            Err(ConclaveError::IsoError(e)) => assert!(e.contains("ISO-404")),
            _ => panic!("Expected ISO-404 error"),
        }
    }

    #[test]
    fn test_pacs008_generation() {
        let card = ConxianJobCard::new(
            "SP1...",
            "SP2...",
            "0.05".to_string(),
            Some("Johannesburg".to_string()),
            Some("ZA".to_string()),
        );
        let xml = Iso20022Wrapper::wrap_pacs008(&card).unwrap();
        assert!(xml.contains("pacs.008.001.08"));
        assert!(xml.contains("sBTC"));
        assert!(xml.contains("Johannesburg"));
    }

    #[test]
    fn test_amount_validation_rejects_invalid_formats() {
        let invalid_amounts = [
            "",
            "+1",
            "-1",
            "1.",
            ".1",
            "1.2.3",
            "abc",
            "1.a",
            "1.123456789",
        ];

        for amount in invalid_amounts {
            let card = ConxianJobCard::new(
                "SP1...",
                "SP2...",
                amount.to_string(),
                Some("Johannesburg".to_string()),
                Some("ZA".to_string()),
            );
            let res = card.validate();
            assert!(res.is_err(), "expected error for amount={amount:?}");
            match res {
                Err(ConclaveError::IsoError(e)) => assert!(e.contains("ISO-422")),
                _ => panic!("Expected ISO-422 error"),
            }
        }
    }

    #[test]
    fn test_amount_validation_rejects_zero_amounts() {
        let invalid_amounts = [
            "0",
            "0.0",
            "000000",
            "000000.0",
            "000000.00000000",
            "0.00000000",
        ];

        for amount in invalid_amounts {
            let card = ConxianJobCard::new(
                "SP1...",
                "SP2...",
                amount.to_string(),
                Some("Johannesburg".to_string()),
                Some("ZA".to_string()),
            );

            let res = card.validate();
            assert!(res.is_err(), "expected error for amount={amount:?}");
            match res {
                Err(ConclaveError::IsoError(e)) => {
                    assert!(e.contains("ISO-422"));
                    assert!(e.contains("greater than zero"));
                }
                _ => panic!("Expected ISO-422 error"),
            }
        }
    }

    #[test]
    fn test_benchmark_pacs008_latency() {
        let card = ConxianJobCard::new(
            "SP1...",
            "SP2...",
            "0.05".to_string(),
            Some("Johannesburg".to_string()),
            Some("ZA".to_string()),
        );
        let iters = 10000;
        let start = Instant::now();

        for _ in 0..iters {
            let _ = Iso20022Wrapper::wrap_pacs008(&card).unwrap();
        }

        let duration = start.elapsed();
        println!("Processed {} transactions in {:?}", iters, duration);
        assert!(
            duration.as_millis() < 50,
            "Benchmark failed: Latency > 50ms for 10k txs"
        );
    }
}
