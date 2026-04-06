use crate::{ConclaveError, ConclaveResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkIntent {
    pub sender_address: String,
    pub receiver_address: String,
    #[serde(rename = "amount_sBTC")]
    pub amount_sbtc: f64,
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
        amount: f64,
        town: Option<String>,
        country: Option<String>,
    ) -> Self {
        Self {
            context: "https://conxian.com/contexts/job-card/v2.0".to_string(),
            r#type: "ConxianJobCard".to_string(),
            work_intent: WorkIntent {
                sender_address: sender.to_string(),
                receiver_address: receiver.to_string(),
                amount_sbtc: amount,
                town_name: town,
                country_code: country,
            },
        }
    }

    pub fn validate(&self) -> ConclaveResult<()> {
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
            0.05,
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
            0.05,
            Some("Johannesburg".to_string()),
            Some("ZA".to_string()),
        );
        let xml = Iso20022Wrapper::wrap_pacs008(&card).unwrap();
        assert!(xml.contains("pacs.008.001.08"));
        assert!(xml.contains("sBTC"));
        assert!(xml.contains("Johannesburg"));
    }

    #[test]
    fn test_benchmark_pacs008_latency() {
        let card = ConxianJobCard::new(
            "SP1...",
            "SP2...",
            0.05,
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
