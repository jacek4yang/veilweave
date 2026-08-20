// Geo / ISP detection from Cloudflare request headers. Drives entry-IP carrier
// selection (CT/CU/CMCC) and ISP-aware caching for domestic users.

// Carrier codes are the operators' own all-caps brand names (CT / CU / CMCC),
// kept verbatim rather than camel-cased so they match the headers we log against.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug)]
pub enum Carrier {
    CT,    // 中国电信 (Telecom)
    CU,    // 中国联通 (Unicom)
    CMCC,  // 中国移动 (Mobile)
    Other, // 其他 / 国际
}

#[derive(Clone, Copy, Debug)]
pub struct UserGeo {
    pub carrier: Carrier,
    pub is_domestic: bool,
}

/// Detect the user's carrier from CF-IPCountry + CF-ASN.
pub fn detect_user_geo(country: &str, asn: Option<u32>) -> UserGeo {
    let is_domestic = country == "CN";
    let carrier = if is_domestic {
        asn.map(asn_to_carrier).unwrap_or(Carrier::Other)
    } else {
        Carrier::Other
    };
    UserGeo {
        carrier,
        is_domestic,
    }
}

/// Map a Chinese ASN to its carrier.
fn asn_to_carrier(asn: u32) -> Carrier {
    match asn {
        // 中国电信 (China Telecom)
        4134 | 4812 | 23724 | 140553 | 136195 | 4811 | 4847 | 136191 | 138169 | 139018 => {
            Carrier::CT
        }
        // 中国联通 (China Unicom)
        4837 | 9929 | 10099 | 138421 | 140292 | 136958 | 136959 | 140726 | 139007 | 140053 => {
            Carrier::CU
        }
        // 中国移动 (China Mobile)
        9808 | 58453 | 24400 | 56040 | 56041 | 56042 | 56044 | 56046 | 56047 | 56048 | 24547
        | 140485 => Carrier::CMCC,
        _ => Carrier::Other,
    }
}
