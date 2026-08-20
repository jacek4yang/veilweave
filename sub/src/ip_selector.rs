// Proxyip (egress) ranking. Carrier optimization lives at the *entry* IP (chosen
// per-carrier from cf.090227.xyz), so here we only prefer in-country egress and
// cap the count. The list arrives already speed/health-ordered upstream, so this
// preserves order within the CN / non-CN partition (a stable partition).

use crate::egress::EgressEntry;
use crate::geo::UserGeo;

pub fn select_best_ips(
    user_geo: &UserGeo,
    all_ips: &[EgressEntry],
    max_count: usize,
) -> Vec<EgressEntry> {
    if all_ips.is_empty() {
        return Vec::new();
    }

    // Non-domestic users: no in-country preference, keep upstream order.
    if !user_geo.is_domestic {
        return all_ips.iter().take(max_count).cloned().collect();
    }

    // Domestic users: CN-country egress first, then the rest — stable to keep the
    // upstream speed ordering inside each group.
    let mut out: Vec<EgressEntry> = all_ips.iter().filter(|e| e.country == "CN").cloned().collect();
    if out.len() < max_count {
        out.extend(all_ips.iter().filter(|e| e.country != "CN").cloned());
    }
    out.truncate(max_count);
    out
}
