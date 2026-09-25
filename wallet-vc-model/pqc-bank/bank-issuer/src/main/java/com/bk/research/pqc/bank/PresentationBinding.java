package com.bk.research.pqc.bank;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * F4 presentation binding: a digest committing an Authorization VP to the exact evidence it presents and
 * to the DAS challenge it answers. The TPP computes it when building the VP; the DAS recomputes it from
 * what actually arrived, so a swapped credential or a replayed challenge cannot keep the binding valid.
 *
 * The hybrid profile uses SHA-384, matching the KB-JWT sd_hash digest of this profile.
 * binding = base64url(SHA-384(authorization_vc + "~" + delegate_vc + "~" + r_das))
 */
public final class PresentationBinding {
    private PresentationBinding() {
    }

    public static String compute(String authorizationVc, String delegateVc, String rDas) {
        String input = (authorizationVc == null ? "" : authorizationVc)
                + "~" + (delegateVc == null ? "" : delegateVc)
                + "~" + (rDas == null ? "" : rDas);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-384");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-384 unavailable for presentation binding", e);
        }
    }
}
