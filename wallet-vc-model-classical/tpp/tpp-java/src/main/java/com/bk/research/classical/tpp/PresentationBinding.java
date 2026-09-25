package com.bk.research.classical.tpp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * F4 presentation binding: a digest committing an Authorization VP to the exact evidence it presents and
 * to the DAS challenge it answers. Must stay byte-identical to the DAS-side definition in the bank issuer.
 *
 * binding = base64url(SHA-256(authorization_vc + "~" + delegate_vc + "~" + r_das))
 */
public final class PresentationBinding {
    private PresentationBinding() {
    }

    public static String compute(String authorizationVc, String delegateVc, String rDas) {
        String input = (authorizationVc == null ? "" : authorizationVc)
                + "~" + (delegateVc == null ? "" : delegateVc)
                + "~" + (rDas == null ? "" : rDas);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable for presentation binding", e);
        }
    }
}
