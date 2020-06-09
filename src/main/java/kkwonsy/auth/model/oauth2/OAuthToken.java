package kkwonsy.auth.model.oauth2;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuthToken {

    private String accessToken;
    private String tokenType;
    private String refreshToken;
    private long expiresIn;
    private String scope;
}
