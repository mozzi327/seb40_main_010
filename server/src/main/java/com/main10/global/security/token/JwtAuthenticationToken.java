package com.main10.global.security.token;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Authentication Token 커스텀 클래스
 * @author mozzi327
 */
@Getter
public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private String accessToken;
    private Object principal;
    private Object credential;
    private Long id;
    private boolean isExpired;
    private String name;

    @Builder
    public JwtAuthenticationToken(Collection<? extends GrantedAuthority> authorities,
                                  Object principal,
                                  Object credential,
                                  Long id,
                                  boolean isExpired,
                                  String accessToken,
                                  String name) {
        super(authorities);
        this.principal = principal;
        this.credential = credential;
        this.id = id;
        this.isExpired = isExpired;
        this.accessToken = accessToken;
        this.name = name;
        this.setAuthenticated(true);
    }

    public JwtAuthenticationToken(String accessToken) {
        super(null);
        this.accessToken = accessToken;
        this.setAuthenticated(false);
    }

    /**
     * Credential 정보 리턴 메서드
     * @return credentials
     * @author mozzi327
     */
    @Override
    public Object getCredentials() {
        return this.credential;
    }

    /**
     * Principal 정보 리턴 메서드
     * @return principal(User or OAuth2User)
     * @author mozzi327
     */
    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    /**
     * AccessToken 리턴 메서드
     * @return accessToken
     * @author mozzi327
     */
    public String getAccessToken() {
        return accessToken;
    }


}
