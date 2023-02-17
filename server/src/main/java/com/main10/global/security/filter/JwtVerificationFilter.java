package com.main10.global.security.filter;

import com.main10.global.security.token.JwtAuthenticationToken;
import com.main10.global.security.utils.AuthConstants;
import com.main10.global.security.utils.CustomAuthorityUtils;
import com.main10.global.security.utils.RedisUtils;
import com.main10.global.security.utils.JwtTokenUtils;
import com.main10.global.security.vo.ClaimsVO;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import static com.main10.global.security.utils.AuthConstants.*;

/**
 * 헤더에 실린 토큰 정보를 통해 요청에 대한 인가를 처리해주는 클래스
 *
 * @author mozzi327
 */
@Slf4j
@RequiredArgsConstructor
public class JwtVerificationFilter extends OncePerRequestFilter {
    private final RedisUtils redisUtils;
    private final JwtTokenUtils jwtTokenUtils;
    private final CustomAuthorityUtils authorityUtils;

    /**
     * 사용자 요청에 대한 권한 인증 메서드<br>
     * - 헤더에 저장된 리프레시 토큰을 가져와 레디스에 리프레시 토큰이 존재하는지 확인하고,<br>
     * 액세스 토큰이 유효한지 확인한다.
     *
     * @param req         요청
     * @param res         응답
     * @param filterChain 필터 체인
     * @author mozzi327
     */
    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain filterChain) throws ServletException, IOException {

        String accessToken = req.getHeader(AuthConstants.AUTHORIZATION);

        if (StringUtils.hasText(accessToken) && accessToken.startsWith(BEARER)) {
            JwtAuthenticationToken token = createJwtAuthentication(accessToken);
            String isLogout = redisUtils.isBlackList(accessToken);
            if (isLogout == null) { // 로그아웃이 아닌 경우
                if (token.isExpired()) res.setHeader(AUTHORIZATION, token.getAccessToken());
                Authentication authentication = token;
                setAuthenticationToContext(authentication);
            }
        }
        doFilter(req, res, filterChain);
    }

    /**
     * accessToken 디코딩 및 재발급 메서드
     *
     * @param accessToken 엑세스 토큰
     * @return JwtAuthenticationToken authentication 정보
     * @author mozzi327
     */
    private JwtAuthenticationToken createJwtAuthentication(String accessToken) {
        try {
            Map<String, Object> claims = jwtTokenUtils.getClaims(accessToken);
            String stringId = claims.get("id").toString();
            Long id = Long.valueOf(stringId);
            String name = (String) claims.get("name");
            String email = (String) claims.get("sub");
            List<String> roles = (List<String>) claims.get(ROLES);
            List<GrantedAuthority> authorities = authorityUtils.createAuthorities(roles);
            return JwtAuthenticationToken.builder()
                    .credential(null)
                    .id(id)
                    .name(name)
                    .principal(email)
                    .authorities(authorities)
                    .accessToken(accessToken)
                    .principal(email)
                    .isExpired(false)
                    .build();

        } catch (ExpiredJwtException ee) { // 토큰 만료
            ClaimsVO parseClaims = jwtTokenUtils.parseClaims(accessToken);
            redisUtils.isExistRefreshToken(parseClaims.getSub());
            List<GrantedAuthority> authorities = authorityUtils.createAuthorities(parseClaims.getSub());
            String generateToken = jwtTokenUtils.generateAccessTokenByClaimsVO(parseClaims);

            return JwtAuthenticationToken.builder()
                    .credential(null)
                    .id(parseClaims.getId())
                    .name(parseClaims.getName())
                    .authorities(authorities)
                    .accessToken(generateToken)
                    .principal(parseClaims.getSub())
                    .isExpired(true)
                    .build();
        }
    }

    /**
     * 추출한 claims 정보를 SecurityContextHolder context에 등록하는 메서드
     *
     * @param authentication 권한 정보
     * @author mozzi327
     */
    private void setAuthenticationToContext(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
