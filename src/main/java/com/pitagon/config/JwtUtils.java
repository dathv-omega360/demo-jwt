package com.pitagon.config;

import com.pitagon.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
    @Value("${beholder.app.jwtSecret}")
    private String jwtSecret;
    @Value("${beholder.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    // Tạo JWT từ username, date, expiration và secret
    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret) // phát hành mã thông báo JWT bằng thuật toán HS256 với key bí mật
                // (Header + Payload + Secret Key)
                .compact(); // đóng nó lại
    }

    // Lấy username từ JWT
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();

    }

    // Xác nhận JWT
    public  boolean validateJwtToken(String authToken){
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
            // parseClaimsJws xảy ra các ngoại lệ
        } catch (SignatureException exception){
            logger.error("Invalid JWT signature: {}", exception.getMessage());
        }catch (MalformedJwtException exception){
            logger.error("Invalid JWT token: {}", exception.getMessage());
        }catch (ExpiredJwtException exception){
            logger.error("JWT token is expired: {}", exception.getMessage());
        }catch (UnsupportedJwtException exception){
            logger.error("JWT token is unsupported: {}", exception.getMessage());
        }catch (IllegalArgumentException exception){
            logger.error("JWT claims string is empty: {}", exception.getMessage());
        }
        return false;
    }

}
