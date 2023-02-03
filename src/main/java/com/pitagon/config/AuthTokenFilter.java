package com.pitagon.config;

import com.pitagon.service.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
    // Có nhiệm vụ kiểm tra request của người dùng trước khi nó tới đích,
    // Nó sẽ lấy Header Authorization ra và kiểm tra xem chuỗi JWT người dùng gửi lên có hợp lệ không.
    // thực thi trên mỗi request
public class AuthTokenFilter extends OncePerRequestFilter {
// OncePerRequestFilter là Filter thực thi một lần duy nhất cho mỗi Request tới API


    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {// lấy JWT từ request
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) // xác thực JWT
            {
                String username = jwtUtils.getUserNameFromJwtToken(jwt); // lấy username từ jwt
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);  // lấy ra thông tin user để kểm tra xác thực người dùng
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken // sử dụng để làm xac thực
                        (
                        userDetails, null, userDetails.getAuthorities());
                // bulid lên web
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //setAuthentication(auth) set thông tin UserDetails vào SecurityContext
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }catch (Exception exception){
            logger.error("Cannot set user authentication: {}", exception);
        }
        filterChain.doFilter(request, response);
    }


    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        // Kiểm tra xem header Authorization có chứa thông tin jwt không
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")){
            return headerAuth.substring(7);
        }
        return null;
    }
}
