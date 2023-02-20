package com.sangeng.filter;

import com.sangeng.domain.LoginUser;
import com.sangeng.utils.JwtUtil;
import com.sangeng.utils.RedisCache;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private RedisCache redisCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //获取token
        String token = request.getHeader("token");
        if (!StringUtils.hasText(token)) {
            //放行
            filterChain.doFilter(request, response);
            return;
        }
        //解析token
        String userid;
        String subject;
        try {
            Claims claims1 = JwtUtil.parseJWT((token));
            subject = claims1.getSubject();
            Claims claims = JwtUtil.parseJWT(token);
            userid = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("token非法");
        }
        String qwq = subject;
        //从redis中获取用户信息
        String redisKey = "login:" + userid;


        Object cacheObject = redisCache.getCacheObject(qwq);


        if (Objects.isNull(cacheObject))
        {
            throw new RuntimeException("登录");
        }
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken1=new UsernamePasswordAuthenticationToken(cacheObject,null,null);
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken1);


        filterChain.doFilter(request,response);
        LoginUser loginUser = redisCache.getCacheObject(redisKey);
        if (Objects.isNull(loginUser)) {
            throw new RuntimeException("用户未登录");
        }
        //存入SecurityContextHolder
        //TODO 获取权限信息封装到Authentication中
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginUser, null, loginUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        //放行
        filterChain.doFilter(request, response);
    }
}
