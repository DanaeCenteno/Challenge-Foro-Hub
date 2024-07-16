package com.alura.forohub.infra.security;

import com.alura.forohub.domain.usuario.Usuario;
import com.alura.forohub.domain.usuario.UsuarioRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.token.TokenService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private TonkenService tonkenService;

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

       var token = request.getHeader("Authorization");


       if(token != null){
           token = token.replace("Bearer", "");
           var subject = tonkenService.getSubject(token);

           if(subject != null){
                var usurio= usuarioRepository.findByEmail(subject);
                var authentication =  new UsernamePasswordAuthenticationToken(usurio,null,usurio.getAuthorities());
               SecurityContextHolder.getContext().setAuthentication(authentication);
           }
       }
        filterChain.doFilter(request, response);
    }
}
