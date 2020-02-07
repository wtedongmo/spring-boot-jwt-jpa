package twb.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.bytebuddy.implementation.bytecode.Throw;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import twb.exception.CustomException;
import org.springframework.web.filter.OncePerRequestFilter;

// We should use OncePerRequestFilter since we are doing a database call, there is no point in doing this more than once
public class JwtTokenFilter extends OncePerRequestFilter {

  private JwtTokenProvider jwtTokenProvider;

  public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
    this.jwtTokenProvider = jwtTokenProvider;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
    String token = jwtTokenProvider.resolveToken(httpServletRequest);
    try {
      if (token != null && jwtTokenProvider.validateToken(token)) {
        Authentication auth = jwtTokenProvider.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(auth);
      }
    } catch (CustomException ex) {
      //this is very important, since it guarantees the user is not authenticated at all
      ex.printStackTrace();
      SecurityContextHolder.clearContext();
      httpServletResponse.sendError(ex.getHttpStatus().value(), ex.getMessage());
      throw new CustomException(ex.getMessage(), ex.getHttpStatus());
//      return;
    }

    filterChain.doFilter(httpServletRequest, httpServletResponse);
  }

}
