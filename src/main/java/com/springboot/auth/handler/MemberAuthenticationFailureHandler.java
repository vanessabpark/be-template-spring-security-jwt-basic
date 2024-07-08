package com.springboot.auth.handler;

import com.google.gson.Gson;
import com.springboot.response.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.naming.AuthenticationException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class MemberAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, org.springframework.security.core.AuthenticationException exception) throws IOException, ServletException {
        log.info("Authenticated failed");
        log.error("Authentication failed", exception.getMessage());
    }

   private void sendErrorResponse(HttpServletResponse response) throws IOException {
       Gson gson = new Gson();
       ErrorResponse errorResponse = ErrorResponse.of(HttpStatus.UNAUTHORIZED);

       response.setContentType(MediaType.APPLICATION_JSON_VALUE);
       response.setStatus(HttpStatus.UNAUTHORIZED.value());
       response.getWriter().write(gson.toJson(errorResponse, ErrorResponse.class));
   }


}
