//package com.example.security1.jwt.filter;
//
//import com.example.security1.execption.ApiResponse;
//import com.example.security1.jwt.execption.SecurityCustomException;
//import com.example.security1.jwt.execption.TokenErrorCode;
//import com.example.security1.jwt.util.HttpResponseUtil;
//import lombok.NonNull;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.http.HttpStatus;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import javax.servlet.FilterChain;
//import javax.servlet.ServletException;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import java.io.IOException;
//
//@Slf4j
//public class JwtExceptionHandlerFilter extends OncePerRequestFilter {
//
//    @Override
//    protected void doFilterInternal(
//            @NonNull HttpServletRequest request,
//            @NonNull HttpServletResponse response,
//            @NonNull FilterChain filterChain
//    ) throws ServletException, IOException {
//
//        try {
//            filterChain.doFilter(request, response);
//        } catch (SecurityCustomException e) {
//            log.warn(">>>>> SecurityCustomException : ", e);
//            TokenErrorCode errorCode = e.getErrorCode();
//            ApiResponse<String> errorResponse = ApiResponse.onFailure(
//                    errorCode.getCode(),
//                    errorCode.getMessage(),
//                    e.getMessage()
//            );
//            HttpResponseUtil.setErrorResponse(
//                    response,
//                    TokenErrorCode.getHttpStatus(),
//                    errorResponse
//            );
//        } catch (Exception e) {
//            log.error(">>>>> Exception : ", e);
//            ApiResponse<String> errorResponse = ApiResponse.onFailure(
//                    TokenErrorCode.INTERNAL_SECURITY_ERROR.getCode(),
//                    TokenErrorCode.INTERNAL_SECURITY_ERROR.getMessage(),
//                    e.getMessage()
//            );
//            HttpResponseUtil.setErrorResponse(
//                    response,
//                    HttpStatus.INTERNAL_SERVER_ERROR,
//                    errorResponse
//            );
//        }
//    }
//}
