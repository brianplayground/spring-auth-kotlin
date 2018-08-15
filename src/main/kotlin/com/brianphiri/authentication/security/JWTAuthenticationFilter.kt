package com.brianphiri.authentication.security

import com.auth0.jwt.JWT
import com.brianphiri.authentication.models.ApplicationUser
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.io.IOException
import java.util.ArrayList
import java.util.Date

import com.auth0.jwt.algorithms.Algorithm.HMAC512
import com.brianphiri.authentication.security.SecurityConstants.EXPIRATION_TIME
import com.brianphiri.authentication.security.SecurityConstants.HEADER_STRING
import com.brianphiri.authentication.security.SecurityConstants.SECRET
import com.brianphiri.authentication.security.SecurityConstants.TOKEN_PREFIX
import org.springframework.security.core.GrantedAuthority

class JWTAuthenticationFilter : UsernamePasswordAuthenticationFilter {

    constructor(authenticationManager: AuthenticationManager) : super() {
        this.authenticationManager = authenticationManager
    }

    @Throws(AuthenticationException::class)
    override fun attemptAuthentication(req: HttpServletRequest, res: HttpServletResponse?): Authentication {
        try {
            val creds = ObjectMapper().readValue(req.inputStream, ApplicationUser::class.java)

            return authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken(
                            creds.username,
                            creds.password,
                            ArrayList<GrantedAuthority>()
                    )
            )
        } catch (e: IOException) {
            throw RuntimeException(e)
        }
    }

    @Throws(IOException::class, ServletException::class)
    override fun successfulAuthentication(req: HttpServletRequest, res: HttpServletResponse, chain: FilterChain?, auth: Authentication) {
        val token = JWT.create()
                .withSubject((auth.principal as User).username)
                .withExpiresAt(Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(HMAC512(SECRET.toByteArray()))
        res.addHeader(HEADER_STRING, TOKEN_PREFIX + token)
    }
}
