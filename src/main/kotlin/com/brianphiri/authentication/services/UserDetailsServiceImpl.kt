package com.brianphiri.authentication.services


import com.brianphiri.authentication.Repositories.UserRepository
import org.springframework.context.annotation.Bean
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Service

import java.util.Collections.emptyList

@Service
class UserDetailsServiceImpl(private val applicationUserRepository: UserRepository) : UserDetailsService {

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String): UserDetails {
        val user = applicationUserRepository.findByUsername(username) ?: throw UsernameNotFoundException(username)
        return User(user.username, user.password, emptyList())
    }

    @Bean
    internal fun bCryptPasswordEncoder(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder()
    }
}