package com.brianphiri.authentication.controllers

import com.brianphiri.authentication.Repositories.UserRepository
import com.brianphiri.authentication.models.ApplicationUser
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/users")
class UserController(private val userRepository: UserRepository,
                     private val bCryptPasswordEncoder: BCryptPasswordEncoder) {

    @PostMapping("/sign-up")
    fun signUp(@RequestBody user: ApplicationUser) {
        user.password = bCryptPasswordEncoder.encode(user.password)
        userRepository.save(user)
    }

    @GetMapping
    fun allUsers(): List<*> {
        return userRepository.findAll()
    }
}
