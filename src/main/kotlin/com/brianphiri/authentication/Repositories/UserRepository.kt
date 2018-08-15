package com.brianphiri.authentication.Repositories

import com.brianphiri.authentication.models.ApplicationUser
import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository : JpaRepository<ApplicationUser, Long> {
    fun findByUsername(username: String): ApplicationUser
}
