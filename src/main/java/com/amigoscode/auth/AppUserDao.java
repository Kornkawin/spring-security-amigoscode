package com.amigoscode.auth;

import java.util.Optional;

public interface AppUserDao {
    Optional<AppUser> selectAppUserByUsername(String username);
}
