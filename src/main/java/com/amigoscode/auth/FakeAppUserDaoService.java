package com.amigoscode.auth;

import com.google.common.collect.Lists;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.amigoscode.security.AppUserRole.*;

@Repository("fake")
public class FakeAppUserDaoService implements AppUserDao {
    private final PasswordEncoder passwordEncoder;

    public FakeAppUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<AppUser> selectAppUserByUsername(String username) {
        return getAppUsers()
                .stream()
                .filter(appUser -> username.equals(appUser.getUsername()))
                .findFirst();
    }

    private List<AppUser> getAppUsers() {
        return Lists.newArrayList(
            new AppUser(
                STUDENT.getGrantedAuthorities(),
                "annasmith",
                passwordEncoder.encode("password"),
                true,
                true,
                true,
                true
            ),
            new AppUser(
                ADMIN.getGrantedAuthorities(),
                "linda",
                passwordEncoder.encode("password123"),
                true,
                true,
                true,
                true
            ),
            new AppUser(
                ADMINTRAINEE.getGrantedAuthorities(),
                "tom",
                passwordEncoder.encode("password123"),
                true,
                true,
                true,
                true
            )
        );
    }
}
