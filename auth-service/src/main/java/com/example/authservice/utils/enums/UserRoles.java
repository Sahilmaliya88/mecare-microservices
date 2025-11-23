package com.example.authservice.utils.enums;

import lombok.Getter;

@Getter
public enum UserRoles {
    SUPER_ADMIN(0), ADMIN(1), TEAM_MEMBER(2), TEAM_DOCTOR(3), DOCTOR(4), USER(5);

    private final int rank;

    UserRoles(int rank) {
        this.rank = rank;
    }
}
