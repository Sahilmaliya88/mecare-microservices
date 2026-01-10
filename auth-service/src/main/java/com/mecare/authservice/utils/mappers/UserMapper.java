package com.mecare.authservice.utils.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import com.mecare.authservice.DTOS.UsersResponse;
import com.mecare.authservice.entities.UserEntity;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @Mapping(source = "userProfile", target = "user_profile")
    UsersResponse tUsersResponse(UserEntity user);
}
