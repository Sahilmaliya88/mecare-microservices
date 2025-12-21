package com.example.authservice.utils.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import com.example.authservice.DTOS.UsersResponse;
import com.example.authservice.Entities.UserEntity;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @Mapping(source = "userProfile", target = "user_profile")
    UsersResponse tUsersResponse(UserEntity user);
}
