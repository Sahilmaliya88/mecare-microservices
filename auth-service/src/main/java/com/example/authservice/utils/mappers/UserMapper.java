package com.example.authservice.utils.mappers;

import org.mapstruct.Mapper;

import com.example.authservice.DTOS.UsersResponse;
import com.example.authservice.Entities.UserEntity;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UsersResponse tUsersResponse(UserEntity user);
}
