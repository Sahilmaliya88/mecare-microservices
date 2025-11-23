


create table user_profiles (
    id UUID primary key,
    user_id UUID not null,
    first_name varchar(100) not null,
    last_name varchar(100) not null,
    date_of_birth date not null,
    profile_picture_url varchar(255),
    gender varchar(50) not null,
    gender_other_title varchar(100),
    phone_number varchar(20),
    bio text,
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp,
    foreign key (user_id) references users(id),
    UNIQUE (user_id)
);
create index if not exists idx_user_profile_user_id on user_profiles (user_id);