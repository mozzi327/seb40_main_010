package com.main21.member.dto;

import lombok.Getter;

public class MemberDto {
    @Getter
    public static class Post {
        private String email;

        private String password;

        private String name;

        private String nickname;

        private String phoneNumber;

        private String profileImage;
    }
    @Getter
    public static class Patch {
        private String profileImage;
        private String nickname;
        private String mbti;
    }
}