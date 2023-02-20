package com.sangeng;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.sangeng")
@MapperScan("com.sangeng.mapper")
public class TokenApplication {
    public static void main(String[] args) {

        SpringApplication.run(TokenApplication.class,args);
    }
}
