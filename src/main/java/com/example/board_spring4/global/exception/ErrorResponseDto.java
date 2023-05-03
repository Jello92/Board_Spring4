package com.example.board_spring4.global.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class ErrorResponseDto {

    private String message;
    private int status;

    public ErrorResponseDto(ExceptionEnum exceptionEnum){
        this.message = exceptionEnum.getMessage();
        this.status = exceptionEnum.getStatus();
    }
}