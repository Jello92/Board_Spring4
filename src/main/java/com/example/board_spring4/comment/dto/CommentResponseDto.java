package com.example.board_spring4.comment.dto;

import com.example.board_spring4.comment.entity.Comment;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
public class CommentResponseDto {

    private Long id;
    private String username;
    private String comment;
    private LocalDateTime createdAt;
    private LocalDateTime modifiedAt;

    public CommentResponseDto(Comment comment){
        this.id = comment.getId();
        this.username = comment.getUsers().getUsername();
        this.comment = comment.getComment();
        this.createdAt = comment.getCreatedAt();
        this.modifiedAt = comment.getModifiedAt();
    }
}
