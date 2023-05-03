package com.example.board_spring4.comment.controller;

import com.example.board_spring4.comment.dto.CommentRequestDto;
import com.example.board_spring4.comment.service.CommentService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/comment")
@RequiredArgsConstructor
public class CommentController {

    private final CommentService commentService;

    @PostMapping("")
    public ResponseEntity<?> createComment (@RequestBody CommentRequestDto commentRequestDto, HttpServletRequest httpServletRequest) {
        return commentService.createComment(commentRequestDto, httpServletRequest);
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateComment (@PathVariable Long id, @RequestBody CommentRequestDto commentRequestDto, HttpServletRequest httpServletRequest){
        return commentService.updateComment(id, commentRequestDto, httpServletRequest);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteComment (@PathVariable Long id, HttpServletRequest httpServletRequest){
        return commentService.deleteComment(id, httpServletRequest);
    }
}
