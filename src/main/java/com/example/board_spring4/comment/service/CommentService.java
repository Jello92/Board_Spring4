package com.example.board_spring4.comment.service;

import com.example.board_spring4.board.entity.Board;
import com.example.board_spring4.board.repository.BoardRepository;
import com.example.board_spring4.comment.dto.CommentRequestDto;
import com.example.board_spring4.comment.dto.CommentResponseDto;
import com.example.board_spring4.comment.entity.Comment;
import com.example.board_spring4.comment.repository.CommentRepository;
import com.example.board_spring4.global.dto.StatusResponseDto;
import com.example.board_spring4.global.exception.ErrorException;
import com.example.board_spring4.global.exception.ErrorResponseDto;
import com.example.board_spring4.global.exception.ExceptionEnum;
import com.example.board_spring4.global.jwt.JwtUtil;
import com.example.board_spring4.user.entity.UserRoleEnum;
import com.example.board_spring4.user.entity.Users;
import com.example.board_spring4.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@Service
@RequiredArgsConstructor
public class CommentService {

    private final CommentRepository commentRepository;
    private final BoardRepository boardRepository;

    @Transactional
    @PostMapping("/comments")
    public ResponseEntity<?> createComment(@RequestBody CommentRequestDto commentRequestDto, Users users) {
        Board board = boardRepository.findById(commentRequestDto.getBoard_id()).orElseThrow(
                () -> new ErrorException(ExceptionEnum.BOARD_NOT_FOUND)
        );

        Comment comment = new Comment(commentRequestDto);
        comment.setBoard(board);

        if (users != null) {
            comment.setUsers(users);
        }

        commentRepository.save(comment);

        CommentResponseDto commentResponseDto = new CommentResponseDto(comment);
        return ResponseEntity.ok(commentResponseDto);
    }
    @ResponseStatus
    @ExceptionHandler({ErrorException.class})
    public ResponseEntity<ErrorResponseDto> handleException(ErrorException e) {
        return ResponseEntity.status(e.getStatus()).body(new ErrorResponseDto(e.getMessage(), e.getStatus()));
    }

    @Transactional
    public ResponseEntity<?> updateComment(Long id, CommentRequestDto commentRequestDto, Users users) {

        Board board = boardRepository.findById(commentRequestDto.getBoard_id()).orElse(null);
        if (board == null) {
            throw new ErrorException(ExceptionEnum.BOARD_NOT_FOUND);
        }

        CommentResponseDto commentResponseDto = null;

        if (users != null) {
            Comment comment = commentRepository.findById(id).orElseThrow(
                    () -> new ErrorException(ExceptionEnum.COMMENT_NOT_FOUND));

            if (!comment.getUsers().getUsername().equals(users.getUsername()) && users.getRole() != UserRoleEnum.ADMIN) {
                throw new ErrorException(ExceptionEnum.NOT_ALLOWED_AUTHORIZATIONS);
            }

            if (!comment.getBoard().getId().equals(board.getId())) {
                throw new ErrorException(ExceptionEnum.BOARD_NOT_FOUND);
            }

            comment.setComment(commentRequestDto.getComment());
            commentRepository.save(comment);

            commentResponseDto = new CommentResponseDto(comment);
        }
        return ResponseEntity.ok(commentResponseDto);
    }


    @Transactional
    public ResponseEntity<?> deleteComment(Long id, Users users) {

        Comment comment = commentRepository.findById(id).orElseThrow(
                () -> new ErrorException(ExceptionEnum.COMMENT_NOT_FOUND)
        );

        StatusResponseDto statusResponseDto = null;

        if (comment.getUsers().getUsername().equals(users.getUsername()) || users.getRole() == UserRoleEnum.ADMIN) {
            commentRepository.delete(comment);

            statusResponseDto = new StatusResponseDto("해당 댓글을 삭제하였습니다.", HttpStatus.OK.value());
        }
        return ResponseEntity.ok(statusResponseDto);
    }
}
