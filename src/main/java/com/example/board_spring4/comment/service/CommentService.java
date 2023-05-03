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
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class CommentService {

    private final CommentRepository commentRepository;
    private final UserRepository userRepository;
    private final BoardRepository boardRepository;
    private final JwtUtil jwtUtil;

    @Transactional
    public ResponseEntity<?> createComment(CommentRequestDto commentRequestDto, HttpServletRequest httpServletRequest) {
        try {
            String token = jwtUtil.resolveToken(httpServletRequest);

            Board board = boardRepository.findById(commentRequestDto.getBoard_id()).orElseThrow(
                    () -> new ErrorException(ExceptionEnum.BOARD_NOT_FOUND)
            );

            Users users = getUserByToken(token);

            if (users != null) {
                Comment comment = new Comment(commentRequestDto);

                comment.setBoard(board);
                comment.setUsers(users);

                commentRepository.save(comment);

                CommentResponseDto commentResponseDto = new CommentResponseDto(comment);
                return ResponseEntity.ok(commentResponseDto);
            } else {
                throw new ErrorException(ExceptionEnum.TOKEN_NOT_FOUND);
            }
        } catch (ErrorException e) {
            ErrorResponseDto errorResponseDto = new ErrorResponseDto(e.getExceptionEnum().getMessage(), e.getExceptionEnum().getStatus());
            return ResponseEntity.status(errorResponseDto.getStatus()).body(errorResponseDto);
        }
    }





    @Transactional
    public ResponseEntity<?> updateComment(Long id, CommentRequestDto commentRequestDto, HttpServletRequest httpServletRequest) {
        try {
            String token = jwtUtil.resolveToken(httpServletRequest);

            Board board = boardRepository.findById(commentRequestDto.getBoard_id()).orElse(null);
            if (board == null) {
                throw new ErrorException(ExceptionEnum.BOARD_NOT_FOUND);
            }

            Users users = getUserByToken(token);

            if (users != null) {
                Comment comment = commentRepository.findById(id).orElseThrow(() -> new ErrorException(ExceptionEnum.COMMENT_NOT_FOUND));

                if (!comment.getUsers().getUsername().equals(users.getUsername()) && users.getRole() != UserRoleEnum.ADMIN) {
                    throw new ErrorException(ExceptionEnum.NOT_ALLOWED_AUTHORIZATIONS);
                }

                if (!comment.getBoard().getId().equals(board.getId())) {
                    throw new ErrorException(ExceptionEnum.BOARD_NOT_FOUND);
                }

                comment.setComment(commentRequestDto.getComment());
                commentRepository.save(comment);

                CommentResponseDto commentResponseDto = new CommentResponseDto(comment);
                return ResponseEntity.ok(commentResponseDto);
            } else {
                throw new ErrorException(ExceptionEnum.TOKEN_NOT_FOUND);
            }
        } catch (ErrorException e) {
            ErrorResponseDto errorResponseDto = new ErrorResponseDto(e.getExceptionEnum().getMessage(), e.getExceptionEnum().getStatus());
            return ResponseEntity.status(errorResponseDto.getStatus()).body(errorResponseDto);
        }
    }



    @Transactional
    public ResponseEntity<?> deleteComment(Long id, HttpServletRequest httpServletRequest) {
        try {
            String token = jwtUtil.resolveToken(httpServletRequest);
            Users users = getUserByToken(token);

            Comment comment = commentRepository.findById(id).orElseThrow(
                    () -> new ErrorException(ExceptionEnum.COMMENT_NOT_FOUND)
            );

            if (comment.getUsers().getUsername().equals(users.getUsername()) || users.getRole() == UserRoleEnum.ADMIN) {
                commentRepository.delete(comment);

                StatusResponseDto statusResponseDto = new StatusResponseDto("해당 댓글을 삭제하였습니다.", HttpStatus.OK.value());
                return ResponseEntity.ok(statusResponseDto);
            } else {
                throw new ErrorException(ExceptionEnum.NOT_ALLOWED_AUTHORIZATIONS);
            }
        } catch (ErrorException e) {
            ErrorResponseDto errorResponseDto = new ErrorResponseDto(e.getExceptionEnum().getMessage(), e.getExceptionEnum().getStatus());
            return ResponseEntity.status(e.getExceptionEnum().getStatus()).body(errorResponseDto);
        }
    }


    private Users getUserByToken(String token) {
        Claims claims;

        if (token != null) {
            if (jwtUtil.validateToken(token)) {
                claims = jwtUtil.getUserInfoFromToken(token);
            } else {
                throw new ErrorException(ExceptionEnum.TOKEN_NOT_FOUND);
            }

            return userRepository.findByUsername(claims.getSubject()).orElseThrow(
                    () -> new ErrorException(ExceptionEnum.USER_NOT_FOUND)
            );
        }
        return null;
    }
}
