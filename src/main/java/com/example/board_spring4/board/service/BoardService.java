package com.example.board_spring4.board.service;

import com.example.board_spring4.board.dto.BoardRequestDto;
import com.example.board_spring4.board.dto.BoardResponseDto;
import com.example.board_spring4.board.entity.Board;
import com.example.board_spring4.board.repository.BoardRepository;
import com.example.board_spring4.comment.dto.CommentResponseDto;
import com.example.board_spring4.comment.entity.Comment;
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

import java.util.ArrayList;
import java.util.List;

@Service //
@RequiredArgsConstructor // generates a constructor for the class that initializes all final fields
public class BoardService {

    //주입
    private final BoardRepository boardRepository;
    @Transactional
    public ResponseEntity<?> createBoard(BoardRequestDto boardRequestDto, Users users) {

        Board board = new Board(boardRequestDto, users);
        boardRepository.save(board);
        BoardResponseDto boardResponseDto = new BoardResponseDto(board);
        return ResponseEntity.ok(boardResponseDto);
    }

    public ResponseEntity<?> getBoard(Long id) {
        Board board = boardRepository.findById(id).orElseThrow(
                () -> new ErrorException(ExceptionEnum.BOARD_NOT_FOUND)
        );

        List<CommentResponseDto> comments = new ArrayList<>();
        for (Comment comment : board.getComment()) {
            comments.add(new CommentResponseDto(comment));
        }

        BoardResponseDto boardResponseDto = new BoardResponseDto(board, comments);
        return ResponseEntity.ok(boardResponseDto);
    }


    @Transactional(readOnly = true)
    public List<BoardResponseDto> getBoardList() {
        List<Board> boardList = boardRepository.findAllByOrderByModifiedAtDesc();

        List<BoardResponseDto> boards = new ArrayList<>();

        for (Board board : boardList) {
            List<CommentResponseDto> comments = new ArrayList<>();
            for (Comment comment : board.getComment()) {
                comments.add(new CommentResponseDto(comment));
            }
            boards.add(new BoardResponseDto(board, comments));
        }
        return boards;
    }

    @Transactional
    public ResponseEntity<?> updateBoard(Long id, BoardRequestDto boardRequestDto, Users users) {

        Board board = boardRepository.findById(id).orElseThrow(
                () -> new ErrorException(ExceptionEnum.BOARD_NOT_FOUND)
        );
        if (board.getUsers().getUsername().equals(users.getUsername()) || users.getRole() == UserRoleEnum.ADMIN) {
            board.update(boardRequestDto);
        return ResponseEntity.ok(new BoardResponseDto(board));
        }else{
            throw new ErrorException(ExceptionEnum.NOT_ALLOWED_AUTHORIZATIONS);
        }
    }


    @Transactional
    public ResponseEntity<?> deleteBoard(Long id, Users users) {
        Board board = boardRepository.findById(id).orElseThrow(
                () -> new ErrorException(ExceptionEnum.BOARD_NOT_FOUND)
        );
        if (users.getUsername().equals(board.getUsers().getUsername()) || users.getRole() == UserRoleEnum.ADMIN) {
            boardRepository.deleteById(board.getId());
            return new ResponseEntity<>(new StatusResponseDto("게시글을 삭제하였습니다.", HttpStatus.OK.value()), HttpStatus.OK);
        } else {
            throw new ErrorException(ExceptionEnum.NOT_ALLOWED_AUTHORIZATIONS);
        }
    }

}