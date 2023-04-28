package com.example.board_spring3.comment.entity;

import com.example.board_spring3.board.entity.Board;
import com.example.board_spring3.comment.dto.CommentRequestDto;
import com.example.board_spring3.global.entity.Timestamped;
import com.example.board_spring3.user.entity.Users;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@NoArgsConstructor
public class Comment extends Timestamped {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    @Column(name = "COMMENT_ID")
    private Long id;

    @Column(nullable = false)
    private String comment;

    @ManyToOne
    @JoinColumn(name="USER_ID", nullable = false)
    private Users users;

    @ManyToOne
    @JoinColumn(name = "BOARD_ID", nullable = false)
    private Board board;

    public Comment (CommentRequestDto commentRequestDto){
        this.comment = commentRequestDto.getComment();
    }

    public void setBoard(Board board){
        this.board = board;
        board.getCommentList().add(this);
    }

       public void updateComment(CommentRequestDto commentRequestDto) {
        this.comment = commentRequestDto.getComment();
    }

    public void setUsers(Users users){
        this.users = users;
    }
}
