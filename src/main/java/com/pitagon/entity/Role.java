package com.pitagon.entity;
import javax.persistence.*;
@Entity
@Table(name = "role")
public class Role {

    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "name", length = 50, nullable = false)
    @Enumerated(value = EnumType.STRING)
    private ERole name;


    public enum ERole {
        ROLE_USER, ROLE_MODERATOR, ROLE_ADMIN
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public ERole getName() {
        return name;
    }

    public void setName(ERole name) {
        this.name = name;
    }



}
