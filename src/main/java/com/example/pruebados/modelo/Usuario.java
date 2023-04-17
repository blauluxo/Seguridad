package com.example.pruebados.modelo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

//---------datos relevantes sin importancia.
//@DiscriminatorColumn(name ="prueba")-->Si queremos discriminar alguna columna
//@JsonIgnore -->Para ignorar en la salida a json que se muestre este dato
@Entity
@Table(name="Usuario")
@Inheritance (strategy = InheritanceType.TABLE_PER_CLASS)
public abstract class Usuario {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "usuario_seq")
    @SequenceGenerator(name = "usuario_seq", sequenceName = "usuario_seq", allocationSize = 1)
    @Column(name = "ID")
    private Integer id;
    //--columnas de la tabla basicas.
    @Basic
    @Column(name = "NOMBRE")
    private String nombre;
    @Basic
    @Column(name = "APELLIDOS")
    private String apellidos;
    @Basic
    @Column(name = "USUAIO")
    private String usuaio;
    @Basic
    @Column(name = "CLAVE")
    private String clave;

    @Basic
    @Column(name = "EMAIL")
    private String email;
    @Basic
    @Column(name = "PASSWORD")
    private String password;



    //--aqui hago la union con citas, la hace el usuario(un usuario puede tener muchas citas)--

   /* @OneToMany
    @JoinColumn(name="citaUsuarioId")
    List<Cita> listaCitas = new ArrayList<>();
   */
    public Usuario() {

    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getApellidos() {
        return apellidos;
    }

    public void setApellidos(String apellidos) {
        this.apellidos = apellidos;
    }

    public String getUsuaio() {
        return usuaio;
    }

    public void setUsuaio(String usuaio) {
        this.usuaio = usuaio;
    }

    public String getClave() {
        return clave;
    }

    public void setClave(String clave) {
        this.clave = clave;
    }

}
