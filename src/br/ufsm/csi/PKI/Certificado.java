package br.ufsm.csi.PKI;

import java.io.Serializable;
import java.util.Date;

public class Certificado implements Serializable {

    private String nome;
    private String endereco;
    private Date validoAte;
    private byte[] chavePublica;
    private byte[] assinatura;
    private String certificador;
    private Date dataCertificacao;

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getEndereco() {
        return endereco;
    }

    public void setEndereco(String endereco) {
        this.endereco = endereco;
    }

    public byte[] getChavePublica() {
        return chavePublica;
    }

    public void setChavePublica(byte[] chavePublica) {
        this.chavePublica = chavePublica;
    }

    public byte[] getAssinatura() {
        return assinatura;
    }

    public void setAssinatura(byte[] assinatura) {
        this.assinatura = assinatura;
    }

    public String getCertificador() {
        return certificador;
    }

    public void setCertificador(String certificador) {
        this.certificador = certificador;
    }

    public Date getDataCertificacao() {
        return dataCertificacao;
    }

    public void setDataCertificacao(Date dataCertificacao) {
        this.dataCertificacao = dataCertificacao;
    }

    public Date getValidoAte() {
        return validoAte;
    }

    public void setValidoAte(Date validoAte) {
        this.validoAte = validoAte;
    }
}
