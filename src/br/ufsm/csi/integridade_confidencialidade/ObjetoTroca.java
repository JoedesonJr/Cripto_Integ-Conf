package br.ufsm.csi.integridade_confidencialidade;

import br.ufsm.csi.PKI.Certificado;

import java.io.Serializable;
import java.security.PublicKey;

public class ObjetoTroca implements Serializable {

    private byte[] arquivo;
    private String nomeArquivo;
    private byte[] chavePublica;
    private byte[] chaveSessao;
    private byte[] resumoHash;
    private Certificado certificado;


    public byte[] getArquivo() {
        return arquivo;
    }

    public void setArquivo(byte[] arquivo) {
        this.arquivo = arquivo;
    }

    public String getNomeArquivo() {
        return nomeArquivo;
    }

    public void setNomeArquivo(String nomeArquivo) {
        this.nomeArquivo = nomeArquivo;
    }

    public byte[] getChavePublica() {
        return chavePublica;
    }

    public void setChavePublica(byte[] chavePublica) {
        this.chavePublica = chavePublica;
    }

    public byte[] getChaveSessao() {
        return chaveSessao;
    }

    public void setChaveSessao(byte[] chaveSessao) {
        this.chaveSessao = chaveSessao;
    }

    public byte[] getResumoHash() {
        return resumoHash;
    }

    public void setResumoHash(byte[] resumoHash) {
        this.resumoHash = resumoHash;
    }

    public Certificado getCertificado() {
        return certificado;
    }

    public void setCertificado(Certificado certificado) {
        this.certificado = certificado;
    }
}
