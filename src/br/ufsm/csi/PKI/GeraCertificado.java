package br.ufsm.csi.PKI;

import javax.crypto.Cipher;
import javax.swing.*;
import java.beans.XMLEncoder;
import java.io.*;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Scanner;

public class GeraCertificado {

    public static void main(String[] args) throws Exception {

        // 1. Instancia o certificado e seta algumas propiedades básicas
        SimpleDateFormat SDF = new SimpleDateFormat("dd/MM/yyyy");
        Certificado certificado = new Certificado();
            certificado.setDataCertificacao(new Date());
            certificado.setCertificador("Prof. Rafael");
            certificado.setValidoAte(SDF.parse("31/06/2016"));
        System.out.println("Nome do Aluno: ");
        Scanner scanIn = new Scanner(System.in);
        String nomeAluno = scanIn.nextLine();
            certificado.setNome(nomeAluno);

        // 2. Seleciona o arquivo da chave publica do aluno
        JFileChooser chooserArquivo = new JFileChooser();
        int escolha = chooserArquivo.showOpenDialog(new JFrame());
        if (escolha != JFileChooser.APPROVE_OPTION) {
            return;
        }

        // 3. Ler o arquivo da chave pública do aluno
        File arquivo = new File(chooserArquivo.getSelectedFile().getAbsolutePath());
        FileInputStream fin = new FileInputStream(arquivo);
        byte[] pubKey = new byte[(int) fin.getChannel().size()];
        fin.read(pubKey);
        certificado.setChavePublica(pubKey);

        // 4. Gera o hash do certificado sem a assinatura
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bout);
        out.writeObject(certificado);
        byte[] hash = md.digest(bout.toByteArray());

        // 5. Lê a chave privada para assinar o hash
        FileInputStream finPriv = new FileInputStream("priv.key");
        byte[] privK = new byte[(int) finPriv.getChannel().size()];
        finPriv.read(privK);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privK));

        // 5.1 Assina o hash e seta a assinatura no certificado
        Cipher cipherRSA = Cipher.getInstance("RSA");
        cipherRSA.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] assinatura = cipherRSA.doFinal(hash);
        certificado.setAssinatura(assinatura);

        // 6. Escreve o certificado como um XML
        XMLEncoder e = new XMLEncoder(
            new BufferedOutputStream(
                new FileOutputStream(nomeAluno +"_cert.xml")
            ));
        e.writeObject(certificado);
        e.close();
    }
}
