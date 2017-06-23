package br.ufsm.csi.integridade_confidencialidade;

import br.ufsm.csi.PKI.AutenticarCertificado;
import br.ufsm.csi.PKI.Certificado;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.beans.XMLDecoder;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/*
 * 1. Selecionar arquivo
 * 2. Ler o arquivo
 * 3. Conectar a Alice
 * 4. Receber o certificado da Alice
 *
 * 5. Verificar a autenticidade do certificado
 *       5.1. Verificar a validade
 *       5.2. Retirar a assinatura do certificado da Alice
 *       5.3. Gerar o hash do certificado
 *       5.4. Ler a chave publica da CA
 *       5.5. Descriptografar assinatura do certificado com a chave publica da CA
 *       5.6. Comparar o hash gerado com a assinatura do certificado
 *
 * 6. Confidencialidade
 *       6.1. Criar a chave de sessão
 *       6.2. Criptografa o arquivo com a chave de sessão
 *       6.3. Criptografa a chave de sessão com a chave pública de Alice
 *
 * 7. Integridade
 *       7.1. Gerar resumo (hash) do arquivo
 *       7.2. Criptografas resumo (hash) com chave privada de Bob
 *
 * 8. Enviar objeto a Alice
 *       8.1. Arquivo criptografado
 *       8.2. Nome do arquivo
 *       8.3. Chave de sessão
 *       8.4. Certificado do Bob
 *       8.5. Resumo (hash)
*/

public class Bob {

    private ObjetoTroca objetoBob;
    private Socket socket;

    public Bob() {
        this.objetoBob = new ObjetoTroca();
    }

    public static void main(String[] args) throws Exception {

        Bob bob = new Bob();

        // 1. Selecionar arquivo.
        JFileChooser arquivoSelecionado = new JFileChooser();
        if(arquivoSelecionado.showOpenDialog(new JFrame()) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        bob.objetoBob.setNomeArquivo(arquivoSelecionado.getSelectedFile().getAbsolutePath());
        System.out.println("\n [ 1. Selecionou o arquivo: "            +bob.objetoBob.getNomeArquivo()+ " ] ");

        // 2. Ler o arquivo
        FileInputStream fileInputStream = new FileInputStream(
            new File(arquivoSelecionado.getSelectedFile().getAbsolutePath()));
        byte[] bytesArquivo = new byte[(int) fileInputStream.getChannel().size()];
        fileInputStream.read(bytesArquivo);
        System.out.println(" [ 2. Leu o arquivo. ] ");

        // 3. Conectar a Alice
        bob.socket = new Socket("localhost", 3333);
        System.out.println(" [ 3. Conectou a Alice. ] ");

        // 4. Receber o certificado de Alice
        ObjectInputStream objectInputStream = new ObjectInputStream(bob.socket.getInputStream());
        Certificado certificadoAlice = (Certificado) objectInputStream.readObject();
        System.out.println(" [ 4. Recebeu o certificado da Alice. ] ");

        // 5. Verificar a autenticidade do certificado
        new AutenticarCertificado().autenticar(certificadoAlice);

        // 6. Confidencialidade
        bob.confidencialidade(bytesArquivo, certificadoAlice.getChavePublica());

        // 7. Integridade
        bob.integridade(bytesArquivo);

        // 8. Enviar objeto a Alice
        fileInputStream = new FileInputStream("Certificados Ca/Joedeson (Bob)_cert.xml");
        XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(fileInputStream));
        bob.objetoBob.setCertificado((Certificado) decoder.readObject());
        decoder.close();

        ObjectOutputStream objectOutputStream = new ObjectOutputStream(bob.socket.getOutputStream());
            objectOutputStream.writeObject(bob.objetoBob);
            objectOutputStream.close();
        bob.socket.close();

        System.out.println("\n [ 8. Objeto enviado a Alice. ] \n");

        System.out.println("\t [ 8.1. Arquivo criptografado: " +bob.objetoBob.getArquivo().length+ " ]");
        System.out.println("\t [ 8.2. Chave de sessão: " +bob.objetoBob.getChaveSessao().length+ " ]");
        System.out.println("\t [ 8.3. Resumo criptografado: " +bob.objetoBob.getResumoHash().length+ " ]");
        System.out.println("\t [ 8.4. Certificado do Bob. ]");

        System.out.println("\n [ CONEXÃO FECHADA ] ");

        System.exit(0);
    }

    public void confidencialidade(byte[] bytesArquivo, byte[] byteChavePublicaAlice) throws Exception {

        System.out.println("\n [ 6. CONFIDENCIALIDADE ] \n");

        // 6.1. Criar a chave de sessão
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println("\t [ 6.1. Criou a chave de sessão. ] ");

        // 6.2. Criptografar o arquivo com chave de sessão
        Cipher cipherAES = Cipher.getInstance("AES");
        cipherAES.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] bytesArquivoCripto = cipherAES.doFinal(bytesArquivo);
        System.out.println("\t [ 6.2. Criptografou o arquivo com a chave de sessão. ] ");

        // 6.3. Criptografa chave de sessão com a chave pública de Alice
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey chavePublicaAlice = keyFactory.generatePublic(new X509EncodedKeySpec(byteChavePublicaAlice));

        Cipher cipherRSA = Cipher.getInstance("RSA");
        cipherRSA.init(Cipher.ENCRYPT_MODE, chavePublicaAlice);
        byte[] chaveSessao = cipherRSA.doFinal(secretKey.getEncoded());
        System.out.println("\t [ 6.3. Criptografa a chave de sessão com a chave pública de Alice. ] ");

        this.objetoBob.setArquivo(bytesArquivoCripto);
        this.objetoBob.setChaveSessao(chaveSessao);
    }

    public void integridade(byte[] bytesArquivo) throws Exception {

        System.out.println("\n [ 7. INTEGRIDADE ] \n");

        // 7.1. Gera um resumo (hash) da mensagem
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        byte[] resumoHash = messageDigest.digest(bytesArquivo);
        System.out.println("\t [ 7.1. Gerou o resumo (hash) da mensagem. ] ");

        // 7.2. Criptografa resumo (hash com a chave privada de Bob
        FileInputStream fileInputStream = new FileInputStream("Chaves Bob/chavePrivadaBob.key");
        byte[] byteChavePrivadaBob = new byte[(int) fileInputStream.getChannel().size()];
        fileInputStream.read(byteChavePrivadaBob);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey chavePrivadaBob = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(byteChavePrivadaBob));

        Cipher cipherRSA = Cipher.getInstance("RSA");
        cipherRSA.init(Cipher.ENCRYPT_MODE, chavePrivadaBob);
        byte[] resumoHashCripto = cipherRSA.doFinal(resumoHash);
        System.out.println("\t [ 7.2. Resumo Criptografado. ] ");

        this.objetoBob.setResumoHash(resumoHashCripto);
    }
}


