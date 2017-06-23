package br.ufsm.csi.integridade_confidencialidade;


import br.ufsm.csi.PKI.AutenticarCertificado;
import br.ufsm.csi.PKI.Certificado;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.beans.XMLDecoder;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/*
 * 1. Abrir socket
 * 2. Aguardar conexão...
 * 3. Enviar o certificado a Bob
 * 4. Recebe o objeto do Bob
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
 *       6.1. Descriptografar a chave de sessão com a chave pública
 *       6.2. Descriptografar o arquivo com a chave de sessão
 *
 * 7. Integridade
 *       7.1. Gera um resumo (hash) do arquivo descriptografado
 *       7.2. Descriptografa resumo de Bob com a chave pública de Bob
 *       7.3. Compara resumo de Alice com resumo de Bob
 *
*/

public class Alice {

    private ObjetoTroca objetoBob;
    private byte[] bytesArquivoDescripto;

    public static void main(String[] args) throws Exception {

        Alice alice = new Alice();

        // 1. Abrir Socket
        ServerSocket serverSocket = new ServerSocket(3333);
        System.out.println("\n [ 1. Socket Aberto. ] ");

        while (true) {
            // 2. Aguardar conexao...
            System.out.println(" [ 2. Aguardando conexao... ] ");
            Socket socket = serverSocket.accept();
            System.out.println(" [ 2. Cliente conectado. ] ");

            // 3. Lê o certificado da Alice
            FileInputStream fileInputStream = new FileInputStream("Certificados Ca/Joedeson (Alice)_cert.xml");
            XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(fileInputStream));
            Certificado certificadoAlice = (Certificado) decoder.readObject();
            decoder.close();

            // 3. Envia o certificado a Bob
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                objectOutputStream.writeObject(certificadoAlice);
            objectOutputStream.flush();
            System.out.println(" [ 3. Certificado enviado a Bob. ] ");

            // 4. Rebecer o objeto de Bob
            ObjectInputStream objectInputStream =
                new ObjectInputStream(socket.getInputStream());
            alice.objetoBob = (ObjetoTroca) objectInputStream.readObject();
            System.out.println(" [ 4. Objeto de Bob recebido. ] ");

            // 5. Verificar a autenticidade do certificado
            new AutenticarCertificado().autenticar(alice.objetoBob.getCertificado());

            // 6. Confidencialidade
            alice.confidencialidade(socket);

            // 7. Integridade
            alice.integridade();

            socket.close();
            System.out.println("\n [ CONEXÃO FECHADA ] \n");
        }
    }

    public void confidencialidade(Socket socket) throws Exception {

        System.out.println("\n [ 6. CONFIDENCIALIDADE ] \n");

        // 6.1. Descriptografar a chave de sessão usando a chave privada
        FileInputStream fileInputStream = new FileInputStream("Chaves Alice/chavePrivadaAlice.key");
        byte[] byteChavePrivadaAlice = new byte[(int) fileInputStream.getChannel().size()];
        fileInputStream.read(byteChavePrivadaAlice);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey chavePrivadaAlice = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(byteChavePrivadaAlice));

        Cipher cipherRSA = Cipher.getInstance("RSA");
        cipherRSA.init(Cipher.DECRYPT_MODE, chavePrivadaAlice);
        byte[] chaveSessaoDescripto = cipherRSA.doFinal(this.objetoBob.getChaveSessao());
        SecretKeySpec secretKeySpec = new SecretKeySpec(chaveSessaoDescripto, "AES");
        System.out.println("\t [ 6.1. Descriptografou a chave de sessão. ] ");

        // 6.2. Descriptografar o arquivo com chave de sessão
        Cipher cipherAES = Cipher.getInstance("AES");
        cipherAES.init(Cipher.DECRYPT_MODE, secretKeySpec);
        this.bytesArquivoDescripto = cipherAES.doFinal(this.objetoBob.getArquivo());
        System.out.println("\t [ 6.2. Descriptografou o arquivo com a chave de sessão. ] ");
    }

    public void integridade() throws Exception {

        System.out.println("\n [ 7. INTEGRIDADE ] \n");

        // 7.1. Gera um resumo (hash) do arquivo descriptografado
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        byte[] resumoHashAlice = messageDigest.digest(this.bytesArquivoDescripto);
        System.out.println("\t [ 7.1. Gerou o resumo do arquivo recebida. ] ");

        // 7.2. Descriptografar o resumo de Bob com a chave pública do Bob
        Cipher cipherRSA = Cipher.getInstance("RSA");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey chavePublicaBob = keyFactory.generatePublic(
            new X509EncodedKeySpec(objetoBob.getCertificado().getChavePublica()));
        cipherRSA.init(Cipher.DECRYPT_MODE, chavePublicaBob);
        byte[] resumoHashBobDescripto = cipherRSA.doFinal(this.objetoBob.getResumoHash());
        System.out.println("\t [ 7.2. Descriptografou o resumo do Bob com a chave pública do Bob. ] ");

        if(Arrays.equals(resumoHashAlice, resumoHashBobDescripto)) {
            System.out.println("\n [ INTEGRIDADE GARANTIDA ] ");
        } else {
            System.out.println("\n [ INTEGRIDADE NÃO GARANTIDA ] ");
        }
    }

}
