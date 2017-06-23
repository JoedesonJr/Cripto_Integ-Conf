package br.ufsm.csi.PKI;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

public class AutenticarCertificado {

    public void autenticar(Certificado certificado) throws Exception {

        System.out.println("\n [ 5. AUTENTICAR CERTIFICADO ] \n");

        // 5. Verificar a validade do certificado
        if(certificado.getValidoAte().compareTo(new Date()) == 1) {
            System.out.println("\t [ 5.1. Certificado válido:  "
                +new SimpleDateFormat("dd/MM/yyyy").format(certificado.getValidoAte()) +"] ");
        } else {
            System.out.println("\t [ 5.1. Certificado inválido:  "
                +new SimpleDateFormat("dd/MM/yyyy").format(certificado.getValidoAte()) +"] ");
        }

        // 5.2. Retirar a assinatura do certificado da Alice
        byte[] assinatura = certificado.getAssinatura();
        certificado.setAssinatura(null);
        System.out.println("\t [ 5.2. Assinatura retirada do certificado. ] ");

        // 5.3. Gerar o hash do certificado
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
            bout.write(certificado.getNome().getBytes("ISO-8859-1"));
            bout.write(new SimpleDateFormat("dd/MM/yyyy").format(
                certificado.getValidoAte()).getBytes("ISO-8859-1"));
            bout.write(certificado.getChavePublica());
        byte[] hashCertificado = md.digest(bout.toByteArray());
        System.out.println("\t [ 5.3. Hash gerado. ] ");

        // 5.4. Ler a chave publica da CA
        FileInputStream fileInputStream = new FileInputStream("Certificados CA/pub.key");
        byte[] byteChavePublicaCA = new byte[(int) fileInputStream.getChannel().size()];
        fileInputStream.read(byteChavePublicaCA);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey chavePublicaCA = keyFactory.generatePublic(new X509EncodedKeySpec(byteChavePublicaCA));
        System.out.println("\t [ 5.4. Chave pública da CA lida. ] ");

        // 5.5. Descriptografar assinatura do certificado com a chave publica da CA
        Cipher cipherRSA = Cipher.getInstance("RSA");
        cipherRSA.init(Cipher.DECRYPT_MODE, chavePublicaCA);
        byte[] assinaturaDescripto = cipherRSA.doFinal(assinatura);
        System.out.println("\t [ 5.5. Assinatura do certificado descriptografado. ] ");

        // 5.6. Comparar o hash gerado com a assinatura do certificado
        if(Arrays.equals(hashCertificado, assinaturaDescripto)) {
            System.out.println("\t [ 5.6. Comparou: CERTIFICADO VALIDO ]");
        } else {
            System.out.println("\t [ 5.6. Comparou: CERTIFICADO INVALIDO ]");
        }

    }
}
