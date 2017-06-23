package br.ufsm.csi.PKI;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class GeraChaves {

    public static void main(String[] args) throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        // 1. Gera o par de chaves para Alice e Bob
        KeyPair keyPairBob = keyPairGenerator.generateKeyPair();
        KeyPair keyPairAlice = keyPairGenerator.generateKeyPair();

        File chavePublicaBob = new File("Chaves Bob/chavePublicaBob.key");
        File chavePrivadaBob = new File("Chaves Bob/chavePrivadaBob.key");

        // 2. Escreve a chave pública e privada do Bob
        OutputStream outputStream = new FileOutputStream(chavePublicaBob);
            outputStream.write(keyPairBob.getPublic().getEncoded());
        outputStream = new FileOutputStream(chavePrivadaBob);
            outputStream.write(keyPairBob.getPrivate().getEncoded());

        File chavePublicaAlice = new File("Chaves Alice/chavePublicaAlice.key");
        File chavePrivadaAlice = new File("Chaves Alice/chavePrivadaAlice.key");

        // 3. Escreve a chave pública e privada da Alice
        outputStream = new FileOutputStream(chavePublicaAlice);
            outputStream.write(keyPairAlice.getPublic().getEncoded());
        outputStream = new FileOutputStream(chavePrivadaAlice);
            outputStream.write(keyPairAlice.getPrivate().getEncoded());

        outputStream.close();
    }

}
