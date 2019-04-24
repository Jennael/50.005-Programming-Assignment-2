import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;

public class ClientWithoutSecurity {
    static String FILENAME = "message.txt";
    static int PORT = 4321;
    static String SERVER = "localhost";
    static Socket clientSocket = null;
    static int NONCE = 0;
    static CertificateFactory cf;

    //CA
    static String CACSE = "cacse.crt";
    static X509Certificate CA_CERT;

    //SERVER
    static X509Certificate SERVER_CERT;
    static PublicKey SERVER_PUBLIC_KEY;
    static Key SESSION_KEY;
    static Boolean AUTHENTIC = false;

    // To exchange data with server
    static DataOutputStream toServer = null;
    static DataInputStream fromServer = null;

    // To read file
    static FileInputStream fileInputStream = null;
    static BufferedInputStream bufferedFileInputStream = null;

    //To output file
    static FileOutputStream fileOutputStream = null;
    static BufferedOutputStream bufferedFileOutputStream = null;

    static int numBytes = 0;


    /*
    1. Ask for encrypted nonce
    2. Ask for signed cert
    3. Get CA public key from cacse
    4. Verify signed cert with CA public key
    if PASS:
    5. Get server public key from verified signed cert
    6. decrypt nonce
     */
    public static void main(String[] args) throws CertificateException, IOException {

        //Check for parameters and set
        if (args.length > 0) {
            parseArgs(args);
        }

        init();

        /*
		packetType signal:
		0 = receiving filename
		1 = receiving file
		2 = nonce request/response
		3 = signedCert request/response
		4 = request session key (encrypted with RSA
		 */

        long timeStarted = System.nanoTime();

        try {

            /*
             *
             * *******************NONCE***********************
             *
             */
            System.out.println("Requesting server certification...");

            //packetType signal - NONCE
            toServer.writeInt(2);

            NONCE = 3;
            byte[] NonceBytes = String.valueOf(NONCE).getBytes();

            toServer.writeInt(NonceBytes.length);
            toServer.write(NonceBytes);
            toServer.flush();
            //wait for nonce encrypted with server private key
            while (fromServer.readInt() != 2){
            }

            //Read encrypted nonce
            numBytes = fromServer.readInt();
            byte [] EncryptedNonceBytes = new byte[numBytes];
            fromServer.readFully(EncryptedNonceBytes, 0, numBytes);

            /*
             *
             * *******************SIGNEDCERT***********************
             *
             */

            // Request cert
            byte [] serverCert = null;

            toServer.writeInt(3); //signal request cert

            fileOutputStream = new FileOutputStream("recv_server_cert.txt");
            bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

            while (fromServer.readInt() == 3) {

                numBytes = fromServer.readInt();
                serverCert = new byte[numBytes];
                fromServer.readFully(serverCert, 0, numBytes);

                if (numBytes > 0)
                    bufferedFileOutputStream.write(serverCert, 0, numBytes);

                if (numBytes < 117) {
                    System.out.println("Fin receiving cert...");
                    if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                    if (bufferedFileOutputStream != null) fileOutputStream.close();

                    break;
                }
            }

//            byte[] signedCertData = Files.readAllBytes(Paths.get("recv_server_cert.txt"));
//            InputStream signedCert = new ByteArrayInputStream(signedCertData);
            InputStream signedCert = new FileInputStream("recv_server_cert.txt");
            SERVER_CERT =(X509Certificate)cf.generateCertificate(signedCert);
            InputStream cacse = new FileInputStream(CACSE);
            CA_CERT =(X509Certificate)cf.generateCertificate(cacse);

            //Decryption of nonce later
            SERVER_PUBLIC_KEY = SERVER_CERT.getPublicKey();
            byte[] nonce = decryptRSA(SERVER_PUBLIC_KEY, EncryptedNonceBytes);

            //Verification
            if (!VerifyCert(CA_CERT, SERVER_CERT) || !new String(nonce).equals(String.valueOf(NONCE))){
                System.out.println("SERVER VALIDITY FAILS");
            } else{
                AUTHENTIC = true;
            }


            /*
             *
             * *******************SESSION KEY (AES)***********************
             *
             */

            //signal to transfer session key
            toServer.writeInt(4);

            System.out.println("Sending session key...");

            byte[] sessionKeyBytes = generateKey();
//            byte[] encryptedSessionKey = encryptRSA(SERVER_PUBLIC_KEY, SESSION_KEY.getEncoded());

            toServer.writeInt(sessionKeyBytes.length);
            System.out.println("length sent: " + sessionKeyBytes.length);
            toServer.write(sessionKeyBytes);
            toServer.flush();
            System.out.println("bytes sent: " + sessionKeyBytes);

            /*
             *
             * *******************FILENAME***********************
             *
             */

            System.out.println("Sending file...");

            // Send the FILENAME
            toServer.writeInt(0); //signal transferring filename
            toServer.writeInt(encryptAES(SESSION_KEY, FILENAME.getBytes()).length);
            toServer.write(encryptAES(SESSION_KEY, FILENAME.getBytes()));
//            toServer.writeInt(FILENAME.getBytes().length);
//            toServer.write(FILENAME.getBytes());
            //toServer.flush();

            /*
             *
             * *******************FILE***********************
             *
             */

            // Open the file
            fileInputStream = new FileInputStream(FILENAME);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            byte [] fromFileBuffer = new byte[117];
            //The client encrypts the file data (in units of blocks – for
            //RSA key size of 1024 bits, the maximum block length is 117 bytes)

            int count = 0;

            // Send the FILE
            for (boolean fileEnded = false; !fileEnded;) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);
                fileEnded = numBytes < 117;

                byte[] encryptedMessage = encryptAES(SESSION_KEY, fromFileBuffer);
                count++;

                if (fileEnded) {
                    toServer.writeInt(5);
                    toServer.writeInt(count);
                    toServer.flush();
                }

                toServer.writeInt(1); //signal transferring file data
//                toServer.writeInt(numBytes);
                toServer.writeInt(encryptedMessage.length);
                System.out.println(encryptedMessage.length);
                toServer.write(encryptedMessage);

                toServer.flush();
            }

            bufferedFileInputStream.close();
            fileInputStream.close();

            System.out.println("Closing connection...");

            clientSocket.close();

        } catch (Exception e) {e.printStackTrace();}

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
    }

    /*
    Parse input arguments:
    args0 = filename
    args1 = server
    args2 = port
    */
    public static void parseArgs(String[] args){

        if (args.length > 0) {
            FILENAME = args[0];
        }

        // socket details
        if (args.length > 1) SERVER = args[1];
        if (args.length > 2) PORT = Integer.parseInt(args[2]);
    }

    public static void init() throws CertificateException {

        cf = CertificateFactory.getInstance("X.509");

        try{
            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(SERVER, PORT);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());
        }catch (Exception e) {e.printStackTrace();}
    }

    public static Boolean VerifyCert(X509Certificate CAcert, X509Certificate ServerCert){

        //CA's public key
        PublicKey CAkey = CAcert.getPublicKey();

        try{
            ServerCert.checkValidity();
            ServerCert.verify(CAkey);
            System.out.println("VERIFIED");
            return true;
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static byte[] decryptRSA (Key key, byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // decrypt the text
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(bytes);

        return decrypted;
    }

    /*
    Generate an AES 128 bit key
    */
    public static byte[] generateKey () throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        //GENERATE KEY
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SESSION_KEY = keyGen.generateKey();
        System.out.println("SESS: " + SESSION_KEY);
        byte[] secretKeyBytes = SESSION_KEY.getEncoded();

        //INIT CIPHER TO ENCRYPT WITH RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        cipher.init(Cipher.ENCRYPT_MODE, SERVER_PUBLIC_KEY);
        byte[] encryptedSecretKey = cipher.doFinal(secretKeyBytes);

//        byte[] encryptedSecretKey = encryptRSA(SERVER_PUBLIC_KEY, secretKeyBytes);
        System.out.println("encryptedSecretKey length: " + encryptedSecretKey.length);

        return encryptedSecretKey;
    }

    public static byte[] encryptAES (Key key, byte[] text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] result = cipher.doFinal(text);

        return result;
    }


}
