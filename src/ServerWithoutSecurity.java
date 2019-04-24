import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;

public class ServerWithoutSecurity {
	static int PORT = 4321;
	static ServerSocket serverSocket = null;
	static Socket connectionSocket = null;
	static CertificateFactory cf = null;

	//SERVER STUFF
	static String KEY = "private_key.der";
	static PrivateKey PRIVATE_KEY = null;

	static String SIGNED_CERT = "signedCert.crt";
	static X509Certificate SERVER_CERT;

	//SESSION KEY
	static Key SESSION_KEY;
	static byte[] sessionKeyBytes;

	//To exchange data with client
	static DataOutputStream toClient = null;
	static DataInputStream fromClient = null;

	// To read file
	static FileInputStream fileInputStream = null;
	static BufferedInputStream bufferedFileInputStream = null;

	//To output file
	static FileOutputStream fileOutputStream = null;
	static BufferedOutputStream bufferedFileOutputStream = null;

	static int numBytes = 0;
	/*
    packetType:
    0 = receiving filename
    1 = receiving file
    2 = nonce request/response
    3 = signedCert request/response
     */
	static int packetType = -1;

	/*
	1. when prompted, send nonce, encrypted with server private key
	2. when prompted, send signedCert, which has the server public key
	 */
	public static void main(String[] args) throws Exception {

		//Check for parameters and set
    	if (args.length > 0) {
    		parseArgs(args);
		}

    	//ESTABLISH CONNECTION AND INIT SOCKET
    	init();

		try {

			int count = 0;
			int finalNumberOfCounts = 0;

			// Transferring
			while (!connectionSocket.isClosed()) {

				packetType = fromClient.readInt();


				/*
				 *
				 * *******************NONCE***********************
				 *
				 */

				// If the packet is to request for nonce
				if (packetType == 2){

					//Read Nonce
					numBytes = fromClient.readInt();
					byte [] NonceBytes = new byte[numBytes];
					fromClient.readFully(NonceBytes, 0, numBytes);

					byte[] encryptedNonce = encryptRSA(PRIVATE_KEY, NonceBytes);

					toClient.writeInt(2);
					toClient.writeInt(encryptedNonce.length);
					toClient.write(encryptedNonce);
					toClient.flush();

				}

				/*
				 *
				 * *******************SIGNEDCERT***********************
				 *
				 */

				if (packetType == 3){

					// Open the certfile
					fileInputStream = new FileInputStream(SIGNED_CERT);
					bufferedFileInputStream = new BufferedInputStream(fileInputStream);

					byte [] fromFileBuffer = new byte[117];
					//The client encrypts the file data (in units of blocks – for
					//RSA key size of 1024 bits, the maximum block length is 117 bytes)

					// Send the FILE
					for (boolean fileEnded = false; !fileEnded;) {
						numBytes = bufferedFileInputStream.read(fromFileBuffer);
						fileEnded = numBytes < 117;

						toClient.writeInt(3); //signal transferring file data
						toClient.writeInt(numBytes);
						toClient.write(fromFileBuffer);
						toClient.flush();
					}
				}

				/*
				 *
				 * *******************SESSION KEY (AES)***********************
				 *
				 */

				if (packetType == 4){

					System.out.println("Receiving session key...");

					numBytes = fromClient.readInt();
					System.out.println("numbytes: " + numBytes);
					System.out.println("NOTE: numbytes output very weird value. But it should be 256.");


//            byte [] encryptedSessionKey = new byte[numBytes];
					byte[] encryptedSessionKey = new byte[256];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(encryptedSessionKey, 0, 256);
					System.out.println("encrypted: " + encryptedSessionKey);
					SESSION_KEY = decryptKey(PRIVATE_KEY, encryptedSessionKey);

					System.out.println(SESSION_KEY);
					System.out.println("SESS: " + SESSION_KEY);

				}
				/*
				 *
				 * *******************FILENAME***********************
				 *
				 */

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					numBytes = fromClient.readInt();
					byte [] filenameEncrypted = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filenameEncrypted, 0, numBytes);

					byte[] filename = decryptAES(SESSION_KEY, filenameEncrypted);
					System.out.println(new String(filename));

					fileOutputStream = new FileOutputStream("recv_" + new String(filename));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				}
				/*
				 *
				 * *******************FILE***********************
				 *
				 */

				else if (packetType == 1) {

					numBytes = fromClient.readInt();
					System.out.println(numBytes);
					byte [] blockEncrypted = new byte[numBytes];
					fromClient.readFully(blockEncrypted, 0, numBytes);

					byte[] block = decryptAES(SESSION_KEY, blockEncrypted);
					count += 1;

					if (numBytes > 0)
						bufferedFileOutputStream.write(block);


					if (count == finalNumberOfCounts) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				} else if (packetType == 5){
					finalNumberOfCounts = fromClient.readInt();
				}
			}
		} catch (Exception e) {e.printStackTrace();}

	}

	/*
	Parse input arguments:
	args0 = port
 	*/
	public static void parseArgs(String[] args){
		PORT = Integer.parseInt(args[0]);
	}

	public static void init() throws Exception {
		cf = CertificateFactory.getInstance("X.509");

		//Cert is signed when it is encrypted with CS's private key.
		InputStream signed_cert = new FileInputStream(SIGNED_CERT);
		SERVER_CERT =(X509Certificate)cf.generateCertificate(signed_cert);

		PRIVATE_KEY = getPrivateKey(KEY);

		try{
			System.out.println("Listening for connection...");

			//Start server socket and accept connection
			serverSocket = new ServerSocket(PORT);

			// Connect to client and get the input and output streams
			connectionSocket = serverSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

		} catch (Exception e) {e.printStackTrace();}
	}

	//To send nonce
	public static byte[] encryptRSA (Key key, byte[] text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		// encrypt the text
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encrypted = cipher.doFinal(text);

		return encrypted;
	}

	//DECRYPT SESSION KEY
	public static Key decryptKey (Key server_private_key, byte[] encryptedBytes) throws InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException {

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, server_private_key);
		byte[] decodedKey = cipher.doFinal(encryptedBytes);
		Key originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

		return originalKey;
	}

	public static byte[] decryptAES (Key key, byte[] text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] result = cipher.doFinal(text);

		return result;
	}

	public static PrivateKey getPrivateKey (String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
		PKCS8EncodedKeySpec spec =	new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

}
