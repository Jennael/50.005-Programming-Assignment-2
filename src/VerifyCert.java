import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate.*;

/*
ca - "cacse.crt"
server - "signedCert.crt"
 */

public class VerifyCert {
    static CertificateFactory cf;

    public static void main(String[] args) throws CertificateException, NoSuchAlgorithmException, FileNotFoundException, SignatureException, NoSuchProviderException, InvalidKeyException {
        VerifyCertFiles("cacse.crt", "signedCert.crt");
    }

    /*
    1. Get public key from cacse.crt
    2. ServerCert.checkValidity();
    3. ServerCert.verify(public key);
     */
    public static void VerifyCertFiles(String ca, String server) throws CertificateNotYetValidException, CertificateExpiredException, CertificateException, FileNotFoundException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        cf = CertificateFactory.getInstance("X.509");

        InputStream cacse = new FileInputStream(ca);
        X509Certificate CAcert =(X509Certificate) cf.generateCertificate(cacse);

        //CA's public key
        PublicKey CAkey = CAcert.getPublicKey();

        InputStream signedCert = new FileInputStream(server);
        X509Certificate ServerCert =(X509Certificate)cf.generateCertificate(signedCert);

        ServerCert.checkValidity();
        ServerCert.verify(CAkey);
    }

    public static Boolean VerifyCert(X509Certificate CAcert, X509Certificate ServerCert){

        //CA's public key
        PublicKey CAkey = CAcert.getPublicKey();

        try{
            ServerCert.checkValidity();
            ServerCert.verify(CAkey);

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

}
