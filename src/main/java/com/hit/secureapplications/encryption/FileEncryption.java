package com.hit.secureapplications.encryption;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class FileEncryption {
	private static String fileToEncryptPath;
	private static String keyStorePath;
	private static String keyStorePass;
	private static String keyStoreType;
	private static String keyPairAlias;
	private static String keyPairPassword;
	private static String receiverSelfSignedCertAlias;
	private static String localWorkingDirectoryPath;
	private static Cipher myCipher;
	private static KeyStore keyStore;
	private static BufferedWriter LogWriter;
	
public FileEncryption(String[] arguments){
	localWorkingDirectoryPath = System.getProperty("user.dir");
	keyStorePath = arguments[0];
	keyStorePass = arguments[1];
	keyStoreType = arguments[2];
	keyPairAlias = arguments[3];
	keyPairPassword = arguments[4];
	receiverSelfSignedCertAlias = arguments[5];;
	fileToEncryptPath = arguments[6];;
	}

	/**
	 * This method encrypting a file according to the giving data
	 * when this Object was created
	 * @throws Exception
	 */
	public void encrypt() throws Exception {
		LogWriter = new BufferedWriter (new FileWriter(localWorkingDirectoryPath + "\\Log_Encryption.txt"));
		FileOutputStream configurationFileOutputStream = null;

		// Loading the store with the giving arguments
		writeToLog("Step 1: Loading the store with the giving arguments");
		loadStore();
		
		
		// Getting the receiver's public-key
		writeToLog("Step 2: Getting the receiver's public-key");
		Certificate receiverCert = keyStore.getCertificate(receiverSelfSignedCertAlias);
		PublicKey receiverPublicKey = receiverCert.getPublicKey();

		// Getting my private key in order to generate a signature
		writeToLog("Step 3: Getting the encryptor's private-key");
		PrivateKey myPrivateKey = getMyPrivateKey();
		

		File fileToEncrrypt = new File(fileToEncryptPath);
		if (fileToEncrrypt.exists() && !fileToEncrrypt.isDirectory() && fileToEncryptPath.endsWith(".txt")) {

			//Generating a symmetric key
			writeToLog("Step 4: Generating a symmetric key");
			KeyGenerator kg = KeyGenerator.getInstance("AES");// TODO -Add a provider?
			SecretKey semetricKey = kg.generateKey();
			
			//Generating a random IV
			writeToLog("Step 5: Generating a random IV");
			byte[] iv = generateRandomIV();
			
			
			//Initilatzing the cipher
			writeToLog("Step 6: Initilatzing the cipher Object");
			myCipher = Cipher.getInstance("AES//CBC//PKCS5Padding","SunJCE");// TODO -Add a provider?
			myCipher.init(Cipher.ENCRYPT_MODE, semetricKey,new IvParameterSpec(iv));
			
			//Initilatzing the signature with my private-key
			writeToLog("Step 7: Initilatzing the signature Object with the encryptor's private-key");
			Signature dataSigner = Signature.getInstance("SHA256withRSA");// TODO -Add a provider?
			dataSigner.initSign(myPrivateKey);

			//Encrypting
			writeToLog("Step 8: Encrypting... ");
			encryptingData(fileToEncrrypt,dataSigner);	
			
			//Signing on the encrypted data
			writeToLog("Step 9: Signing on the encrypted data ");
			byte[] mySignature = dataSigner.sign();


			// Encrypt the symmetric key with the public of the receiver
			writeToLog("Step 10: Encrypt the symmetric key with the public of the receiver ");
			byte[] encryptedSymmetricKey = encryptSymmetricKey(receiverPublicKey,semetricKey);
			
			
			//Saving the IV, Encrypted Semetric-Key and Signature to the configurations file
			writeToLog("Step 11: Saving the IV, Encrypted Semetric-Key and Signature to the configurations file ");
			savingToConfigurationsFile(configurationFileOutputStream,iv,encryptedSymmetricKey,mySignature);
			
			LogWriter.write("Encryption completed, No Errors Were Found");
			LogWriter.close();
		}
	}
	
	/**
	 * This private method is responsible to encrypt the data from the file
	 * and while doing so, updates the Signature Object with the encrypted data
	 * @param fileToEncrrypt - A path to the file
	 * @param dataSigner - Signature Object
	 * @throws Exception 
	 * @throws IOException
	 * @throws SignatureException
	 */
	private void encryptingData(File fileToEncrrypt, Signature dataSigner) throws Exception {
		FileOutputStream fos = null;
		FileInputStream fis = null;
		CipherInputStream cis = null;
		try {
			fos = new FileOutputStream(localWorkingDirectoryPath + "\\Encrypted_File.txt");
			fis = new FileInputStream(fileToEncrrypt);
			byte[] encryptedDataByteArray = new byte[8];
			cis = new CipherInputStream(fis, myCipher);
			int i = cis.read(encryptedDataByteArray);
			while (i != -1) {
				// Updating the data inside the Signer
				dataSigner.update(encryptedDataByteArray);
				// writing the encrypted data to the file
				fos.write(encryptedDataByteArray, 0, i);
				i = cis.read(encryptedDataByteArray);
			}
		} catch (Exception e) {
			writeToLog("Error: While trying to encrypt the data");
			LogWriter.close();
			throw new Exception("Error: While trying to encrypt the data",e);
		} finally {
			cis.close();
			fis.close();
			fos.close();
		}
	}

	/**
	 * This Private Method return the private key of the encryptor
	 * @return PrivateKey - the private key of the encryptor
	 * @throws Exception
	 */
	private PrivateKey getMyPrivateKey() throws Exception {
		
		Key myKeyPair = null;
		try {
			myKeyPair = keyStore.getKey(keyPairAlias, keyPairPassword.toCharArray());
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			writeToLog("The key: " + keyPairAlias + " is not a private-key");
			LogWriter.close();
			throw new Exception("The key: " + keyPairAlias + " is not a private-key",e);
		}
		
		PrivateKey myPrivateKey;
		if (myKeyPair instanceof PrivateKey) {
			myPrivateKey = (PrivateKey) myKeyPair;
		} else {
			writeToLog("The key: " + keyPairAlias + " is not a private-key");
			LogWriter.close();
			throw new Exception("The key: " + keyPairAlias + " is not a private-key");
		}
		return myPrivateKey;
	}

	

	/**
	 * This Private Method responsible to load the key-store
	 * @throws Exception
	 */
	private void loadStore() throws Exception {
		keyStore = KeyStore.getInstance(keyStoreType.toUpperCase());
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(keyStorePath);
			keyStore.load(fis, keyStorePass.toCharArray());
		} catch (CertificateException e) {
			writeToLog("Error while trying to load the key-store");
			LogWriter.close();
			throw new Exception("Error while trying to load the key-store", e);
		} finally {
			if (fis != null) {
				fis.close();
			}
		}
	}

	/**
	 * This Private Method is responsible to save all the configuration
	 * data(IV,Semetric-Key,Signature) to the configuration file
	 * That will be deliverd to the reciver
	 * @param configurationFileOutputStream
	 * @param iv
	 * @param encryptedSymmetricKey
	 * @param mySignature
	 * @throws IOException
	 */
	private void savingToConfigurationsFile(FileOutputStream configurationFileOutputStream, byte[] iv,
		byte[] encryptedSymmetricKey, byte[] mySignature) throws IOException {
		
		configurationFileOutputStream = new FileOutputStream(localWorkingDirectoryPath + "\\Config.txt");
	
		// Saving the IV to the configuration file
		configurationFileOutputStream.write(iv);
		
		// Saving the encrypted symmetric key to the configuration file
		configurationFileOutputStream.write(encryptedSymmetricKey);

		// Saving the my signature to the configuration file
		configurationFileOutputStream.write(mySignature);

		//Closing the output stream
		configurationFileOutputStream.close();

	}

	/**
	 * This Private Method generates a random IV
	 * dedicated for the Cipher 
	 * @return byte[] - The IV byte array
	 */
	private byte[] generateRandomIV() {
		SecureRandom rand = new SecureRandom();
		byte[] iv = new byte[16];
		rand.nextBytes(iv);
		return iv;
	}

	/**
	 * This Private Method encrypt the symmetric key that was in use in this program
	 * with the reciver's public-key
	 * @param receiverPublicKey
	 * @param semetricKey
	 * @return byte[] - the encrypt symmetric-key
	 * @throws Exception 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private byte[] encryptSymmetricKey(PublicKey receiverPublicKey, SecretKey semetricKey) throws Exception {
		try{
		myCipher = Cipher.getInstance("RSA");//TODO - Add a provider?
		myCipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
		return myCipher.doFinal(semetricKey.getEncoded());
		}catch(Exception e){
			writeToLog("Error: While trying to encrypt the semetric-key");
			LogWriter.close();
			throw new Exception();
		}
		
	}
	/**
	 * This Private methods writes the steps\\errors to the log file
	 * @param logMessage
	 * @throws IOException
	 */
	private void writeToLog(String logMessage) throws IOException {
		LogWriter.write(logMessage);
		LogWriter.newLine();
	}

}
