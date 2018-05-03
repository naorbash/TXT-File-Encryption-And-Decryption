package com.hit.secureapplications.decryption;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FileDecryption {
	private static String fileToDecrypt;
	private static String keyStorePass;
	private static String keyStorePath;
	private static String keyStoreType;
	private static String keyPairAlias;
	private static String keyPairPassword;
	private static String senderSelfSignedCertAliss;
	private static String configFilePath;
	private static Cipher myCipher;
	private static KeyStore keyStore;
	private static String localWorkingDirectoryPath;
	private static FileInputStream configurationFileReader;
	private static BufferedWriter LogWriter;
	
	public FileDecryption(String[] arguments){
		localWorkingDirectoryPath = System.getProperty("user.dir");
		keyStorePath = arguments[0];
		keyStorePass = arguments[1];
		keyStoreType = arguments[2];
		keyPairAlias = arguments[3];
		keyPairPassword = arguments[4];
		senderSelfSignedCertAliss = arguments[5];
		configFilePath = arguments[6];
		fileToDecrypt = arguments[7];;
		
	}

	/**
	 * This method decrypting an encrypted file 
	 * according to the giving data when this Object was created
	 * @throws Exception
	 */
	public void decrypt() throws Exception{
		configurationFileReader = new FileInputStream(configFilePath);
		LogWriter = new BufferedWriter (new FileWriter(localWorkingDirectoryPath + "\\Log_Decryption.txt"));
		

		// Loading the store with the giving arguments
		writeToLog("Step 1: Loading the store with the giving arguments ");
		loadStore();

		// Loading the sender's certificate
		writeToLog("Step 2: Getting the sender certificate");
		Certificate senderCert = keyStore.getCertificate(senderSelfSignedCertAliss);
		if(senderCert==null) {
			logError("The entered certificate alias: \"" +senderSelfSignedCertAliss+ "\" dose not exist in the keys store.");
		}

		// Loading the reciver's private-key to decrypt the semetric key
		writeToLog("Step 3: Getting the reciver's private-key");
		PrivateKey myPrivateKey = getMyPrivateKey();

		// loading the IV from the configuration file
		writeToLog("Step 4: loading the IV from the configuration file");
		byte[] iv = new byte[16];
		if (configurationFileReader.read(iv) != -1) {

			// Getting the encrypted symmetric-key
			writeToLog("Step 5: Getting the encrypted semetric-key");
			byte[] encryptedSymmetricKey = new byte[256];
			if (configurationFileReader.read(encryptedSymmetricKey) != -1) {

				// Decrypting the symmetric-key
				writeToLog("Step 6: Decrypting the semetric-key");
				SecretKey semetricKey = semetricKeyDecryption(myPrivateKey, encryptedSymmetricKey);

				// Getting the sender's signature on the data
				writeToLog("Step 7: Getting the sender's signature on the data");
				byte[] senderSignature = new byte[configurationFileReader.available()];
				if (configurationFileReader.read(senderSignature) != -1) {

					// Initialize the Signature Object for verification with the sender's certificate
					writeToLog("Step 8: Initialize the Signature Object for verification with the sender's certificate");
					Signature signatureVer = Signature.getInstance("SHA256withRSA");// TODO -Add provider?
					signatureVer.initVerify(senderCert);
					
					//Update the Signature Object with the data to be verified
					writeToLog("Step 9: Update the Signature Object with the data to be verified");
					loadDataToSignature(signatureVer);
					
					// Verify the sender's signature
					writeToLog("Step 10: Verify the sender's signature");
					boolean verifies = signatureVer.verify(senderSignature);
					
					if (verifies) {
						// Decrypting the encrypted data and saving it to a new file "decryptedFile.txt"
						writeToLog("Step 11: Decrypting the encrypted data and saving it to a new file \"decryptedFile.txt\" ");
						ByteArrayOutputStream decrpytedDataByteStream = decryptData(semetricKey,iv);
						FileWriter fw = new FileWriter(localWorkingDirectoryPath + "\\Decrypted_File.txt");
						fw.write(new String(decrpytedDataByteStream.toByteArray()));
						fw.close();
					} else {
						logError("Signature verification has failed");
					}
				} else {
					logError("Error: while reading the signature from the configuration file");
				}
			} else {
				logError("Error: while reading the encrypted semetric-key from the configuration file");
			}
		} else {
			logError("Error: while reading the IV from the configuration file");
		}
		writeToLog("Decryption completed, No Errors Were Found");
		LogWriter.close();
		configurationFileReader.close();
	}

	/**
	 * This private method responsible on decrypting the data from the giving file.
	 * This happens after the signature verification process has passed successfully
	 * @param semetricKey - the semetric-key that was used in the encryption process
	 * @param iv - the IV that was used in the encryption process
	 * @return ByteArrayOutputStream - the decrpyted data in a ByteStream Object
	 * @throws Exception 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IOException
	 */
	private ByteArrayOutputStream decryptData(SecretKey semetricKey, byte[] iv) throws Exception {
		CipherInputStream cis = null;
		FileInputStream encyptedDataFileReader = null;
		try {
			myCipher = Cipher.getInstance("AES//CBC//PKCS5Padding", "SunJCE");// add
																				// provider?
			myCipher.init(Cipher.DECRYPT_MODE, semetricKey, new IvParameterSpec(iv));
			encyptedDataFileReader = new FileInputStream(fileToDecrypt);
			cis = new CipherInputStream(encyptedDataFileReader, myCipher);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] decryptedDataByteArray = new byte[1024];
			int numberOfBytedRead;
			while ((numberOfBytedRead = cis.read(decryptedDataByteArray)) >= 0) {
				baos.write(decryptedDataByteArray, 0, numberOfBytedRead);
			}
			return baos;
		} catch (Exception e) {
			writeToLog("Error: While trying to decrypt the data");
			LogWriter.close();
			configurationFileReader.close();
			throw new Exception("Error: While trying to decrypt the data", e);
		} finally {
			cis.close();
			encyptedDataFileReader.close();
		}
	}

	/**
	 * This private method responsible to load all the encrypted data
	 * to the Signature Object while using the update method.
	 * This will use us when checking the sender's signature on the data.
	 * @param signatureVer
	 * @throws SignatureException
	 * @throws IOException
	 */
	private void loadDataToSignature(Signature signatureVer) throws SignatureException, IOException  {
		FileInputStream datafis = new FileInputStream(fileToDecrypt);
		BufferedInputStream bufin = new BufferedInputStream(datafis);

		byte[] buffer = new byte[1024];
		int len;
		while (bufin.available() != 0) {
		    len = bufin.read(buffer);
		    signatureVer.update(buffer, 0, len);
		};

		bufin.close();	
	}

	/**
	 * This Private Method decrypts the symmetric key that was in use while encrypting the data.
	 * The semetric key will be decrypt with the reciver's private-key
	 * @param myPrivateKey
	 * @param encryptedSymmetricKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private SecretKey semetricKeyDecryption(PrivateKey myPrivateKey, byte[] encryptedSymmetricKey) throws Exception {
		try {
			myCipher = Cipher.getInstance("RSA", "SunJCE");
			myCipher.init(Cipher.DECRYPT_MODE, myPrivateKey);
			byte[] decryptedSymmetricKey = myCipher.doFinal(encryptedSymmetricKey);
			return new SecretKeySpec(decryptedSymmetricKey, "AES");
		} catch (Exception e) {
			writeToLog("Error: While trying to decrypt the semetric-key");
			LogWriter.close();
			configurationFileReader.close();
			throw new Exception("Error: While trying to decrypt the semetric-key",e);
		}

	}

	private void logError(String errorMessage) throws Exception {
		writeToLog(errorMessage);
		LogWriter.close();
		configurationFileReader.close();
		throw new Exception(errorMessage);
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
			writeToLog("The key: \"" + keyPairAlias + "\" cannot be recovered.");
			LogWriter.close();
			throw new Exception("The key: \"" + keyPairAlias + "\" cannot be recovered.",e);
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
		keyStore = KeyStore.getInstance(keyStoreType);
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(keyStorePath);
			keyStore.load(fis, keyStorePass.toCharArray());
		} catch (CertificateException|IOException e) {
			writeToLog("Error while trying to load the key-store");
			LogWriter.close();
			configurationFileReader.close();
			throw new Exception("Error while trying to load the key-store", e);
		} finally {
			if (fis != null) {
				fis.close();
			}
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
