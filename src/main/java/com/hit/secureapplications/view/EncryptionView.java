package com.hit.secureapplications.view;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.security.Provider;
import java.security.Security;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import com.hit.secureapplications.encryption.FileEncryption;

public class EncryptionView extends JFrame {
	
	private static final long serialVersionUID = 1L;
	
	private JLabel KeyStorePath= new JLabel("Enter Your Key-Store Full Path: ");
    private JTextField textKeyStorePath = new JTextField(20);
    private JLabel KeyStorePass = new JLabel("Enter Your Key-Store Password: ");
    private JPasswordField textKeyStorePass = new JPasswordField(20);
    private JLabel PrivateKeyAlias = new JLabel("Enter Your Key-Pair Alias: ");
    private JTextField textPrivateKeyAlias = new JTextField(20);
    private JLabel PrivateKeyPassword = new JLabel("Enter Your Key-Pair Password: ");
    private JPasswordField textPrivateKeyPassword = new JPasswordField(20);
    private JLabel ReceiverSelfSignedCertAlias = new JLabel("Enter The Reciver's Self Signed Certificate Alias: ");
    private JTextField textReceiverSelfSignedCertAlias = new JTextField(20);
    private JLabel SymmetricKeyProvider = new JLabel("Enter an AES Provider(optional): ");
    private JTextField textSymmetricKeyProvider = new JTextField(20);
    private JLabel SecureRandomSeed = new JLabel("Enter A Seed(optional): ");
    private JTextField textSecureRandomSeed = new JTextField(9);
    private JLabel FileToEncryptPath = new JLabel("Enter A Full Path To The File To Be Encrypt: ");
    private JTextField textFileToEncryptPath = new JTextField(30);

    private JButton Encrypt = new JButton("Encrypt");
    private JButton chooseFile = new JButton("Browse...");
    private JButton chooseStore = new JButton("Browse...");

     
    public EncryptionView() {
        super("File Encryption Program");
         
        // create a new panel with GridBagLayout manager
        JPanel newPanel = new JPanel(new GridBagLayout());
         
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(10, 10, 10, 10);
         
        //Lables adding
        constraints.gridx = 0;
        constraints.gridy = 0;     
        newPanel.add(KeyStorePath, constraints);
        constraints.gridy = 1;
        newPanel.add(KeyStorePass, constraints);
        constraints.gridy = 2;
        newPanel.add(PrivateKeyAlias, constraints);
        constraints.gridy = 3;
        newPanel.add(PrivateKeyPassword, constraints);
        constraints.gridy = 4;
        newPanel.add(ReceiverSelfSignedCertAlias, constraints);
        constraints.gridy = 5;
        newPanel.add(SymmetricKeyProvider, constraints);
        constraints.gridy = 6;
        newPanel.add(SecureRandomSeed, constraints);
        constraints.gridy = 7;
        newPanel.add(FileToEncryptPath, constraints);
         
        //Text Fields adding
        constraints.gridx = 1;
        constraints.gridy = 0;     
        newPanel.add(textKeyStorePath, constraints);
        constraints.gridy = 1;
        newPanel.add(textKeyStorePass, constraints);
        constraints.gridy = 2;
        newPanel.add(textPrivateKeyAlias, constraints);
        constraints.gridy = 3;
        newPanel.add(textPrivateKeyPassword, constraints);
        constraints.gridy = 4;
        newPanel.add(textReceiverSelfSignedCertAlias, constraints);
        constraints.gridy = 5;
        newPanel.add(textSymmetricKeyProvider, constraints);
        constraints.gridy = 6;
        newPanel.add(textSecureRandomSeed, constraints);
        constraints.gridy = 7;
        newPanel.add(textFileToEncryptPath, constraints);
        
        //buttons adding
        constraints.gridx = 2;
        constraints.gridy = 0; 
        newPanel.add(chooseStore, constraints);
        constraints.gridy = 7; 
        newPanel.add(chooseFile, constraints);
        constraints.gridy = 8;
        constraints.gridwidth = 2;
        newPanel.add(Encrypt, constraints);
        
        Encrypt.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				String[] arguments = null;
				if((arguments = verifayArgument())!=null){
					generateFileEncryption(arguments);
				}else{
					return;
				}
			}
		});
        
        chooseStore.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String storePath = openChooseFile();
				if(storePath!=null){
					textKeyStorePath.setText(storePath);
				}
			}
		});
        
        chooseFile.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				String filePath = openChooseFile();
				if(filePath!=null){
					textFileToEncryptPath.setText(filePath);
				}
			}
		});
         
        // set border for the panel
        newPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Encryption Details Panel"));
         
        // add the panel to this frame
        this.add(newPanel);
         
        this.pack();
        setLocationRelativeTo(null);
        this.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

	private String openChooseFile() {
		JFileChooser fc = new JFileChooser();
		fc.setCurrentDirectory(new File(System.getProperty("user.dir")));
		int returnVal = fc.showOpenDialog(this);
		if (returnVal == JFileChooser.APPROVE_OPTION) {
			File file = fc.getSelectedFile();
			return file.getAbsolutePath();
		}
		return null;

	}

    private void generateFileEncryption(String[] arguments) {
    	FileEncryption fe = new FileEncryption(arguments);
		try {
			fe.encrypt();
			JOptionPane.showMessageDialog(this,
					"Encryption Done Successfully",
					"Encryption Finished", JOptionPane.PLAIN_MESSAGE);
			this.dispose();
		} catch (Exception e1) {
			JOptionPane.showMessageDialog(this,
					"Error while Encrypting,Please check log file",
					"Encryption Error", JOptionPane.ERROR_MESSAGE);
			this.dispose();
			e1.printStackTrace();
			return;
		}
	}

	/**
     * This Function responsible to verify the argument giving by the user.
     * @return textSymmetricKeyProvider
     */
	public String[] verifayArgument() {
		String keyStorePath = textKeyStorePath.getText().trim();
		String keyStorePass = new String(textKeyStorePass.getPassword()).trim();
		String keyStoreType = keyStorePath.substring(keyStorePath.lastIndexOf(".") + 1).toUpperCase();
		String privateKeyAlias = textPrivateKeyAlias.getText().trim();
		String privateKeyPassword = new String(textPrivateKeyPassword.getPassword()).trim();
		String receiverSelfSignedCertAlias = textReceiverSelfSignedCertAlias.getText().trim();
		String symmetricKeyProvider = textSymmetricKeyProvider.getText().trim();
		String seed = textSecureRandomSeed.getText().trim();
		String fileToEncryptPath = textFileToEncryptPath.getText().trim();
		
		if (keyStorePath.isEmpty() || keyStorePass.isEmpty() || keyStoreType.isEmpty() || privateKeyAlias.isEmpty()
				|| privateKeyPassword.isEmpty() || receiverSelfSignedCertAlias.isEmpty()
				|| fileToEncryptPath.isEmpty()) {
			JOptionPane.showMessageDialog(this,
					"Some if the fields are left empty, Please fill out all the requested fields", "Argument Error",
					JOptionPane.ERROR_MESSAGE);
			return null;
		}
		
		if (fileToEncryptPath.endsWith(".txt") || fileToEncryptPath.endsWith(".TXT")) {
			if (new File(fileToEncryptPath).isFile()) {
				if (new File(keyStorePath).isFile()) {
					if (keyStoreTypeVerification(keyStoreType)) {
						if(seedVerefication(seed)) {
							if(providerVerification(symmetricKeyProvider)) {
								return new String[]{keyStorePath,keyStorePass,keyStoreType,privateKeyAlias,privateKeyPassword,receiverSelfSignedCertAlias,symmetricKeyProvider,seed,fileToEncryptPath};
							}else {
								JOptionPane.showMessageDialog(this,
										"The entered AES provider: \"" +symmetricKeyProvider+ "\" does not exist \\ does not support the AES algorithm."
												+ "please try a diffrent one or leave empty.",
										"Argument Error", JOptionPane.ERROR_MESSAGE);
								return null;
							}
						}else {
							JOptionPane.showMessageDialog(this,
									"The seed entered: \"" +seed+ "\" is illegal, try a legal seed or leave empty",
									"Argument Error", JOptionPane.ERROR_MESSAGE);
							return null;
						}
						
					} else {
						JOptionPane.showMessageDialog(this,
								"The Key-Store type: " + keyStoreType
										+ " is not supported,Please try a diffrent one.",
								"Argument Error", JOptionPane.ERROR_MESSAGE);
						return null;
					}
				} else {
					JOptionPane.showMessageDialog(this,
							"The Key-Store entered: " + keyStorePath
									+ " is not a file,Please enter a qualified Key-Store path.",
							"Argument Error", JOptionPane.ERROR_MESSAGE);
					return null;
				}
			} else {
				JOptionPane.showMessageDialog(this,
						"The file entered: " + fileToEncryptPath + " is not a file,Please enter a qualified file path.",
						"Argument Error", JOptionPane.ERROR_MESSAGE);
				return null;
			}
		} else {
			JOptionPane.showMessageDialog(this, "The file entered is not a TXT file,Pleae enter a text file path.",
					"Argument Error", JOptionPane.ERROR_MESSAGE);
			return null;
		}
	}
    	
	private boolean providerVerification(String symmetricKeyProvider) {
		if(symmetricKeyProvider==null || symmetricKeyProvider.equals("")) {
			return true;
		}
		Provider enetredProvider = Security.getProvider(symmetricKeyProvider);
		if(enetredProvider!=null) {
			if(enetredProvider.getInfo().contains("AES")) {
				return true;
			}
		}
		return false;
	}

	/**
	 * If the entered key-store type is supported, return true
	 * Otherwise, return false.
	 * @param keyStoreType
	 * @return
	 */
	private boolean keyStoreTypeVerification(String keyStoreType) {
		if (keyStoreType.equals("JKS") || keyStoreType.equals("JCEKS") || keyStoreType.equals("PKCS12")
				|| keyStoreType.equals("PKCS11") || keyStoreType.equals("Windows-MY") || keyStoreType.equals("BKS"))
			return true;
		return false;
	}

	/**
	 * If the entered seed is empty or legal seed, return true.
	 * Otherwise, return false
	 * @param seed
	 * @return boolean
	 */
	private boolean seedVerefication(String seed) {
		if(seed!=null && !(seed.equals(""))){
			try {
				Long.parseLong(seed);
			}catch(NumberFormatException e) {
				return false;
			}
		}
		return true;
	}

	public static void main(String[] args) {
		  try {
	            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
	        } catch (Exception ex) {
	            ex.printStackTrace();
	        }
	         
	        SwingUtilities.invokeLater(new Runnable() {
	            @Override
	            public void run() {
	                new EncryptionView().setVisible(true);
	            }
	        });
	    }

}
