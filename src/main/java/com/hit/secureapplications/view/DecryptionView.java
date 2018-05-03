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

import com.hit.secureapplications.decryption.FileDecryption;

public class DecryptionView extends JFrame{
private static final long serialVersionUID = 1L;
	
	private JLabel KeyStorePath= new JLabel("Enter Your Key-Store Full Path: ");
    private JTextField textKeyStorePath = new JTextField(20);
    private JLabel KeyStorePass = new JLabel("Enter Your Key-Store Password: ");
    private JPasswordField textKeyStorePass = new JPasswordField(20);
    private JLabel PrivateKeyAlias = new JLabel("Enter Your Key-Pair Alias: ");
    private JTextField textPrivateKeyAlias = new JTextField(20);
    private JLabel PrivateKeyPassword = new JLabel("Enter Your Key-Pair Password: ");
    private JPasswordField textPrivateKeyPassword = new JPasswordField(20);
    private JLabel ReceiverSelfSignedCertAlias = new JLabel("Enter The Sender's Self Signed Certificate Alias: ");
    private JTextField textReceiverSelfSignedCertAlias = new JTextField(20);
    private JLabel algorithm = new JLabel("Enter your algorithm in a transformation shape(leave empty if none entered in the encryption program): ");
    private JTextField textAlgorithm = new JTextField(20);
    private JLabel algorithmProvider = new JLabel("Enter your algorithm provider(leave empty if none entered in the encryption program): ");
    private JTextField textAlgorithmProvider = new JTextField(20);
    private JLabel configFilePathPath = new JLabel("Enter A Full Path To The Configuration File: ");
    private JTextField textConfigFilePathPath = new JTextField(30);
    private JLabel FileToEncryptPath = new JLabel("Enter A Full Path To The File To Be Decrypted: ");
    private JTextField textFileToEncryptPath = new JTextField(30);

    private JButton decrypt = new JButton("Decrypt");
    private JButton chooseFile = new JButton("Browse...");
    private JButton chooseStore = new JButton("Browse...");
    private JButton chooseConfig = new JButton("Browse...");

     
    public DecryptionView() {
        super("File Decryption Program");
         
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
        newPanel.add(algorithm, constraints);
        constraints.gridy = 6;
        newPanel.add(algorithmProvider, constraints);
        constraints.gridy = 7;
        newPanel.add(configFilePathPath, constraints);
        constraints.gridy = 8;
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
        newPanel.add(textAlgorithm, constraints);
        constraints.gridy = 6;
        newPanel.add(textAlgorithmProvider, constraints);
        constraints.gridy = 7;
        newPanel.add(textConfigFilePathPath, constraints);
        constraints.gridy = 8;
        newPanel.add(textFileToEncryptPath, constraints);
        
        //buttons adding
        constraints.gridx = 2;
        constraints.gridy = 0; 
        newPanel.add(chooseStore, constraints);
        constraints.gridy = 7; 
        newPanel.add(chooseConfig, constraints);
        constraints.gridy = 8; 
        newPanel.add(chooseFile, constraints);
        constraints.gridwidth = 2;
        constraints.gridy = 9;
        newPanel.add(decrypt, constraints);
        
        decrypt.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				String[] arguments = null;
				if((arguments = verifayArgument())!=null){
					generateFileDecryption(arguments);
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
        
        chooseConfig.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String configFilePath = openChooseFile();
				if(configFilePath!=null){
					textConfigFilePathPath.setText(configFilePath);
				}
			}
		});
         
        // set border for the panel
        newPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Encryption Details Panel"));
         
        // add the panel to this frame
        add(newPanel);
         
        pack();
        setLocationRelativeTo(null);
        this.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

	private String openChooseFile() {
		final JFileChooser fc = new JFileChooser();
		fc.setCurrentDirectory(new File(System.getProperty("user.dir")));
		int returnVal = fc.showOpenDialog(this);
		if (returnVal == JFileChooser.APPROVE_OPTION) {
			File file = fc.getSelectedFile();
			return file.getAbsolutePath();
		}
		return null;

	}

    private void generateFileDecryption(String[] arguments) {
    	FileDecryption fd = new FileDecryption(arguments);
		try {
			fd.decrypt();
			JOptionPane.showMessageDialog(this,
					"Decryption Done Successfully",
					"Decryption Finished", JOptionPane.PLAIN_MESSAGE);
			this.dispose();
		} catch (Exception e1) {
			JOptionPane.showMessageDialog(this,
					"Error while Decrypting,Please check log file",
					"Decryption Error", JOptionPane.ERROR_MESSAGE);
			this.dispose();
			e1.printStackTrace();
			return;
		}
	}

	/**
     * This Function responsible to verify the argument giving by the user.
     * @return
     */
	public String[] verifayArgument() {
		String keyStorePath = textKeyStorePath.getText().trim();
		String keyStorePass = new String(textKeyStorePass.getPassword()).trim();
		String keyStoreType = keyStorePath.substring(keyStorePath.lastIndexOf(".") + 1).toUpperCase();
		String privateKeyAlias = textPrivateKeyAlias.getText().trim();
		String privateKeyPassword = new String(textPrivateKeyPassword.getPassword()).trim();
		String receiverSelfSignedCertAlias = textReceiverSelfSignedCertAlias.getText().trim();
		String algorithm = textAlgorithm.getText().trim();
		String algorithmProvider = textAlgorithmProvider.getText().trim();
		String configFilePathPath = textConfigFilePathPath.getText().trim();
		String fileToEncryptPath = textFileToEncryptPath.getText().trim();
		
		if (keyStorePath.isEmpty() || keyStorePass.isEmpty() || keyStoreType.isEmpty() || privateKeyAlias.isEmpty()
				|| privateKeyPassword.isEmpty() || receiverSelfSignedCertAlias.isEmpty() || configFilePathPath.isEmpty()
				|| fileToEncryptPath.isEmpty()) {
			JOptionPane.showMessageDialog(this,
					"Some if the fields are left empty, Please fill out all the requested fields", "Argument Error",
					JOptionPane.ERROR_MESSAGE);
			return null;
		}
		
		if (fileToEncryptPath.endsWith(".txt") || fileToEncryptPath.endsWith(".TXT")) {
			if (configFilePathPath.endsWith(".txt") || configFilePathPath.endsWith(".TXT")) {
				if (new File(configFilePathPath).isFile()) {
					if (new File(fileToEncryptPath).isFile()) {
						if (new File(keyStorePath).isFile()) {
							if (keyStoreTypeVerification(keyStoreType)) {
								if (providerVerification(algorithmProvider, algorithm)) {
									return new String[] { keyStorePath, keyStorePass, keyStoreType, privateKeyAlias,
											privateKeyPassword, receiverSelfSignedCertAlias, algorithm,
											algorithmProvider, configFilePathPath, fileToEncryptPath };
								} else {
									JOptionPane.showMessageDialog(this, "The entered algorithm provider: \""
											+ algorithmProvider
											+ "\" does not exist \\ can't be placed when algorithem field is empty.",
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
								"The file entered: " + fileToEncryptPath
										+ " is not a file,Please enter a qualified file path.",
								"Argument Error", JOptionPane.ERROR_MESSAGE);
						return null;
					}
				} else {
					JOptionPane.showMessageDialog(this,
							"The file entered: " + configFilePathPath
									+ " is not a file,Please enter a qualified file path.",
							"Argument Error", JOptionPane.ERROR_MESSAGE);
					return null;
				}
			} else {
				JOptionPane.showMessageDialog(this,
						"The configuration file entered is not a TXT file,Pleae enter a text file path.",
						"Argument Error", JOptionPane.ERROR_MESSAGE);
				return null;
			}
		} else {
			JOptionPane.showMessageDialog(this, "The file entered is not a TXT file,Pleae enter a text file path.",
					"Argument Error", JOptionPane.ERROR_MESSAGE);
			return null;
		}
	}
	

	/**
	 * This method checks if a giving provider matches the giving algorithm
	 * @param algorithmProvider
	 * @param enteredAlgorithm
	 * @return boolean
	 */
	@SuppressWarnings("null")
	private boolean providerVerification(String algorithmProvider,String enteredAlgorithm) {
		//If there isn't an algorithm entered but there is a provider, return false.
		if(enteredAlgorithm==null ||enteredAlgorithm.equals("")) {
			if(algorithmProvider!=null && !(algorithmProvider.equals(""))) {
				return false;
			}
		//If there is isn't a provider, return true.
		}if(algorithmProvider==null || algorithmProvider.equals("")) {
			return true;
		}else {
			//check If there is such provider 
			Provider enetredProvider = Security.getProvider(algorithmProvider);
			if(enetredProvider!=null) {
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

	public static void main(String[] args) {
		  try {
	            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
	        } catch (Exception ex) {
	            ex.printStackTrace();
	        }
	         
	        SwingUtilities.invokeLater(new Runnable() {
	            @Override
	            public void run() {
	                new DecryptionView().setVisible(true);
	            }
	        });
	    }

}
