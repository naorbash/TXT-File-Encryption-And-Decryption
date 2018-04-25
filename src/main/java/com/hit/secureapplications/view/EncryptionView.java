package com.hit.secureapplications.view;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
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
    private JLabel FileToEncryptPath = new JLabel("Enter A Full Path To The File To Be Encrypt: ");
    private JTextField textFileToEncryptPath = new JTextField(20);

    private JButton Encrypt = new JButton("Encrypt");
    private JButton chooseFile = new JButton("Browse...");
    private JButton chooseStore = new JButton("Browse...");

     
    public EncryptionView() {
        super("JPanel Demo Program");
         
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
        newPanel.add(textFileToEncryptPath, constraints);
        
        //buttons adding
        constraints.gridx = 2;
        constraints.gridy = 0; 
        newPanel.add(chooseStore, constraints);
        constraints.gridy = 5; 
        newPanel.add(chooseFile, constraints);
        constraints.gridy = 6;
        constraints.gridwidth = 2;
        constraints.anchor = GridBagConstraints.CENTER;
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
     * @return
     */
	public String[] verifayArgument() {
		String KeyStorePath = textKeyStorePath.getText().trim();
		String KeyStorePass = new String(textKeyStorePass.getPassword()).trim();
		String KeyStoreType = KeyStorePath.substring(KeyStorePath.lastIndexOf(".") + 1).toUpperCase();
		String PrivateKeyAlias = textPrivateKeyAlias.getText().trim();
		String PrivateKeyPassword = new String(textPrivateKeyPassword.getPassword()).trim();
		String ReceiverSelfSignedCertAlias = textReceiverSelfSignedCertAlias.getText().trim();
		String FileToEncryptPath = textFileToEncryptPath.getText().trim();
		
		if (KeyStorePath.isEmpty() || KeyStorePass.isEmpty() || KeyStoreType.isEmpty() || PrivateKeyAlias.isEmpty()
				|| PrivateKeyPassword.isEmpty() || ReceiverSelfSignedCertAlias.isEmpty()
				|| FileToEncryptPath.isEmpty()) {
			JOptionPane.showMessageDialog(this,
					"Some if the fields are left empty, Please fill out all the requested fields", "Argument Error",
					JOptionPane.ERROR_MESSAGE);
			return null;
		}
		
		if (FileToEncryptPath.endsWith(".txt") || FileToEncryptPath.endsWith(".TXT")) {
			if (new File(FileToEncryptPath).isFile()) {
				if (new File(KeyStorePath).isFile()) {
					if (KeyStoreType.equals("JKS") || KeyStoreType.equals("JCEKS") || KeyStoreType.equals("PKCS12")
							|| KeyStoreType.equals("PKCS11") || KeyStoreType.equals("Windows-MY")||KeyStoreType.equals("BKS")) {
						return new String[]{KeyStorePath,KeyStorePass,KeyStoreType,PrivateKeyAlias,PrivateKeyPassword,ReceiverSelfSignedCertAlias,FileToEncryptPath};
					} else {
						JOptionPane.showMessageDialog(this,
								"The Key-Store type: " + KeyStoreType
										+ " is not supported,Please try a diffrent one.",
								"Argument Error", JOptionPane.ERROR_MESSAGE);
						return null;
					}
				} else {
					JOptionPane.showMessageDialog(this,
							"The Key-Store entered: " + KeyStorePath
									+ " is not a file,Please enter a qualified Key-Store path.",
							"Argument Error", JOptionPane.ERROR_MESSAGE);
					return null;
				}
			} else {
				JOptionPane.showMessageDialog(this,
						"The file entered: " + FileToEncryptPath + " is not a file,Please enter a qualified file path.",
						"Argument Error", JOptionPane.ERROR_MESSAGE);
				return null;
			}
		} else {
			JOptionPane.showMessageDialog(this, "The file entered is not a TXT file,Pleae enter a text file path.",
					"Argument Error", JOptionPane.ERROR_MESSAGE);
			return null;
		}
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
