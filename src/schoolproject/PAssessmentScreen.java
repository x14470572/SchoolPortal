/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package schoolproject;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author seanb
 */
public class PAssessmentScreen extends javax.swing.JFrame {
    private ParentMainMenu pMainMenu;
    private String username;
    private final String DB_URL = "jdbc:mysql://schoolportal.ck4ehi6goau1.eu-west-1.rds.amazonaws.com:3306/SchoolPortal";
    private Properties prop = new Properties();
    private InputStream input = null;
    private String encryptedData;
    private char[] decryptedData;
    private static SecretKeySpec schoolNumber;
    private static byte[] key;
    private char[] convertedChar;
    private String dbusername;
    private Connection conn = null;
    private Statement stmt = null;
    private ResultSet results;
    private ResultSet results2;
    private int parentId;
    private int studentId;
    private String studentName;
    /**
     * Creates new form PAssessmentScreen
     */
    public PAssessmentScreen() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        backgroundPanel = new javax.swing.JPanel();
        backBT = new javax.swing.JButton();
        assessmentIcon = new javax.swing.JLabel();
        assessmentsTxt = new javax.swing.JTextField();
        dateTxt = new javax.swing.JTextField();
        dateCB = new javax.swing.JComboBox<>();
        dateBT = new javax.swing.JButton();
        noteTxt = new javax.swing.JTextField();
        noteTF = new javax.swing.JTextField();
        descriptionTxt = new javax.swing.JTextField();
        jScrollPane1 = new javax.swing.JScrollPane();
        descriptionTA = new javax.swing.JTextArea();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setSize(new java.awt.Dimension(1000, 1000));

        backgroundPanel.setBackground(new java.awt.Color(250, 228, 188));
        backgroundPanel.setPreferredSize(new java.awt.Dimension(1000, 1000));
        backgroundPanel.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        backBT.setBackground(new java.awt.Color(250, 228, 188));
        backBT.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Pictures/backBT.png"))); // NOI18N
        backBT.setBorder(null);
        backBT.setOpaque(false);
        backBT.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                backBTActionPerformed(evt);
            }
        });
        backgroundPanel.add(backBT, new org.netbeans.lib.awtextra.AbsoluteConstraints(40, 40, 50, 50));

        assessmentIcon.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        assessmentIcon.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Pictures/assessmentIcon.png"))); // NOI18N
        backgroundPanel.add(assessmentIcon, new org.netbeans.lib.awtextra.AbsoluteConstraints(400, 60, 200, 200));

        assessmentsTxt.setEditable(false);
        assessmentsTxt.setBackground(new java.awt.Color(250, 228, 188));
        assessmentsTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 36)); // NOI18N
        assessmentsTxt.setText("Assessments");
        assessmentsTxt.setBorder(null);
        assessmentsTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                assessmentsTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(assessmentsTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(420, 270, -1, -1));

        dateTxt.setEditable(false);
        dateTxt.setBackground(new java.awt.Color(250, 228, 188));
        dateTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        dateTxt.setText("Date:");
        dateTxt.setBorder(null);
        dateTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dateTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(dateTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(470, 340, -1, -1));

        dateCB.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        backgroundPanel.add(dateCB, new org.netbeans.lib.awtextra.AbsoluteConstraints(380, 370, 250, 50));

        dateBT.setBackground(new java.awt.Color(65, 147, 211));
        dateBT.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        dateBT.setForeground(new java.awt.Color(255, 255, 255));
        dateBT.setText("Select Date");
        dateBT.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dateBTActionPerformed(evt);
            }
        });
        backgroundPanel.add(dateBT, new org.netbeans.lib.awtextra.AbsoluteConstraints(430, 450, 150, 50));

        noteTxt.setEditable(false);
        noteTxt.setBackground(new java.awt.Color(250, 228, 188));
        noteTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        noteTxt.setText("Note:");
        noteTxt.setBorder(null);
        noteTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                noteTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(noteTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(390, 550, -1, -1));

        noteTF.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        backgroundPanel.add(noteTF, new org.netbeans.lib.awtextra.AbsoluteConstraints(390, 590, 250, 50));

        descriptionTxt.setEditable(false);
        descriptionTxt.setBackground(new java.awt.Color(250, 228, 188));
        descriptionTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        descriptionTxt.setText("Description:");
        descriptionTxt.setBorder(null);
        descriptionTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                descriptionTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(descriptionTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(390, 670, -1, -1));

        descriptionTA.setEditable(false);
        descriptionTA.setColumns(20);
        descriptionTA.setRows(5);
        jScrollPane1.setViewportView(descriptionTA);

        backgroundPanel.add(jScrollPane1, new org.netbeans.lib.awtextra.AbsoluteConstraints(390, 710, 350, 110));

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(backgroundPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(backgroundPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void backBTActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_backBTActionPerformed
        // TODO add your handling code here:
        this.setVisible(false);
         pMainMenu.setVisible(true);
        
    }//GEN-LAST:event_backBTActionPerformed

    private void assessmentsTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_assessmentsTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_assessmentsTxtActionPerformed

    private void noteTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_noteTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_noteTxtActionPerformed

    private void descriptionTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_descriptionTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_descriptionTxtActionPerformed

    private void dateTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dateTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dateTxtActionPerformed

    private void dateBTActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dateBTActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dateBTActionPerformed

   

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel assessmentIcon;
    private javax.swing.JTextField assessmentsTxt;
    private javax.swing.JButton backBT;
    private javax.swing.JPanel backgroundPanel;
    private javax.swing.JButton dateBT;
    private javax.swing.JComboBox<String> dateCB;
    private javax.swing.JTextField dateTxt;
    private javax.swing.JTextArea descriptionTA;
    private javax.swing.JTextField descriptionTxt;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextField noteTF;
    private javax.swing.JTextField noteTxt;
    // End of variables declaration//GEN-END:variables
    void account(Object account) {

        pMainMenu = (schoolproject.ParentMainMenu) account;
    }
    
    void StudentId(String studentName,int pId){
        parentId = pId;
        
        databaseConnection();
        try {
            Class.forName("com.mysql.jdbc.Driver");

            conn = DriverManager.getConnection(DB_URL, dbusername, new String(decryptedData));
            
           
            String query = "SELECT Id FROM Students WHERE ParentId = ? ";
            String query2 = "SELECT Date FROM Assessments WHERE StudentId = ? ";
            
            try{
            conn.setAutoCommit(false);
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setInt(1, parentId);
            results = pstmt.executeQuery();
                 while(results.next()){
                   studentId =results.getInt("Id");
                 }
            
            PreparedStatement pstmt2 = conn.prepareStatement(query2);
            
            pstmt2.setInt(1, studentId);

            results2 = pstmt2.executeQuery();
            while (results2.next()) {
                //dbPassword= results2.getString("Password");
                dateCB.addItem(results2.getString("Date"));
                
            }
                 
                
                conn.commit();
            }catch(SQLException e){
                System.out.println(e);
                conn.rollback();
            }
            conn.close();

        } catch (ClassNotFoundException ex) { 
            
        } catch (SQLException ex) {
            
        }
        
        
    }
    
    private void databaseConnection() {
            try {

                //Gets details from properties file
                input = new FileInputStream("config.properties");
                prop.load(input);
                dbusername = prop.getProperty("pusername");
                encryptedData = prop.getProperty("ppassword");
                decryptedData = decrypt(encryptedData);

            } catch (FileNotFoundException ex) {
                //Logger.getLogger(SignInScreen.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {

            }
    }

    private char[] decrypt(String encryptedData) {
        String schoolPostcode = "LdU6_UF}?Z3Pnwa3";
        schoolPostCodeGen(schoolPostcode);

        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, schoolNumber);
            c.doFinal(Base64.getDecoder().decode(encryptedData));
            byte[] convertedByte = c.doFinal(Base64.getDecoder().decode(encryptedData));
            convertedChar = new char[convertedByte.length];
            for (int i = 0; i < convertedByte.length; i++) {
                convertedChar[i] = (char) convertedByte[i];
            }
        } catch (NoSuchAlgorithmException ex) {

        } catch (NoSuchPaddingException ex) {

        } catch (InvalidKeyException ex) {

        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(SignInScreen.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(SignInScreen.class.getName()).log(Level.SEVERE, null, ex);
        }

        return convertedChar;
    }

    private void schoolPostCodeGen(String postCode) {
        MessageDigest sha = null;
        try {
            key = postCode.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            schoolNumber = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

}
