/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package schoolproject;

/**
 *
 * @author seanb
 */
public class ParentMainMenu extends javax.swing.JFrame {

    /**
     * Creates new form ParentMainMenu
     */
    public ParentMainMenu() {
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
        signOutBT = new javax.swing.JButton();
        parentIcon = new javax.swing.JLabel();
        parentTxt = new javax.swing.JTextField();
        parentTF = new javax.swing.JTextField();
        reportBT = new javax.swing.JButton();
        assessmentsBT = new javax.swing.JButton();
        editProfileBT = new javax.swing.JButton();
        studentTxt = new javax.swing.JTextField();
        studentTF = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setSize(new java.awt.Dimension(1000, 1000));

        backgroundPanel.setBackground(new java.awt.Color(250, 228, 188));
        backgroundPanel.setPreferredSize(new java.awt.Dimension(1000, 1000));
        backgroundPanel.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        signOutBT.setFont(new java.awt.Font("Tw Cen MT", 0, 18)); // NOI18N
        signOutBT.setText("Sign Out");
        signOutBT.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                signOutBTActionPerformed(evt);
            }
        });
        backgroundPanel.add(signOutBT, new org.netbeans.lib.awtextra.AbsoluteConstraints(40, 30, -1, -1));

        parentIcon.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        parentIcon.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Pictures/ParentIcon.png"))); // NOI18N
        backgroundPanel.add(parentIcon, new org.netbeans.lib.awtextra.AbsoluteConstraints(400, 60, 200, 200));

        parentTxt.setEditable(false);
        parentTxt.setBackground(new java.awt.Color(250, 228, 188));
        parentTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        parentTxt.setText("Parent User:");
        parentTxt.setBorder(null);
        parentTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                parentTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(parentTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(380, 310, -1, -1));

        parentTF.setEditable(false);
        parentTF.setBackground(new java.awt.Color(250, 228, 188));
        parentTF.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        parentTF.setText("Jerry12");
        parentTF.setBorder(null);
        parentTF.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                parentTFActionPerformed(evt);
            }
        });
        backgroundPanel.add(parentTF, new org.netbeans.lib.awtextra.AbsoluteConstraints(500, 310, 190, -1));

        reportBT.setBackground(new java.awt.Color(65, 147, 211));
        reportBT.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        reportBT.setText("Weekly Reports");
        reportBT.setBorder(null);
        reportBT.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                reportBTActionPerformed(evt);
            }
        });
        backgroundPanel.add(reportBT, new org.netbeans.lib.awtextra.AbsoluteConstraints(370, 440, 260, 90));

        assessmentsBT.setBackground(new java.awt.Color(65, 147, 211));
        assessmentsBT.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        assessmentsBT.setText("Assessments");
        assessmentsBT.setBorder(null);
        assessmentsBT.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                assessmentsBTActionPerformed(evt);
            }
        });
        backgroundPanel.add(assessmentsBT, new org.netbeans.lib.awtextra.AbsoluteConstraints(370, 570, 260, 90));

        editProfileBT.setBackground(new java.awt.Color(65, 147, 211));
        editProfileBT.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        editProfileBT.setText("Edit Profile");
        editProfileBT.setBorder(null);
        editProfileBT.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editProfileBTActionPerformed(evt);
            }
        });
        backgroundPanel.add(editProfileBT, new org.netbeans.lib.awtextra.AbsoluteConstraints(370, 720, 260, 90));

        studentTxt.setEditable(false);
        studentTxt.setBackground(new java.awt.Color(250, 228, 188));
        studentTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        studentTxt.setText("Student:");
        studentTxt.setBorder(null);
        studentTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                studentTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(studentTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(380, 350, -1, -1));

        studentTF.setEditable(false);
        studentTF.setBackground(new java.awt.Color(250, 228, 188));
        studentTF.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        studentTF.setText("Jerry12");
        studentTF.setBorder(null);
        studentTF.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                studentTFActionPerformed(evt);
            }
        });
        backgroundPanel.add(studentTF, new org.netbeans.lib.awtextra.AbsoluteConstraints(470, 350, 190, -1));

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

    private void signOutBTActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_signOutBTActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_signOutBTActionPerformed

    private void parentTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_parentTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_parentTxtActionPerformed

    private void parentTFActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_parentTFActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_parentTFActionPerformed

    private void editProfileBTActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editProfileBTActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_editProfileBTActionPerformed

    private void reportBTActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_reportBTActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_reportBTActionPerformed

    private void assessmentsBTActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_assessmentsBTActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_assessmentsBTActionPerformed

    private void studentTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_studentTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_studentTxtActionPerformed

    private void studentTFActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_studentTFActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_studentTFActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton assessmentsBT;
    private javax.swing.JPanel backgroundPanel;
    private javax.swing.JButton editProfileBT;
    private javax.swing.JLabel parentIcon;
    private javax.swing.JTextField parentTF;
    private javax.swing.JTextField parentTxt;
    private javax.swing.JButton reportBT;
    private javax.swing.JButton signOutBT;
    private javax.swing.JTextField studentTF;
    private javax.swing.JTextField studentTxt;
    // End of variables declaration//GEN-END:variables
}