/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package schoolproject;


public final class PReportScreen extends javax.swing.JFrame {

    /**
     * Creates new form PReportScreen
     */
    public PReportScreen() {
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
        reportIcon = new javax.swing.JLabel();
        reportTxt = new javax.swing.JTextField();
        dateCB = new javax.swing.JComboBox<>();
        scoreTxt = new javax.swing.JTextField();
        dateTxt = new javax.swing.JTextField();
        dateBT = new javax.swing.JButton();
        line = new javax.swing.JTextField();
        line2 = new javax.swing.JTextField();
        mathsTF = new javax.swing.JTextField();
        englishTF = new javax.swing.JTextField();
        irishTF = new javax.swing.JTextField();
        chemistryTF = new javax.swing.JTextField();
        businessTF = new javax.swing.JTextField();
        frenchTF = new javax.swing.JTextField();
        subjectTxt = new javax.swing.JTextField();
        mathTxt = new javax.swing.JTextField();
        englishTxt = new javax.swing.JTextField();
        irishTxt = new javax.swing.JTextField();
        chemistryTxt = new javax.swing.JTextField();
        businessTxt = new javax.swing.JTextField();
        frenchTxt = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setSize(new java.awt.Dimension(1000, 1000));

        backgroundPanel.setBackground(new java.awt.Color(250, 228, 188));
        backgroundPanel.setPreferredSize(new java.awt.Dimension(1000, 1000));
        backgroundPanel.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        backBT.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Pictures/backBT.png"))); // NOI18N
        backBT.setBorder(null);
        backBT.setOpaque(false);
        backBT.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                backBTActionPerformed(evt);
            }
        });
        backgroundPanel.add(backBT, new org.netbeans.lib.awtextra.AbsoluteConstraints(40, 40, 50, 50));

        reportIcon.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        reportIcon.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Pictures/student.png"))); // NOI18N
        backgroundPanel.add(reportIcon, new org.netbeans.lib.awtextra.AbsoluteConstraints(400, 60, 200, 200));

        reportTxt.setEditable(false);
        reportTxt.setBackground(new java.awt.Color(250, 228, 188));
        reportTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 36)); // NOI18N
        reportTxt.setText("Weekly Report");
        reportTxt.setBorder(null);
        reportTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                reportTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(reportTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(390, 270, -1, -1));

        dateCB.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        backgroundPanel.add(dateCB, new org.netbeans.lib.awtextra.AbsoluteConstraints(400, 370, 250, 50));

        scoreTxt.setEditable(false);
        scoreTxt.setBackground(new java.awt.Color(250, 228, 188));
        scoreTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        scoreTxt.setText("Score:");
        scoreTxt.setBorder(null);
        scoreTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                scoreTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(scoreTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(650, 550, -1, -1));

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
        backgroundPanel.add(dateTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(400, 330, -1, -1));

        dateBT.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        dateBT.setText("Select Date");
        dateBT.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dateBTActionPerformed(evt);
            }
        });
        backgroundPanel.add(dateBT, new org.netbeans.lib.awtextra.AbsoluteConstraints(450, 440, 150, 50));

        line.setEditable(false);
        line.setBackground(new java.awt.Color(65, 147, 211));
        line.setBorder(null);
        backgroundPanel.add(line, new org.netbeans.lib.awtextra.AbsoluteConstraints(100, 590, 800, 10));

        line2.setEditable(false);
        line2.setBackground(new java.awt.Color(65, 147, 211));
        line2.setBorder(null);
        backgroundPanel.add(line2, new org.netbeans.lib.awtextra.AbsoluteConstraints(500, 550, 10, 400));

        mathsTF.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        backgroundPanel.add(mathsTF, new org.netbeans.lib.awtextra.AbsoluteConstraints(610, 610, 160, 50));

        englishTF.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        backgroundPanel.add(englishTF, new org.netbeans.lib.awtextra.AbsoluteConstraints(610, 660, 160, 50));

        irishTF.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        backgroundPanel.add(irishTF, new org.netbeans.lib.awtextra.AbsoluteConstraints(610, 710, 160, 50));

        chemistryTF.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        backgroundPanel.add(chemistryTF, new org.netbeans.lib.awtextra.AbsoluteConstraints(610, 760, 160, 50));

        businessTF.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        backgroundPanel.add(businessTF, new org.netbeans.lib.awtextra.AbsoluteConstraints(610, 810, 160, 50));

        frenchTF.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        backgroundPanel.add(frenchTF, new org.netbeans.lib.awtextra.AbsoluteConstraints(610, 860, 160, 50));

        subjectTxt.setEditable(false);
        subjectTxt.setBackground(new java.awt.Color(250, 228, 188));
        subjectTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        subjectTxt.setText("Subject:");
        subjectTxt.setBorder(null);
        subjectTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                subjectTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(subjectTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(240, 550, -1, -1));

        mathTxt.setEditable(false);
        mathTxt.setBackground(new java.awt.Color(250, 228, 188));
        mathTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        mathTxt.setText("Math");
        mathTxt.setBorder(null);
        mathTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mathTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(mathTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(240, 610, -1, -1));

        englishTxt.setEditable(false);
        englishTxt.setBackground(new java.awt.Color(250, 228, 188));
        englishTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        englishTxt.setText("English");
        englishTxt.setBorder(null);
        englishTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                englishTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(englishTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(240, 660, -1, -1));

        irishTxt.setEditable(false);
        irishTxt.setBackground(new java.awt.Color(250, 228, 188));
        irishTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        irishTxt.setText("Irish");
        irishTxt.setBorder(null);
        irishTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                irishTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(irishTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(240, 710, -1, -1));

        chemistryTxt.setEditable(false);
        chemistryTxt.setBackground(new java.awt.Color(250, 228, 188));
        chemistryTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        chemistryTxt.setText("Chemistry");
        chemistryTxt.setBorder(null);
        chemistryTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                chemistryTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(chemistryTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(240, 760, -1, -1));

        businessTxt.setEditable(false);
        businessTxt.setBackground(new java.awt.Color(250, 228, 188));
        businessTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        businessTxt.setText("Business");
        businessTxt.setBorder(null);
        businessTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                businessTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(businessTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(240, 810, -1, -1));

        frenchTxt.setEditable(false);
        frenchTxt.setBackground(new java.awt.Color(250, 228, 188));
        frenchTxt.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        frenchTxt.setText("French");
        frenchTxt.setBorder(null);
        frenchTxt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                frenchTxtActionPerformed(evt);
            }
        });
        backgroundPanel.add(frenchTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(240, 860, -1, -1));

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
    }//GEN-LAST:event_backBTActionPerformed

    private void reportTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_reportTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_reportTxtActionPerformed

    private void frenchTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_frenchTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_frenchTxtActionPerformed

    private void scoreTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_scoreTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_scoreTxtActionPerformed

    private void dateTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dateTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dateTxtActionPerformed

    private void dateBTActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dateBTActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dateBTActionPerformed

    private void subjectTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_subjectTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_subjectTxtActionPerformed

    private void mathTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mathTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_mathTxtActionPerformed

    private void englishTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_englishTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_englishTxtActionPerformed

    private void irishTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_irishTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_irishTxtActionPerformed

    private void chemistryTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_chemistryTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_chemistryTxtActionPerformed

    private void businessTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_businessTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_businessTxtActionPerformed

    

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton backBT;
    private javax.swing.JPanel backgroundPanel;
    private javax.swing.JTextField businessTF;
    private javax.swing.JTextField businessTxt;
    private javax.swing.JTextField chemistryTF;
    private javax.swing.JTextField chemistryTxt;
    private javax.swing.JButton dateBT;
    private javax.swing.JComboBox<String> dateCB;
    private javax.swing.JTextField dateTxt;
    private javax.swing.JTextField englishTF;
    private javax.swing.JTextField englishTxt;
    private javax.swing.JTextField frenchTF;
    private javax.swing.JTextField frenchTxt;
    private javax.swing.JTextField irishTF;
    private javax.swing.JTextField irishTxt;
    private javax.swing.JTextField line;
    private javax.swing.JTextField line2;
    private javax.swing.JTextField mathTxt;
    private javax.swing.JTextField mathsTF;
    private javax.swing.JLabel reportIcon;
    private javax.swing.JTextField reportTxt;
    private javax.swing.JTextField scoreTxt;
    private javax.swing.JTextField subjectTxt;
    // End of variables declaration//GEN-END:variables
}
