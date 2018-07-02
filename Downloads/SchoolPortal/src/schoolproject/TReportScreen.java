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
public class TReportScreen extends javax.swing.JFrame {

    /**
     * Creates new form TReportScreen
     */
    public TReportScreen() {
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
        studentTxt = new javax.swing.JTextField();
        studentCB = new javax.swing.JComboBox<>();
        scoreTxt = new javax.swing.JTextField();
        scoreCB = new javax.swing.JComboBox<>();
        dateTxt = new javax.swing.JTextField();
        dateTF = new javax.swing.JTextField();
        addBT = new javax.swing.JButton();

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
        backgroundPanel.add(studentTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(400, 400, -1, -1));

        studentCB.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        backgroundPanel.add(studentCB, new org.netbeans.lib.awtextra.AbsoluteConstraints(400, 430, 250, 50));

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
        backgroundPanel.add(scoreTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(400, 500, -1, -1));

        scoreCB.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        scoreCB.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "5", "4", "3", "2", "1" }));
        backgroundPanel.add(scoreCB, new org.netbeans.lib.awtextra.AbsoluteConstraints(400, 530, 250, 50));

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
        backgroundPanel.add(dateTxt, new org.netbeans.lib.awtextra.AbsoluteConstraints(400, 610, -1, -1));

        dateTF.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        backgroundPanel.add(dateTF, new org.netbeans.lib.awtextra.AbsoluteConstraints(400, 650, 250, 50));

        addBT.setFont(new java.awt.Font("Tw Cen MT", 0, 24)); // NOI18N
        addBT.setText("Add Report");
        addBT.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addBTActionPerformed(evt);
            }
        });
        backgroundPanel.add(addBT, new org.netbeans.lib.awtextra.AbsoluteConstraints(420, 780, 230, 50));

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

    private void reportTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_reportTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_reportTxtActionPerformed

    private void studentTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_studentTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_studentTxtActionPerformed

    private void scoreTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_scoreTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_scoreTxtActionPerformed

    private void dateTxtActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dateTxtActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dateTxtActionPerformed

    private void addBTActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addBTActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_addBTActionPerformed

    private void backBTActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_backBTActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_backBTActionPerformed

  

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addBT;
    private javax.swing.JButton backBT;
    private javax.swing.JPanel backgroundPanel;
    private javax.swing.JTextField dateTF;
    private javax.swing.JTextField dateTxt;
    private javax.swing.JLabel reportIcon;
    private javax.swing.JTextField reportTxt;
    private javax.swing.JComboBox<String> scoreCB;
    private javax.swing.JTextField scoreTxt;
    private javax.swing.JComboBox<String> studentCB;
    private javax.swing.JTextField studentTxt;
    // End of variables declaration//GEN-END:variables
}