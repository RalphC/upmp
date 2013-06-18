/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.unionpay.upmp.jmeterplugin.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.apache.jmeter.gui.util.HorizontalPanel;
import org.apache.jmeter.gui.util.VerticalPanel;
import org.apache.jmeter.samplers.gui.AbstractSamplerGui;
import org.apache.jmeter.testelement.TestElement;
import org.apache.jorphan.gui.JLabeledTextField;

import com.unionpay.upmp.jmeterplugin.UPMPSamplerBase;
import com.unionpay.upmp.jmeterplugin.UPMPSamplerProxy;
import com.unionpay.upmp.util.UPMPConstant;

//For unit tests, @see TestHttpTestSampleGui

/**
 * HTTP Sampler GUI
 *
 */
public class UPMPTestSampleGui extends AbstractSamplerGui 
    implements ItemListener {
    private static final long serialVersionUID = 1L;

    private UPMPMultipartUrlConfigGui urlConfigGui;

    private JCheckBox getImages;
    
    private JCheckBox concurrentDwn;
    
    private JTextField concurrentPool; 

    private JCheckBox isMon;

    private JCheckBox useMD5;

    private JLabeledTextField embeddedRE; // regular expression used to match against embedded resource URLs

    private JLabeledTextField sourceIpAddr; // does not apply to Java implementation

    private final boolean isAJP;
    
    public UPMPTestSampleGui() {
        isAJP = false;
        init();
    }

    // For use by AJP
    protected UPMPTestSampleGui(boolean ajp) {
        isAJP = ajp;
        init();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void configure(TestElement element) {
        super.configure(element);
        urlConfigGui.configure(element);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TestElement createTestElement() {
    	UPMPSamplerBase sampler = new UPMPSamplerProxy();
        modifyTestElement(sampler);
        return sampler;
    }

    /**
     * Modifies a given TestElement to mirror the data in the gui components.
     * <p>
     * {@inheritDoc}
     */
    @Override
    public void modifyTestElement(TestElement sampler) {
        sampler.clear();
        urlConfigGui.modifyTestElement(sampler);
        this.configureTestElement(sampler);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getLabelResource() {
        return "upmp_testing_title"; // $NON-NLS-1$
    }
    
    @Override
    public String getStaticLabel() {
        return UPMPConstant.upmp_testing_title;
    }

    private void init() {// called from ctor, so must not be overridable
        setLayout(new BorderLayout(0, 5));
        setBorder(makeBorder());

        add(makeTitlePanel(), BorderLayout.NORTH);

        // URL CONFIG
        urlConfigGui = new UPMPMultipartUrlConfigGui(true, !isAJP);
        add(urlConfigGui, BorderLayout.CENTER);

        // OPTIONAL TASKS
        //add(createOptionalTasksPanel(), BorderLayout.SOUTH);
    }

    protected JPanel createOptionalTasksPanel() {
        // OPTIONAL TASKS
        final JPanel optionalTasksPanel = new VerticalPanel();
        optionalTasksPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), UPMPConstant.optional_tasks)); // $NON-NLS-1$

        final JPanel checkBoxPanel = new HorizontalPanel();
        // RETRIEVE IMAGES
        getImages = new JCheckBox(UPMPConstant.upmp_testing_retrieve_images); // $NON-NLS-1$
        // add a listener to activate or not concurrent dwn.
        getImages.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(final ItemEvent e) {
                if (e.getStateChange() == ItemEvent.SELECTED) { enableConcurrentDwn(true); }
                else { enableConcurrentDwn(false); }
            }
        });
        // Download concurrent resources
        concurrentDwn = new JCheckBox(UPMPConstant.upmp_testing_concurrent_download); // $NON-NLS-1$
        concurrentDwn.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(final ItemEvent e) {
                if (getImages.isSelected() && e.getStateChange() == ItemEvent.SELECTED) { concurrentPool.setEnabled(true); }
                else { concurrentPool.setEnabled(false); }
            }
        });
        concurrentPool = new JTextField(2); // 2 column size
        concurrentPool.setMaximumSize(new Dimension(30,20));
        // Is monitor
        isMon = new JCheckBox(UPMPConstant.monitor_is_title); // $NON-NLS-1$
        // Use MD5
        useMD5 = new JCheckBox(UPMPConstant.response_save_as_md5); // $NON-NLS-1$

        checkBoxPanel.add(getImages);
        checkBoxPanel.add(concurrentDwn);
        checkBoxPanel.add(concurrentPool);
        checkBoxPanel.add(isMon);
        checkBoxPanel.add(useMD5);
        optionalTasksPanel.add(checkBoxPanel);

        // Embedded URL match regex
        embeddedRE = new JLabeledTextField(UPMPConstant.upmp_testing_embedded_url_pattern,30); // $NON-NLS-1$
        optionalTasksPanel.add(embeddedRE, BorderLayout.CENTER);

        if (!isAJP) {
            // Add a new field source ip address (for HC implementations only)
            sourceIpAddr = new JLabeledTextField(UPMPConstant.upmp_testing2_source_ip); // $NON-NLS-1$
            optionalTasksPanel.add(sourceIpAddr, BorderLayout.EAST);
        }

        return optionalTasksPanel;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Dimension getPreferredSize() {
        return getMinimumSize();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void clearGui() {
        super.clearGui();
        //getImages.setSelected(false);
        //concurrentDwn.setSelected(false);
        //concurrentPool.setText(String.valueOf(UPMPSamplerBase.CONCURRENT_POOL_SIZE));
        //enableConcurrentDwn(false);
        //isMon.setSelected(false);
        //useMD5.setSelected(false);
        urlConfigGui.clear();
        //embeddedRE.setText(""); // $NON-NLS-1$
        //if (!isAJP) {
        //    sourceIpAddr.setText(""); // $NON-NLS-1$
        //}
    }
    
    private void enableConcurrentDwn(boolean enable) {
        if (enable) {
            concurrentDwn.setEnabled(true);
            if (concurrentDwn.isSelected()) {
                concurrentPool.setEnabled(true);
            }
        } else {
            concurrentDwn.setEnabled(false);
            concurrentPool.setEnabled(false);
        }
    }

    @Override
    public void itemStateChanged(ItemEvent event) {
        if (event.getStateChange() == ItemEvent.SELECTED) {
            enableConcurrentDwn(true);
        } else {
            enableConcurrentDwn(false);
        }
    }

}
