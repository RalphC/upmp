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

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JPanel;

import org.apache.jmeter.testelement.TestElement;

import com.unionpay.upmp.util.UPMPConstant;

public class UPMPMultipartUrlConfigGui extends UPMPUrlConfigGui {

    private static final long serialVersionUID = 1L;

    // used by HttpTestSampleGui
    public UPMPMultipartUrlConfigGui() {
        super();
        init();
    }

    // not currently used
    public UPMPMultipartUrlConfigGui(boolean showSamplerFields) {
        super(showSamplerFields);
        init();
    }

    public UPMPMultipartUrlConfigGui(boolean showSamplerFields, boolean showImplementation) {
        super(showSamplerFields, showImplementation, true);
        init();
    }

    @Override
    public void modifyTestElement(TestElement sampler) {
        super.modifyTestElement(sampler);
    }

    @Override
    public void configure(TestElement el) {
        super.configure(el);
    }

    private void init() {// called from ctor, so must not be overridable
        this.setLayout(new BorderLayout());

        // WEB REQUEST PANEL
        JPanel webRequestPanel = new JPanel();
        webRequestPanel.setLayout(new BorderLayout());
        webRequestPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(),
                UPMPConstant.upmp_request)); // $NON-NLS-1$

        JPanel northPanel = new JPanel();
        northPanel.setLayout(new BoxLayout(northPanel, BoxLayout.Y_AXIS));
        northPanel.add(getProtocolAndMethodPanel());
        northPanel.add(getPathPanel());

        webRequestPanel.add(northPanel, BorderLayout.NORTH);
        webRequestPanel.add(getParameterPanel(), BorderLayout.CENTER);

        this.add(getWebServerTimeoutPanel(), BorderLayout.NORTH);
        this.add(webRequestPanel, BorderLayout.CENTER);
        this.add(getProxyServerPanel(), BorderLayout.SOUTH);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void clear() {
        super.clear();
    }
}
