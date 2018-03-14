/*
* Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.wso2.carbon.ei.migration.service.migrator;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.ei.migration.MigrationClientException;
import org.wso2.carbon.ei.migration.internal.MigrationServiceDataHolder;
import org.wso2.carbon.ei.migration.service.Migrator;
import org.wso2.carbon.ei.migration.util.Constant;
import org.wso2.carbon.ei.migration.util.Utility;
import org.wso2.carbon.user.api.Tenant;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.*;
import java.util.Iterator;

/**
 * Password transformation class for Entitlement mediator.
 */
public class ServerProfileMigrator extends Migrator {
    private static final Log log = LogFactory.getLog(ServerProfileMigrator.class);
    private boolean isModified = false;

    @Override
    public void migrate() throws MigrationClientException {
        transformPasswordInAllServerProfiles();
    }

    /**
     * This method will transform the Entitlement Mediator password encrypted with old encryption algorithm to new encryption
     * algorithm.
     *
     * @throws MigrationClientException
     */
    private void transformPasswordInAllServerProfiles() throws MigrationClientException {
        log.info(Constant.MIGRATION_LOG + "Migration starting on Entitlement Mediators.");
        updateSuperTenantConfigs();
        updateTenantConfigs();
    }

    private void updateSuperTenantConfigs() {
        String carbonHome = System.getProperty(Constant.CARBON_HOME);
        try {
            File[] spFolders = new File(carbonHome + Constant.ANALYTICS_SERVER_PROFILE_PATH + Constant.SUPER_TENANT_ID).listFiles();
            processSPFiles(spFolders);
        } catch (Exception e) {
            log.error("Error while updating mediator password for super tenant", e);
        }
    }

    private void updateTenantConfigs() {
        Tenant[] tenants;
        String carbonHome = System.getProperty(Constant.CARBON_HOME);
        try {
            tenants = MigrationServiceDataHolder.getRealmService().getTenantManager().getAllTenants();
            boolean isIgnoreForInactiveTenants = Boolean.parseBoolean(System.getProperty(Constant.IGNORE_INACTIVE_TENANTS));
            for (Tenant tenant : tenants) {
                if (isIgnoreForInactiveTenants && !tenant.isActive()) {
                    log.info("Tenant " + tenant.getDomain() + " is inactive. Skipping secondary userstore migration!");
                    continue;
                }

                File[] spFolders = new File(carbonHome + Constant.ANALYTICS_SERVER_PROFILE_PATH + tenant.getId()).listFiles();
                processSPFiles(spFolders);
            }
        } catch (Exception e) {
            log.error("Error while updating entitlement mediator password for tenant", e);
        }
    }

    private void processSPFiles(File[] spFolders) throws MigrationClientException {
        if (spFolders != null) {
            for (File folder : spFolders) {
                File[] spFiles = folder.listFiles();
                if (spFiles != null) {
                    for (File spFile : spFiles) {
                        if (spFile.isFile() && spFile.getName().toLowerCase().endsWith(".xml")) {
                            transformSPPassword(spFile.getAbsolutePath());
                        }
                    }
                }
            }
        }
    }

    private void transformSPPassword(String filePath) throws MigrationClientException {
        isModified = false;
        XMLStreamReader parser = null;
        FileInputStream stream = null;
        try {
            log.info("Migrating password in: " + filePath);
            stream = new FileInputStream(filePath);
            parser = XMLInputFactory.newInstance().createXMLStreamReader(stream);
            StAXOMBuilder builder = new StAXOMBuilder(parser);
            OMElement documentElement = builder.getDocumentElement();

            Iterator it = documentElement.getChildElements();
            String newEncryptedPassword = null;
            while (it.hasNext()) {
                OMElement element = (OMElement) it.next();
                if ("true".equals(element.getAttributeValue(Constant.SECURE_PASSWORD_Q))) {
                    String password = element.getAttributeValue(Constant.PASSWORD_Q);
                    newEncryptedPassword = Utility.getNewEncryptedValue(password);
                    if (StringUtils.isNotEmpty(newEncryptedPassword)) {
                        element.getAttribute(Constant.PASSWORD_Q).setAttributeValue(newEncryptedPassword);
                    }
                }
            }

            if (newEncryptedPassword != null) {
                OutputStream outputStream = new FileOutputStream(new File(filePath));
                documentElement.serialize(outputStream);
            }
        } catch (XMLStreamException | FileNotFoundException e) {
            new MigrationClientException("Error while writing the file: " + e);
        } catch (CryptoException e) {
            e.printStackTrace();
        } finally {
            try {
                if (parser != null) {
                    parser.close();
                }
                if (stream != null) {
                    try {
                        if (stream != null) {
                            stream.close();
                        }
                    } catch (IOException e) {
                        log.error("Error occurred while closing Input stream", e);
                    }
                }
            } catch (XMLStreamException ex) {
                log.error("Error while closing XML stream", ex);
            }
        }
    }
}
