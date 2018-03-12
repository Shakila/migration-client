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
import org.wso2.carbon.ei.migration.service.dao.EntitlementMediatorDAO;
import org.wso2.carbon.ei.migration.util.Constant;
import org.wso2.carbon.ei.migration.util.Utility;
import org.wso2.carbon.user.api.Tenant;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Password transformation class for Entitlement mediator.
 */
public class EntitlementMediatorMigrator extends Migrator {
    private static final Log log = LogFactory.getLog(EntitlementMediatorMigrator.class);

    @Override
    public void migrate() throws MigrationClientException {
        transformPasswordInAllEntitlementMediators();
    }

    /**
     * This method will transform the Entitlement Mediator password encrypted with old encryption algorithm to new encryption
     * algorithm.
     *
     * @throws MigrationClientException
     */
    private void transformPasswordInAllEntitlementMediators() throws MigrationClientException {
        log.info(Constant.MIGRATION_LOG + "Migration starting on Entitlement Mediators.");
        updateSuperTenantConfigs();
        updateTenantConfigs();
    }

    private void updateSuperTenantConfigs() {
        try {
            HashMap<String, File[]> filesMap = EntitlementMediatorDAO.getInstance().getEMConfigFiles(Constant.SUPER_TENANT_ID);
            for (Map.Entry entry : filesMap.entrySet()) {
                File[] emConfigs = (File[]) entry.getValue();
                for (File file : emConfigs) {
                    if (file.isFile() && file.getName().toLowerCase().endsWith(".xml")) {
                        transformEMPassword(file.getAbsolutePath());
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error while updating mediator password for super tenant", e);
        }
    }

    private void updateTenantConfigs() {
        Tenant[] tenants;
        try {
            tenants = MigrationServiceDataHolder.getRealmService().getTenantManager().getAllTenants();
            for (Tenant tenant : tenants) {
                HashMap<String, File[]> filesMap = EntitlementMediatorDAO.getInstance().getEMConfigFiles(tenant.getId());
                for (Map.Entry entry : filesMap.entrySet()) {
                    File[] emConfigs = (File[]) entry.getValue();
                    for (File file : emConfigs) {
                        if (file.isFile() && file.getName().toLowerCase().endsWith(".xml")) {
                            transformEMPassword(file.getAbsolutePath());
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error while updating entitlement mediator password for tenant", e);
        }
    }

    private void transformEMPassword(String filePath) throws MigrationClientException {
        XMLStreamReader parser = null;
        FileInputStream stream = null;
        try {
            log.info("Migrating password in: " + filePath);
            stream = new FileInputStream(filePath);
            parser = XMLInputFactory.newInstance().createXMLStreamReader(stream);
            StAXOMBuilder builder = new StAXOMBuilder(parser);
            OMElement documentElement = builder.getDocumentElement();
            Iterator it = null;
            String str = filePath.substring(0, filePath.lastIndexOf(File.separator));
            String artifactType = str.substring(str.lastIndexOf(File.separator) + 1);
            if ("api".equals(artifactType)) {
                it = ((OMElement) ((OMElement) documentElement.getChildrenWithName(Constant.RESOURCE_Q).next())
                        .getChildrenWithName(Constant.IN_SEQUENCE_Q).next())
                        .getChildrenWithName(Constant.ENTITLEMENT_SERVICE_Q);
            } else if ("proxy-services".equals(artifactType)) {
                it = ((OMElement) ((OMElement) documentElement.getChildrenWithName(Constant.TARGET_Q).next())
                        .getChildrenWithName(Constant.IN_SEQUENCE_Q).next())
                        .getChildrenWithName(Constant.ENTITLEMENT_SERVICE_Q);
            } else if ("sequences".equals(artifactType)) {
                it = documentElement.getChildrenWithName(Constant.ENTITLEMENT_SERVICE_Q);
            } else if ("templates".equals(artifactType)) {
                it = ((OMElement) documentElement.getChildrenWithName(Constant.SEQUENCE_Q).next())
                        .getChildrenWithName(Constant.ENTITLEMENT_SERVICE_Q);
            }
            String newEncryptedPassword = null;
            while (it.hasNext()) {
                OMElement element = (OMElement) it.next();
                String remoteServicePassword = element.getAttributeValue(Constant.REMOTE_SERVICE_PASSWORD_Q);
                if (remoteServicePassword.startsWith(Constant.EM_ENCRYPTED_PASSWORD_PREFIX)) {
                    newEncryptedPassword = Utility.getNewEncryptedValue(remoteServicePassword
                            .replace(Constant.EM_ENCRYPTED_PASSWORD_PREFIX, ""));
                    if (StringUtils.isNotEmpty(newEncryptedPassword)) {
                        element.getAttribute(Constant.REMOTE_SERVICE_PASSWORD_Q)
                                .setAttributeValue(Constant.EM_ENCRYPTED_PASSWORD_PREFIX + newEncryptedPassword);
                    }
                }
            }

            if (newEncryptedPassword != null) {
                OutputStream outputStream = new FileOutputStream(filePath);
                documentElement.serialize(outputStream);
            }
        } catch (XMLStreamException | FileNotFoundException e) {
            new MigrationClientException("Error while writing the file: " + e);
        } catch (CryptoException e) {
            new MigrationClientException(e.getMessage());
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
