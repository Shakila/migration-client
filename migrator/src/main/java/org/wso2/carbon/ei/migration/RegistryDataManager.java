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
package org.wso2.carbon.ei.migration;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.ei.migration.internal.MigrationServiceDataHolder;
import org.wso2.carbon.ei.migration.util.Utility;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID;

public class RegistryDataManager {

    private static final Log log = LogFactory.getLog(RegistryDataManager.class);
    private static final String PASSWORD = "password";
    private static final String PRIVATE_KEY_PASS = "privatekeyPass";
    private static final String KEYSTORE_RESOURCE_PATH = "/repository/security/key-stores/";
    private static final String SYSLOG = "/repository/components/org.wso2.carbon.logging/loggers/syslog/SYSLOG_PROPERTIES";

    private static RegistryDataManager instance = new RegistryDataManager();

    private RegistryDataManager(){}

    public static RegistryDataManager getInstance() {
        return instance;
    }

    private void startTenantFlow(Tenant tenant) {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantId(tenant.getId());
        carbonContext.setTenantDomain(tenant.getDomain());
    }

    /**
     * Method to migrate encrypted password of key stores
     *
     * @param migrateActiveTenantsOnly
     * @throws Exception
     */
    public void migrateKeyStorePassword(boolean migrateActiveTenantsOnly) throws Exception {

        //migrating super tenant configurations
        try {
            migrateKeyStorePasswordForTenant(SUPER_TENANT_ID);
            log.info("Keystore passwords migrated for tenant : " + SUPER_TENANT_DOMAIN_NAME);
        } catch (Exception e) {
            log.error("Error while migrating Keystore passwords for tenant : " + SUPER_TENANT_DOMAIN_NAME);
            throw e;
        }

        //migrating tenant configurations
        Tenant[] tenants = MigrationServiceDataHolder.getRealmService().getTenantManager().getAllTenants();
        for (Tenant tenant : tenants) {
            if (migrateActiveTenantsOnly && !tenant.isActive()) {
                log.info("Tenant " + tenant.getDomain() + " is inactive. Skipping Subscriber migration!");
                continue;
            }
            try {
                startTenantFlow(tenant);
                migrateKeyStorePasswordForTenant(tenant.getId());
                log.info("Keystore passwords migrated for tenant : " + tenant.getDomain());
            } catch (Exception e) {
                log.error("Error while migrating keystore passwords for tenant : " + tenant.getDomain());
                throw e;
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    /**
     * Method to migrate encrypted password of SYSLOG_PROPERTIES registry resource
     *
     * @param migrateActiveTenantsOnly
     * @throws UserStoreException
     */
    public void migrateSysLogPropertyPassword(boolean migrateActiveTenantsOnly)
            throws UserStoreException, RegistryException, CryptoException {

        //migrating super tenant configurations
        try {
            migrateSysLogPropertyPasswordForTenant(SUPER_TENANT_ID);
            log.info("Sys log property password migrated for tenant : " + SUPER_TENANT_DOMAIN_NAME);
        } catch (Exception e) {
            log.error("Error while migrating Sys log property password for tenant : " + SUPER_TENANT_DOMAIN_NAME, e);
        }
        Tenant[] tenants = MigrationServiceDataHolder.getRealmService().getTenantManager().getAllTenants();
        for (Tenant tenant : tenants) {
            if (migrateActiveTenantsOnly && !tenant.isActive()) {
                log.info("Tenant " + tenant.getDomain() + " is inactive. Skipping SYSLOG_PROPERTIES file migration. ");
                continue;
            }
            try {
                startTenantFlow(tenant);
                migrateSysLogPropertyPasswordForTenant(tenant.getId());
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    private void migrateKeyStorePasswordForTenant(int tenantId) throws RegistryException, CryptoException {
        Registry registry = MigrationServiceDataHolder.getRegistryService().getGovernanceSystemRegistry(tenantId);
        if (registry.resourceExists(KEYSTORE_RESOURCE_PATH)) {
            Collection keyStoreCollection = (Collection) registry.get(KEYSTORE_RESOURCE_PATH);
            for (String keyStorePath : keyStoreCollection.getChildren()) {
                updateRegistryProperties(registry, keyStorePath,
                        new ArrayList<>(Arrays.asList(PASSWORD, PRIVATE_KEY_PASS)));
            }
        }
    }

    private void migrateSysLogPropertyPasswordForTenant(int tenantId) throws RegistryException, CryptoException {

        Registry registry = MigrationServiceDataHolder.getRegistryService().getConfigSystemRegistry(tenantId);
        updateRegistryProperties(registry, SYSLOG, new ArrayList<>(Arrays.asList(PASSWORD)));
    }

    private void updateRegistryProperties(Registry registry, String resource, List<String> properties)
            throws RegistryException, CryptoException {

        if (registry == null || StringUtils.isEmpty(resource) || CollectionUtils.isEmpty(properties)) {
            return;
        }

        if (registry.resourceExists(resource)) {
            try {
                registry.beginTransaction();
                Resource resourceObj = registry.get(resource);
                for (String encryptedPropertyName : properties) {
                    String oldValue = resourceObj.getProperty(encryptedPropertyName);
                    String newValue = Utility.getNewEncryptedValue(oldValue);
                    if (StringUtils.isNotEmpty(newValue)) {
                        resourceObj.setProperty(encryptedPropertyName, newValue);
                    }
                }
                registry.put(resource, resourceObj);
                registry.commitTransaction();
            } catch (RegistryException e) {
                registry.rollbackTransaction();
                log.error("Unable to update the registry resource", e);
                throw e;
            }
        }
    }
}
