/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.ei.migration.service.migrator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.ei.migration.MigrationClientException;
import org.wso2.carbon.ei.migration.service.Migrator;
import org.wso2.carbon.ei.migration.service.RegistryDataManager;
import org.wso2.carbon.ei.migration.util.Constant;

public class KeyStorePasswordMigrator extends Migrator {

    private static final Log log = LogFactory.getLog(KeyStorePasswordMigrator.class);

    @Override
    public void migrate() {
            migrateKeystorePasswords();
    }

    private void migrateKeystorePasswords() {

        log.info(Constant.MIGRATION_LOG + "Migration starting on Key Stores");
        boolean isIgnoreForInactiveTenants = Boolean.parseBoolean(System.getProperty(Constant.IGNORE_INACTIVE_TENANTS));
        RegistryDataManager registryDataManager = RegistryDataManager.getInstance();
        registryDataManager.migrateKeyStorePassword(isIgnoreForInactiveTenants);
    }
}
