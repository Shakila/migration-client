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
package org.wso2.carbon.ei.migration.service.dao;

import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.ei.migration.MigrationClient;
import org.wso2.carbon.ei.migration.MigrationClientException;
import org.wso2.carbon.ei.migration.service.migrator.DatasourceMigrator;
import org.wso2.carbon.ei.migration.util.Utility;
import org.wso2.carbon.ndatasource.common.DataSourceConstants;
import org.wso2.carbon.ndatasource.common.DataSourceException;
import org.wso2.carbon.registry.api.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;

import javax.xml.stream.XMLStreamException;
import java.util.ArrayList;
import java.util.List;

import org.wso2.carbon.ndatasource.core.utils.DataSourceUtils;

public class DataSourceDAO {
    private static final Log log = LogFactory.getLog(DataSourceDAO.class);

    private static DataSourceDAO instance = new DataSourceDAO();

    private DataSourceDAO() {

    }

    public static DataSourceDAO getInstance() {

        return instance;
    }

    /**
     * Obtain all the DataSources
     *
     * @return DataSources List
     */
    public List<Resource> getAllDataSources(int tenantId) throws MigrationClientException {

        List<Resource> dataSources = new ArrayList<>();
        Registry registry;
        try {
            registry = getRegistry(tenantId);
        } catch (DataSourceException e) {
            throw new MigrationClientException("Error in getting the registry configuration: " + e.getMessage());
        }
        Collection dsCollection = null;
        try {
            dsCollection = (Collection) registry.get(DataSourceConstants.DATASOURCES_REPOSITORY_BASE_PATH);
        } catch (RegistryException e) {
            //Ignore
        }
        try {
            if (dsCollection != null) {
                String[] dataSourceNames = dsCollection.getChildren();
                for (String dataSourcePath : dataSourceNames) {
                    Resource resource = registry.get(dataSourcePath);
                    dataSources.add(resource);
                }
            }
        } catch (Exception e) {
            throw new MigrationClientException("Error in getting all data source names from repository: " + e.getMessage());
        }
        return dataSources;
    }

    private static Registry getRegistry(int tenantId) throws DataSourceException {

        Registry registry = DataSourceUtils.getConfRegistryForTenant(tenantId);
        if (log.isDebugEnabled()) {
            log.debug("Retrieving the governance registry for tenant: " + tenantId);
        }

        return registry;
    }

    public static void saveDataSource(int tenantId, Resource resource) throws DataSourceException {
        try {
            getRegistry(tenantId).put(resource.getPath(), resource);
        } catch (RegistryException e) {
            new DataSourceException("Error while saving the datasource into the registry.", e);
        }
    }
}
