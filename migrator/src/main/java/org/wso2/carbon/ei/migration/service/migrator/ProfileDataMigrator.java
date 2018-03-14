package org.wso2.carbon.ei.migration.service.migrator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.analytics.common.jmx.agent.profiles.Profile;
import org.wso2.carbon.analytics.common.jmx.agent.tasks.internal.JmxTaskServiceComponent;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.ei.migration.MigrationClientException;
import org.wso2.carbon.ei.migration.internal.MigrationServiceDataHolder;
import org.wso2.carbon.ei.migration.service.Migrator;
import org.wso2.carbon.ei.migration.util.Constant;
import org.wso2.carbon.ei.migration.util.Utility;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserStoreException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ProfileDataMigrator extends Migrator {
    private static final String PROFILE_SAVE_REG_LOCATION = "repository/components/org.wso2.carbon.publish.jmx.agent/";
    private static final Log LOG = LogFactory.getLog(ProfileDataMigrator.class);

    private Registry registry;
    private RegistryService registryService;


    @Override
    public void migrate() {
        migrateProfilePassword();
    }

    private void migrateProfilePassword() {
        Tenant[] tenants = new Tenant[0];
        try {
            tenants = MigrationServiceDataHolder.getRealmService().getTenantManager().getAllTenants();
        } catch (UserStoreException e) {
            LOG.error("Error while migrating profiles. Tenant retrieving failed. ", e);
        }
        for (Tenant tenant : tenants) {
            try {
                migrateProfilePasswordforTenant(tenant.getId());
            } catch (MigrationClientException e) {
                LOG.error("Error while migrating profiles. ", e);
            }
        }
    }

    private void migrateProfilePasswordforTenant(int tenantID) throws MigrationClientException {
        if (tenantID == Constant.SUPER_TENANT_ID) {
            try {
                Collection profilesCollection = (Collection) registry.get(PROFILE_SAVE_REG_LOCATION);
                for (String profileName : profilesCollection.getChildren()) {
                    Profile profile = getProfile(profileName);
                    reEncryptProfileWithNewCipher(profile);
                }
            } catch (RegistryException e) {
                throw new MigrationClientException("error while obtaining the registry ", e);
            }
        } else {
            try {
                registryService = JmxTaskServiceComponent.getRegistryService();
                registry = registryService.getGovernanceSystemRegistry(tenantID);
                Collection profileCollection = (Collection) registry.get(PROFILE_SAVE_REG_LOCATION);
                for (String profileName : profileCollection.getChildren()) {
                    Profile profile = getProfile(profileName);
                    reEncryptProfileWithNewCipher(profile);
                }
            } catch (RegistryException e) {
                throw new MigrationClientException("error while obtaining the registry ", e);
            }
        }
    }

    private void reEncryptProfileWithNewCipher(Profile profile) throws MigrationClientException {
        String reEncryptedValue;
        try {
            reEncryptedValue = Utility.getNewEncryptedValue(profile.getPass());
        } catch (CryptoException e) {
            throw new MigrationClientException(e.getMessage());
        }
        profile.setPass(reEncryptedValue);
        saveUpdatedProfile(profile);
    }


    private Profile getProfile(String profileName) throws MigrationClientException {
        ByteArrayInputStream byteArrayInputStream;
        try {
            //if the profile exists
            Resource res = registry.get(PROFILE_SAVE_REG_LOCATION + profileName);
            byteArrayInputStream = new ByteArrayInputStream((byte[]) res.getContent());
        } catch (RegistryException e) {
            LOG.error("Unable to get profile : " + profileName + ". ", e);
            throw new MigrationClientException("Unable to get profile : ".concat(profileName).concat(". "), e);
        }

        Profile profile;
        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(Profile.class);
            Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
            profile = (Profile) jaxbUnmarshaller.unmarshal(byteArrayInputStream);
        } catch (JAXBException e) {
            LOG.error("JAXB unmarshalling exception :" + profileName + ". ", e);
            throw new MigrationClientException("JAXB unmarshalling exception has occurred while retrieving '".
                    concat(profileName).concat("' profile from registry"), e);
        }
        return profile;

    }

    private void saveUpdatedProfile(Profile profile) throws MigrationClientException {
        String path = PROFILE_SAVE_REG_LOCATION + profile.getName();

        JAXBContext jaxbContext;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            jaxbContext = JAXBContext.newInstance(Profile.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            jaxbMarshaller.marshal(profile, byteArrayOutputStream);
        } catch (JAXBException e) {
            throw new MigrationClientException("JAXB unmarshalling exception has occurred while saving '".
                    concat(profile.getName()).concat("'."), e);
        }

        //replace the profile if it exists
        try {
            Resource res = registry.newResource();
            res.setContent(byteArrayOutputStream.toString());
            //delete the existing profile
            registry.delete(path);
            //save the new profile
            registry.put(path, res);
        } catch (RegistryException e) {
            throw new MigrationClientException("Error has occurred while trying to save '".concat(profile.getName())
                    .concat("' profile on registry. "), e);
        }

        try {
            byteArrayOutputStream.close();
        } catch (IOException e) {
            // Just log the exception. Do nothing.
            LOG.warn("Unable to close byte stream ...", e);

        }
    }

}
