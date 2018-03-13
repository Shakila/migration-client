package org.wso2.carbon.ei.migration.service.migrator;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.ei.migration.MigrationClientException;
import org.wso2.carbon.ei.migration.service.Migrator;
import org.wso2.carbon.ei.migration.util.Constant;
import org.wso2.carbon.ei.migration.util.Utility;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Iterator;

public class InputOutputDataMigration extends Migrator {
    private static final Log log = LogFactory.getLog(InputOutputDataMigration.class);

    private static InputOutputDataMigration instance = new InputOutputDataMigration();

    public static InputOutputDataMigration getInstance() {
        return instance;
    }

    @Override
    public void migrate() throws MigrationClientException {
        log.info(Constant.MIGRATION_LOG + "Password transformation starting on Event Publisher and Receiver.");

        String carbonPath = System.getProperty(Constant.CARBON_HOME);
        migratePublishers(carbonPath);
        migrateReceivers(carbonPath);
    }

    private static File readFiles(String path) {
        return new File(path);
    }

    private static void migratePublishers(String carbonHome) throws MigrationClientException {
        File publisherPath = readFiles(carbonHome + Constant.EVENT_PUBLISHER_PATH);
        try {
            migrateData(publisherPath);
            log.info("Migrating publishers was successful");
        } catch (MigrationClientException e) {
            throw new MigrationClientException(e.getMessage());
        }
    }

    private static void migrateReceivers(String carbonHome) throws MigrationClientException {
        File receiverPath = readFiles(carbonHome + Constant.EVENT_RECIEVER_PATH);
        try {
            migrateData(receiverPath);
            log.info("Migrating receivers was successful");
        } catch (MigrationClientException e) {
            throw new MigrationClientException("Error while migrating receivers : " + e);
        }
    }

    private static void migrateData(File folder) throws MigrationClientException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder builder;
        Document doc;
        XMLStreamReader parser;
        FileInputStream stream;
        try {
            File[] configs = folder.listFiles();
            if (configs != null) {
                for (File fileEntry : configs) {
                    if (fileEntry.isFile() && fileEntry.getName().toLowerCase().endsWith(".xml")) {
                        stream = new FileInputStream(fileEntry);
                        parser = XMLInputFactory.newInstance().createXMLStreamReader(stream);
                        StAXOMBuilder builder1 = new StAXOMBuilder(parser);
                        OMElement documentElement = builder1.getDocumentElement();
                        Iterator it = ((OMElement) documentElement.getChildrenWithName(Constant.TO_Q).next()).getChildElements();
                        //documentElement.getChildElements();
                        String newEncryptedPassword = null;
                        while (it.hasNext()) {
                            OMElement element = (OMElement) it.next();
                            if ("true".equals(element.getAttributeValue(Constant.ENCRYPTED_Q))) {
                                String password = element.getText();
                                newEncryptedPassword = Utility.getNewEncryptedValue(password);
                                if (StringUtils.isNotEmpty(newEncryptedPassword)) {
                                    element.setText(newEncryptedPassword);
                                }
                            }
                        }

                        if (newEncryptedPassword != null) {
                            OutputStream outputStream = new FileOutputStream(new File(fileEntry.getAbsolutePath()).getPath());
                            documentElement.serialize(outputStream);
                        }
                    }
                }
            }
        } catch (IOException | CryptoException e) {
            new MigrationClientException(e.getMessage());
        } catch (XMLStreamException e) {
            e.printStackTrace();
        }
    }
}
