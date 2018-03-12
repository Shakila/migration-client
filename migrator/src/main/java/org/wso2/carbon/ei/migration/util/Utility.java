/*
* Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.ei.migration.util;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.internal.CarbonCoreDataHolder;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Util class.
 */
public class Utility {

    private static Log log = LogFactory.getLog(Utility.class);

    public static String getMigrationResourceDirectoryPath() {

        Path path = Paths.get(System.getProperty(Constant.CARBON_HOME), Constant.MIGRATION_RESOURCE_HOME);
        return path.toString();
    }

    public static OMElement toOM(InputStream inputStream) throws XMLStreamException {
        XMLStreamReader reader = XMLInputFactory.newInstance().createXMLStreamReader(inputStream);
        StAXOMBuilder builder = new StAXOMBuilder(reader);
        return builder.getDocumentElement();
    }

    public static String getNewEncryptedValue(String encryptedValue) throws CryptoException {
        if (StringUtils.isNotEmpty(encryptedValue) && !isNewlyEncrypted(encryptedValue) && isEncryptedByRSA(encryptedValue)) {
            byte[] decryptedPassword = CryptoUtil.getDefaultCryptoUtil().base64DecodeAndDecrypt(encryptedValue, Constant.RSA);
            return CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(decryptedPassword);
        }
        return null;
    }

    public static boolean isNewlyEncrypted(String encryptedValue) throws CryptoException {
        CryptoUtil cryptoUtil = null;
        try {
            cryptoUtil = CryptoUtil.getDefaultCryptoUtil(CarbonCoreDataHolder.getInstance().getServerConfigurationService(),
                    CarbonCoreDataHolder.getInstance().getRegistryService());
        } catch (Exception e) {
            new CryptoException(e.getMessage());
        }
        return cryptoUtil.base64DecodeAndIsSelfContainedCipherText(encryptedValue);
    }

    public static boolean isEncryptedByRSA(String password) throws CryptoException {
        return password.equals(CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(CryptoUtil.getDefaultCryptoUtil()
                        .base64DecodeAndDecrypt(password, Constant.RSA)
                , Constant.RSA, false));
    }

}
