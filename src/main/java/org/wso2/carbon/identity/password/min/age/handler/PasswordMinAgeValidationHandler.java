/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.identity.password.min.age.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.password.history.constants.PasswordHistoryConstants;
import org.wso2.carbon.identity.password.history.exeption.IdentityPasswordHistoryException;
import org.wso2.carbon.identity.password.min.age.Util.Utils;
import org.wso2.carbon.identity.password.min.age.constants.PasswordMinAgeConstants;
import org.wso2.carbon.identity.password.min.age.internal.IdentityPasswordMinAgeServiceDataHolder;
import org.wso2.carbon.identity.password.min.age.store.MinPasswordAgeDataStore;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class PasswordMinAgeValidationHandler extends AbstractEventHandler implements IdentityConnectorConfig {

    private static final Log log = LogFactory.getLog(PasswordMinAgeValidationHandler.class);

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();
        String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties
                .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
        String domainName = userStoreManager.getRealmConfiguration().getUserStoreProperty(UserCoreConstants
                .RealmConfig.PROPERTY_DOMAIN_NAME);
        if (StringUtils.isBlank(domainName)) {
            domainName = IdentityUtil.getPrimaryDomainName();
        }
        User user = new User();
        user.setUserName(userName);
        user.setUserStoreDomain(domainName);
        user.setTenantDomain(tenantDomain);


        Property[] identityProperties;
        try {
            identityProperties = IdentityPasswordMinAgeServiceDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while retrieving account lock handler properties.", e);
        }

        boolean passwordHistoryValidation = false;
        int minAge = 0;
        for (Property identityProperty : identityProperties) {
            if (PasswordMinAgeConstants.PM_MIN_AGE_ENABLE.equals(identityProperty.getName())) {
                passwordHistoryValidation = Boolean.parseBoolean(identityProperty.getValue());
            } else if (PasswordMinAgeConstants.PW_MIN_AGE_COUNT.equals(identityProperty.getName())) {
                minAge = Integer.parseInt(identityProperty.getValue());
            }
        }

        if (!passwordHistoryValidation) {
            if (log.isDebugEnabled()) {
                log.debug("Password History validation is disabled");
            }
            return;
        }

        if (minAge <= 0) {
            //The history should not validate
            return;
        }

        MinPasswordAgeDataStore minPasswordAgeDataStore= new MinPasswordAgeDataStore();
        if (IdentityEventConstants.Event.PRE_UPDATE_CREDENTIAL.equals(event.getEventName()) || IdentityEventConstants.Event
                .PRE_UPDATE_CREDENTIAL_BY_ADMIN.equals(event.getEventName())) {
            try {
                boolean validate = minPasswordAgeDataStore.validate(user, minAge);
                if (!validate) {
                    throw Utils.handleEventException(PasswordMinAgeConstants.ErrorMessages.ERROR_CODE_MIN_AGE_VIOLATE, null);
                }
            } catch (IdentityPasswordHistoryException e) {
                throw Utils.handleEventException(PasswordMinAgeConstants.ErrorMessages.ERROR_CODE_VALIDATING_PM_MIN_AGE, null, e);
            }
        }
    }

    @Override
    public String getName() {
        return "passwordMinAge";
    }

    @Override
    public String getFriendlyName() {
        return "Password Minimum Age";
    }

    @Override
    public String getCategory() {
        return "Password Policies";
    }

    @Override
    public String getSubCategory() {
        return "DEFAULT";
    }

    @Override
    public int getOrder() { return 1; }

    @Override
    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(PasswordMinAgeConstants.PM_MIN_AGE_ENABLE, "Enable Password Minimum Age Feature");
        nameMapping.put(PasswordMinAgeConstants.PW_MIN_AGE_COUNT, "Password Minimum Age (Days)");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(PasswordMinAgeConstants.PM_MIN_AGE_ENABLE, "Enable Password Minimum Age Feature");
        descriptionMapping.put(PasswordMinAgeConstants.PW_MIN_AGE_COUNT, "Password Minimum Age (Days)");
        return descriptionMapping;
    }

    @Override
    public void init(InitConfig configuration) throws IdentityRuntimeException {
        super.init(configuration);
        IdentityPasswordMinAgeServiceDataHolder.getInstance().getBundleContext().registerService
                (IdentityConnectorConfig.class.getName(), this, null);
    }

    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(PasswordMinAgeConstants.PM_MIN_AGE_ENABLE);
        properties.add(PasswordMinAgeConstants.PW_MIN_AGE_COUNT);
        return properties.toArray(new String[properties.size()]);
    }

    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {

        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(PasswordMinAgeConstants.PM_MIN_AGE_ENABLE, configs.getModuleProperties()
                .getProperty(PasswordMinAgeConstants.PM_MIN_AGE_ENABLE));
        defaultProperties.put(PasswordMinAgeConstants.PW_MIN_AGE_COUNT, configs.getModuleProperties()
                .getProperty(PasswordMinAgeConstants.PW_MIN_AGE_COUNT));
        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain) throws IdentityGovernanceException {
        return null;
    }
}
