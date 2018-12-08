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

package org.wso2.carbon.identity.password.min.age.store;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.Days;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.password.history.constants.PasswordHistoryConstants;
import org.wso2.carbon.identity.password.history.exeption.IdentityPasswordHistoryException;

import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

public class MinPasswordAgeDataStore {

    private static final Log log = LogFactory.getLog(MinPasswordAgeDataStore.class);

    public static final String LOAD_HISTORY_DATA = "SELECT TIME_CREATED FROM IDN_PASSWORD_HISTORY_DATA WHERE USER_NAME= ? AND " +
            "USER_DOMAIN = ? AND TENANT_ID = ? ORDER BY TIME_CREATED DESC LIMIT 1 ";

    public boolean validate(User user, int minAge) throws IdentityPasswordHistoryException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            connection.setAutoCommit(false);
            prepStmt = connection.prepareStatement(LOAD_HISTORY_DATA);
            prepStmt.setString(1, user.getUserName());
            prepStmt.setString(2, user.getUserStoreDomain());
            prepStmt.setInt(3, IdentityTenantUtil.getTenantId(user.getTenantDomain()));

            resultSet = prepStmt.executeQuery();

            Timestamp date = null;
            while (resultSet.next()) {
                date = resultSet.getTimestamp(1);
            }

            if (date == null) {
                return true;
            }

            long lastPasswordTime = date.getTime();
            long currentTime = new java.util.Date().getTime();
            long differentTime = currentTime - lastPasswordTime;
            if (differentTime < minAge * 86400000) {
                return false;
            }
        } catch (SQLException e) {
            throw new IdentityPasswordHistoryException("Error while validating password min age ", e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
            IdentityDatabaseUtil.closeResultSet(resultSet);
            IdentityDatabaseUtil.closeConnection(connection);
        }
        return true;
    }
}
